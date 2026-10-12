import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CLI_ENV_DENY, CliRejectedError, PRESET_CONNECTORS, capMessageBodies, cliArgv, type ConnectorConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const TOKEN = "mq-fake-token-7c1d9e2a";
const NS = "namesrv.internal:9876";
const preset = PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!;
const mq: ConnectorConfig = { ...preset, namesrvs: [NS], profile: "readonly-ops" };

/** Mock mqadmin: records argv, answers --version, prints a message with a body for queryMsgById. */
function mockMqadmin(dir: string, body: string): string {
  const p = join(dir, "mqadmin");
  writeFileSync(join(dir, "body.txt"), body);
  writeFileSync(p, `#!/usr/bin/env node
const fs=require("fs"),path=require("path");
if(process.argv[2]==="--version"){console.log("mqadmin 5.9.9-mock");process.exit(0)}
fs.appendFileSync(path.join(__dirname,"calls.jsonl"),JSON.stringify({argv:process.argv.slice(2),env:Object.keys(process.env)})+"\\n");
const sub=process.argv[2];
if(sub==="queryMsgById"||sub==="queryMsgByKey"){
  console.log("OffsetID:            0A00000100002A9F0000000000001234");
  console.log("Topic:               orders");
  console.log("Message Body:        "+fs.readFileSync(path.join(__dirname,"body.txt"),"utf8"));
  console.log("");
  console.log("WARN: No Consumer");
} else console.log("TOPIC-STATUS orders brokerOffset=42 "+process.argv.slice(2).join(" "));
`);
  chmodSync(p, 0o755);
  return p;
}

function setup(body = "hello") {
  const bin = mkdtempSync(join(tmpdir(), "wt-mq-"));
  const { core, root } = mockCore({ secrets: [TOKEN], connectors: [{ ...mq, binary: mockMqadmin(bin, body) }] });
  const calls = () => (existsSync(join(bin, "calls.jsonl")) ? readFileSync(join(bin, "calls.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { argv: string[]; env: string[] }) : []);
  const start = async () => (await core.startWalkthrough({ title: "mq", sandbox: { cwd: root, up: "true", down: "true" } })).id;
  const ev = (id: string, evId: string) => readFileSync(join(root, ".walkthrough", id, "evidence", `${evId}.txt`), "utf8");
  return { core, root, calls, start, ev };
}
const rejects = async (p: Promise<unknown>, re: RegExp) => { await expect(p).rejects.toBeInstanceOf(CliRejectedError); await expect(p).rejects.toThrow(re); };

describe("mqadmin read-only preset: argv allowlist", () => {
  it.each([
    ["updateTopic", "-t", "x", "-c", "c1"], ["deleteTopic", "-t", "x"], ["sendMessage", "-t", "x", "-k", "k"],
    ["resetOffsetByTime", "-g", "g", "-t", "x", "-s", "now"], ["updateSubGroup", "-g", "g"], ["deleteSubGroup", "-g", "g"],
    ["wipeWritePerm", "-b", "b"], ["updateBrokerConfig", "-k", "k", "-v", "v"], ["cleanExpiredCQ"], ["updateKvConfig", "-s", "s"],
  ])("write/admin subcommand %s is rejected", (...argv) => expect(() => cliArgv(mq, argv)).toThrow(/not in whitelist/));

  it("rejects args not on the subcommand's own allowlist", () => {
    expect(() => cliArgv(mq, ["topicStatus", "-t", "orders", "-g", "g"])).toThrow(/argument not in allowlist/);
    expect(() => cliArgv(mq, ["topicList", "-t", "orders"])).toThrow(/argument not in allowlist/);
    expect(() => cliArgv(mq, ["queryMsgByKey", "-t", "orders", "-k", "o1", "-f", "x"])).toThrow(/not allowed|not in allowlist/);
    expect(() => cliArgv(mq, ["topicStatus", "--namesrvAddr", "evil:9876", "-t", "orders"])).toThrow(/argument not in allowlist/);
    expect(() => cliArgv(mq, ["topicStatus", "-t", "orders", "extra"])).toThrow(/argument not in allowlist/);
  });

  it("-n must be in the configured namesrv allowlist; it is appended from config when omitted", () => {
    expect(() => cliArgv(mq, ["topicList", "-n", "evil.example:9876"])).toThrow(/name server not in allowlist/);
    expect(() => cliArgv(mq, ["topicList", "-n=10.0.0.9:9876"])).toThrow(/name server not in allowlist/);
    expect(() => cliArgv(mq, ["topicStatus", "-t", "orders", "-n", NS, "-n", "evil:9876"])).toThrow(/name server not in allowlist/);
    expect(cliArgv(mq, ["topicList"])).toEqual(["topicList", "-n", NS]);
    expect(cliArgv(mq, ["topicStatus", "-n", NS, "-t", "orders"])).toEqual(["topicStatus", "-n", NS, "-t", "orders"]);
  });

  it("unconfigured namesrvs: every call is rejected with the exact config to add", () => {
    for (const argv of [["topicList"], ["topicList", "-n", NS]]) {
      expect(() => cliArgv(preset, argv)).toThrow(CliRejectedError);
      expect(() => cliArgv(preset, argv)).toThrow(
        'mqadmin: no name server configured. Add the allowed address(es) to the mqadmin connector\'s "namesrvs" in your config, e.g.\n' +
        '  connectors: PRESET_CONNECTORS.map((c) => c.name === "mqadmin" ? { ...c, namesrvs: ["namesrv.internal:9876"] } : c)\n' +
        "Only listed addresses are accepted for -n; when -n is omitted the first one is used.");
    }
  });

  it("allowlists match RocketMQ 5.5.1 tools options; side-effecting options are rejected", () => {
    expect(cliArgv(mq, ["queryMsgByKey", "-t", "orders", "-k", "o1", "-b", "1700000000000", "-m", "32"])).toBeTruthy();
    expect(cliArgv(mq, ["consumerStatus", "-g", "g1", "-b", "10.0.0.5:10911"])).toBeTruthy();
    expect(cliArgv(mq, ["queryMsgById", "-t", "orders", "-i", "ID1", "-c", "c1"])).toBeTruthy();
    for (const argv of [
      ["queryMsgById", "-t", "orders", "-i", "ID1", "-s", "true"],          // resend
      ["queryMsgById", "-t", "orders", "-i", "ID1", "-g", "g1", "-d", "c1"], // consumeMessageDirectly
      ["queryMsgByUniqueKey", "-t", "orders", "-i", "ID1", "-g", "g1", "-d", "c1"],
      ["clusterList", "-i", "1"],                                           // interval: never exits
      ["queryMsgByKey", "-n", NS, "-t", "orders", "-k", "o1", "-x", "1"],
    ]) expect(() => cliArgv(mq, argv)).toThrow(/argument not in allowlist/);
  });

  it("name server / RocketMQ env vars are never passed to the child", () => {
    for (const n of ["NAMESRV_ADDR", "ROCKETMQ_HOME", "rocketmq_access_key"]) expect(CLI_ENV_DENY.test(n)).toBe(true);
  });
});

describe("mqadmin via run_cli with a mock binary", () => {
  it("rejected calls never spawn", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["deleteTopic", "-t", "orders"] }), /not in whitelist/);
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["topicStatus", "-t", "orders", "-b", "b1"] }), /not in allowlist/);
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["topicStatus", "-n", "attacker:9876", "-t", "orders"] }), /name server/);
    expect(calls()).toEqual([]);
  });

  it("query output lands as core-executed evidence with cli name/version/profile and sha256", async () => {
    const { core, calls, start, ev } = setup();
    process.env.NAMESRV_ADDR = "evil:9876";
    try {
      const id = await start();
      const r = await core.runCli(id, { connector: "mqadmin", argv: ["topicStatus", "-t", "orders"] });
      expect(calls()[0].argv).toEqual(["topicStatus", "-t", "orders", "-n", NS]);
      expect(calls()[0].env).not.toContain("NAMESRV_ADDR");
      expect(r.evidence).toMatchObject({ executedBy: "core", kind: "cli_output" });
      expect(r.log.cli).toEqual({ name: "mqadmin", version: "mqadmin 5.9.9-mock", profile: "readonly-ops" });
      expect(r.log.argv).not.toContain("--profile");
      expect(r.log.outputSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(r.log.outputSha256).toBe(r.evidence.sha256);
      expect(ev(id, r.evidence.id)).toContain("TOPIC-STATUS orders brokerOffset=42");
    } finally { delete process.env.NAMESRV_ADDR; }
  });

  it("message bodies are redacted then truncated to the cap before being saved", async () => {
    const cap = preset.messageBody!.maxChars;
    const body = `auth=${TOKEN} ${"x".repeat(cap * 3)}TAIL-MARKER`;
    const { core, root, start, ev } = setup(body);
    const id = await start();
    const r = await core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", "0A00000100002A9F0000000000001234"] });
    const text = ev(id, r.evidence.id);
    expect(text).not.toContain(TOKEN);
    expect(text).toContain("auth=[REDACTED]");
    expect(text).not.toContain("TAIL-MARKER");
    expect(text).toMatch(/…\[truncated \d+ chars\]/);
    const line = text.split("\n").find((l) => l.startsWith("Message Body:"))!;
    expect(line.replace(/^Message Body:\s*/, "").replace(/…\[truncated \d+ chars\]$/, "").length).toBe(cap);
    expect(text).toContain("WARN: No Consumer"); // output after the body is kept
    const all = ["commands.jsonl", "walkthrough.json"].map((f) => readFileSync(join(root, ".walkthrough", id, f), "utf8")).join("");
    expect(all).not.toContain(TOKEN);
  });

  it("capMessageBodies redacts before cutting, so a secret straddling the cap is not partially kept", () => {
    const out = capMessageBodies(`Message Body: ${"a".repeat(8)}${TOKEN}\n\nend`, 12, (s) => s.split(TOKEN).join("[REDACTED]"));
    expect(out).toBe("Message Body: aaaaaaaa[RED…[truncated 6 chars]\n\nend");
    expect(out).not.toContain(TOKEN.slice(0, 4));
  });
});
