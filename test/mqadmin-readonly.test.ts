import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CliRejectedError, PRESET_CONNECTORS, type ConnectorConfig } from "../src/core/index.js";
import { CLI_ENV_DENY, cliArgv, collectMessageBodies } from "../src/core/runcli.js";
import { mockCore } from "./helpers.js";
// @ts-expect-error plain ESM helper without types
import { writeMockMqadmin } from "../examples/trace-demo/mock-mqadmin.mjs";

const TOKEN = "mq-fake-token-7c1d9e2a";
const NS = "namesrv.internal:9876";
const preset = PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!;
const mq: ConnectorConfig = { ...preset, namesrvs: [NS], profile: "readonly-ops" };

const mockMqadmin = (bin: string, cfg: Record<string, unknown>): string => writeMockMqadmin(bin, cfg);

const ID_A = "0A00000100002A9F0000000000001234";
const ID_B = "0A00000100002A9F0000000000005678";
const UNIQ = "7F0000010B1C18B4AAC2730A6B9F0000";

function setup(cfg: Record<string, unknown> = {}) {
  const bin = mkdtempSync(join(tmpdir(), "wt-mq-"));
  const dir = join(bin, "msgbodys");
  const conn: ConnectorConfig = { ...mq, messageBody: { ...preset.messageBody!, dir }, binary: mockMqadmin(bin, { dir, ...cfg }) };
  // Injected resolver: the name server is pinned to this loopback answer (no real DNS).
  const { core, root } = mockCore({ secrets: [TOKEN], connectors: [conn], resolver: async () => "127.0.0.1" });
  const calls = () => (existsSync(join(bin, "calls.jsonl")) ? readFileSync(join(bin, "calls.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { argv: string[]; env: string[] }) : []);
  const start = async () => (await core.startWalkthrough({ title: "mq", sandbox: { cwd: root, up: "true", down: "true" } })).id;
  const ev = (id: string, evId: string) => readFileSync(join(root, ".walkthrough", id, "evidence", `${evId}.txt`), "utf8");
  const runFiles = (id: string) => listFiles(join(root, ".walkthrough", id)).map((f) => readFileSync(f, "utf8")).join("\n");
  return { core, root, bin, dir, calls, start, ev, runFiles };
}
function listFiles(d: string): string[] {
  return readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listFiles(join(d, e.name)) : [join(d, e.name)]));
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

  it("queryMsgById is rejected (#26: direct connect to the IP:port in the msgId) with a hint to the name-server-routed queries", () => {
    for (const argv of [["queryMsgById", "-t", "orders", "-i", ID_A], ["queryMsgById", "-n", NS, "-t", "orders", "-i", ID_A]]) {
      expect(() => cliArgv(mq, argv)).toThrow(CliRejectedError);
      expect(() => cliArgv(mq, argv)).toThrow(/queryMsgById is not allowed: mqadmin connects to the broker IP:port decoded from the msgId.*Use queryMsgByUniqueKey -t <topic> -i <uniqueKey> or queryMsgByKey -t <topic> -k <key>/);
    }
    expect(preset.allow!.some((p) => p[0] === "queryMsgById")).toBe(false);
    expect(preset.messageBody!.subcommands).toEqual(["queryMsgByUniqueKey"]);
  });

  it("queryMsgByUniqueKey -g / -d (consumeMessageDirectly) are not allowlisted and are rejected in space and = forms", () => {
    expect(preset.args!.queryMsgByUniqueKey).not.toContain("-g");
    expect(preset.args!.queryMsgByUniqueKey).not.toContain("-d");
    const base = ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A];
    for (const extra of [["-g", "g1"], ["-g=g1"], ["-d", "client-1"], ["-d=client-1"], ["-g", "g1", "-d", "client-1"], ["-g=g1", "-d=client-1"]]) {
      expect(() => cliArgv(mq, [...base, ...extra])).toThrow(/argument not in allowlist: "-[gd]"/);
    }
  });

  it("brokerStatus -b (direct broker address, #25) is rejected; -c (cluster via name server) still works", () => {
    expect(() => cliArgv(mq, ["brokerStatus", "-b", "10.0.0.5:10911"])).toThrow(/argument not in allowlist: "-b"/);
    expect(() => cliArgv(mq, ["brokerStatus", "-b=169.254.169.254:80"])).toThrow(/argument not in allowlist: "-b"/);
    expect(cliArgv(mq, ["brokerStatus", "-c", "DefaultCluster"])).toEqual(["brokerStatus", "-c", "DefaultCluster", "-n", NS]);
  });

  it("consumerStatus -b (direct broker address) is rejected", () => {
    expect(() => cliArgv(mq, ["consumerStatus", "-g", "g1", "-b", "169.254.169.254:80"])).toThrow(/argument not in allowlist/);
    expect(() => cliArgv(mq, ["consumerStatus", "-g", "g1", "-b=10.0.0.5:10911"])).toThrow(/argument not in allowlist/);
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
    expect(cliArgv(mq, ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A, "-c", "c1"])).toBeTruthy();
    for (const argv of [
      ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A, "-g", "g1", "-d", "c1"],
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
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_A] }), /queryMsgById is not allowed/);
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["brokerStatus", "-b", "10.0.0.5:10911"] }), /not in allowlist/);
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
      expect(calls()[0].argv).toEqual(["topicStatus", "-t", "orders", "-n", "127.0.0.1:9876"]); // pinned to the checked IP
      expect(calls()[0].env).not.toContain("NAMESRV_ADDR");
      expect(r.evidence).toMatchObject({ executedBy: "core", kind: "cli_output" });
      expect(r.log.cli).toEqual({ name: "mqadmin", version: "mqadmin 5.5.1-mock", profile: "readonly-ops" });
      expect(r.log.argv).not.toContain("--profile");
      expect(r.log.outputSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(r.log.outputSha256).toBe(r.evidence.sha256);
      expect(ev(id, r.evidence.id)).toContain("TOPIC-STATUS orders brokerOffset=42");
    } finally { delete process.env.NAMESRV_ADDR; }
  });

  it("queryMsgByUniqueKey: body file is read, redacted, truncated, stored as evidence and deleted; secret is nowhere in run files", async () => {
    const cap = preset.messageBody!.maxChars;
    const body = `auth=${TOKEN}\n\n${"x".repeat(cap * 3)}TAIL-MARKER`;
    const s = setup({ body });
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A] });
    expect(existsSync(join(s.dir, ID_A))).toBe(false);
    const text = s.ev(id, r.evidence.id);
    expect(text).toMatch(/^Message Body Path: +\S+ \[read by core, original deleted\]$/m);
    const line = text.split("\n").find((l) => l.startsWith("Message Body: "))!;
    expect(line).toContain("auth=[REDACTED]\\n\\nxxx");
    expect(line).toMatch(/…\[truncated \d+ chars\]$/);
    expect(line.replace(/^Message Body: +/, "").replace(/…\[truncated \d+ chars\]$/, "").length).toBe(cap + 2); // + the two escaped "\n"
    expect(text).not.toContain("TAIL-MARKER");
    expect(text).toContain("WARN: No Consumer");
    expect(s.runFiles(id)).not.toContain(TOKEN);
    expect(r.log.outputSha256).toBe(r.evidence.sha256);
  });

  it("queryMsgByUniqueKey: same treatment", async () => {
    const s = setup({ body: `k=${TOKEN}` });
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", UNIQ] });
    expect(s.ev(id, r.evidence.id)).toMatch(/^Message Body: +k=\[REDACTED\]$/m);
    expect(existsSync(join(s.dir, UNIQ))).toBe(false);
    expect(s.runFiles(id)).not.toContain(TOKEN);
  });

  it("a traversal / non-hex msgId is rejected before spawning", async () => {
    const s = setup();
    const id = await s.start();
    for (const bad of ["../../etc/passwd", "..%2f..%2fetc", `${ID_A}/../x`, `${ID_A},../../x`, "abc"]) {
      await rejects(s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", bad] }), /hex message id/);
    }
    expect(s.calls()).toEqual([]);
  });

  it("path lines that escape the body dir or name another message are not read or deleted", () => {
    const d = mkdtempSync(join(tmpdir(), "wt-mqb-"));
    const dir = join(d, "msgbodys"); mkdirSync(dir);
    const outside = join(d, ID_A); writeFileSync(outside, TOKEN);
    const other = join(dir, ID_B); writeFileSync(other, TOKEN);
    const out = [`Message Body Path:   ${dir}/../${ID_A}`, `Message Body Path:   ${outside}`, `Message Body Path:   ${other}`].join("\n");
    const r = collectMessageBodies(out, { dir, maxChars: 100, sinceMs: Date.now(), ids: new Set([ID_A]) }, (x) => x);
    expect(r.match(/\[not read: unexpected path\]/g)).toHaveLength(2);
    expect(r).toContain("[not read: not this query's message id]");
    expect(r).not.toContain(TOKEN);
    expect(readFileSync(outside, "utf8")).toBe(TOKEN);
    expect(readFileSync(other, "utf8")).toBe(TOKEN);
  });

  it("a planted symlink named after the msgId: neither the link nor its target is read or deleted", async () => {
    const s = setup({ noWrite: true });
    mkdirSync(s.dir, { recursive: true });
    const target = join(s.bin, "victim.txt");
    writeFileSync(target, `victim ${TOKEN}`);
    symlinkSync(target, join(s.dir, ID_A));
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A] });
    expect(s.ev(id, r.evidence.id)).toContain("[not read: not a regular file]");
    expect(lstatSync(join(s.dir, ID_A)).isSymbolicLink()).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(`victim ${TOKEN}`);
    expect(s.runFiles(id)).not.toContain("victim");
  });

  it("two concurrent queries each read and delete only their own body file", async () => {
    const s = setup({ waitFiles: 2, listAll: true, body: "shared-body" });
    const [w1, w2] = [await s.start(), await s.start()];
    const [r1, r2] = await Promise.all([
      s.core.runCli(w1, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_A] }),
      s.core.runCli(w2, { connector: "mqadmin", argv: ["queryMsgByUniqueKey", "-t", "orders", "-i", ID_B] }),
    ]);
    const [t1, t2] = [s.ev(w1, r1.evidence.id), s.ev(w2, r2.evidence.id)];
    expect(t1).toMatch(new RegExp(`${ID_A} \\[read by core, original deleted\\]`));
    expect(t1).toMatch(new RegExp(`${ID_B}\\nMessage Body: +\\[not read: not this query's message id\\]`));
    expect(t2).toMatch(new RegExp(`${ID_B} \\[read by core, original deleted\\]`));
    expect(t2).toMatch(new RegExp(`${ID_A}\\nMessage Body: +\\[not read: not this query's message id\\]`));
    expect(readdirSync(s.dir)).toEqual([]);
  });
});

describe("mock mqadmin consumerProgress (5.5.1 format)", () => {
  it("prints the per-queue table and totals; Diff Total reflects broker − consumer offsets", async () => {
    const s = setup({ queues: [[0, 10, 7], [1, 5, 5]] });
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["consumerProgress", "-g", "g1", "-t", "orders"] });
    const text = s.ev(id, r.evidence.id);
    expect(text).toMatch(/^orders +broker-a +0 +10 +7 +3 +0 +\S/m);
    expect(text).toMatch(/^Consume Diff Total: 3$/m);
  });
});

describe("#27: the blank-line body capper is gone; body files are capped as a whole", () => {
  it("capMessageBodies is no longer exported", async () => {
    const mod = await import("../src/core/index.js");
    expect("capMessageBodies" in mod).toBe(false);
  });
  it("a body with blank lines is still cut to the cap in full (no text after the first blank line escapes)", () => {
    const d = mkdtempSync(join(tmpdir(), "wt-mqc-"));
    const dir = join(d, "msgbodys"); mkdirSync(dir);
    writeFileSync(join(dir, ID_A), `head\n\n${"y".repeat(5000)}\n\nTAIL`);
    const out = collectMessageBodies(`Message Body Path:   ${join(dir, ID_A)}\n\nWARN: No Consumer`, { dir, maxChars: 16, sinceMs: Date.now(), ids: new Set([ID_A]) }, (x) => x);
    const line = out.split("\n").find((l) => l.startsWith("Message Body: "))!;
    expect(line.replace(/^Message Body: +/, "")).toMatch(/^head\\n\\ny{10}…\[truncated \d+ chars\]$/);
    expect(out).not.toContain("TAIL");
    expect(out.length).toBeLessThan(300);
    expect(out.endsWith("WARN: No Consumer")).toBe(true);
  });
});
