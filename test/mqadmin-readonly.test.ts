import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CLI_ENV_DENY, CliRejectedError, PRESET_CONNECTORS, cliArgv, collectMessageBodies, type ConnectorConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const TOKEN = "mq-fake-token-7c1d9e2a";
const NS = "namesrv.internal:9876";
const preset = PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!;
const mq: ConnectorConfig = { ...preset, namesrvs: [NS], profile: "readonly-ops" };

/**
 * Mock mqadmin reproducing the 5.5.1 output format (rocketmq-all-5.5.1, efa1be5):
 *  - queryMsgById: QueryMsgByIdSubCommand.printMsg L59-163 (`%-20s %s%n` lines, `Message Body Path:` L142-145, no
 *    body printed without -f, then `%n%nWARN: No Consumer`), body written raw by createBodyFile L166-180 to
 *    `/tmp/rocketmq/msgbodys/<msg.getMsgId()>`.
 *  - queryMsgByUniqueKey: showMessage L82-116 (no OffsetID line, `Message Body Path:` L102), createBodyFile L119-138.
 * Behaviour comes from cfg.json next to the binary: dir (stands in for /tmp/rocketmq/msgbodys), body, fileId
 * (defaults to the -i value), noWrite, delayMs, waitFiles, listAll (print a path line for every file in dir, like a hostile output).
 */
function mockMqadmin(bin: string, cfg: Record<string, unknown>): string {
  const p = join(bin, "mqadmin");
  writeFileSync(join(bin, "cfg.json"), JSON.stringify(cfg));
  writeFileSync(p, `#!/usr/bin/env node
const fs=require("fs"),path=require("path");
const cfg=JSON.parse(fs.readFileSync(path.join(__dirname,"cfg.json"),"utf8"));
const a=process.argv.slice(2);
if(a[0]==="--version"){console.log("mqadmin 5.5.1-mock");process.exit(0)}
fs.appendFileSync(path.join(__dirname,"calls.jsonl"),JSON.stringify({argv:a,env:Object.keys(process.env)})+"\\n");
const opt=(f)=>{const i=a.indexOf(f);return i>=0?a[i+1]:undefined};
const out=(k,v)=>process.stdout.write(k.padEnd(20)+" "+v+"\\n");
const sub=a[0];
if(sub==="queryMsgById"||sub==="queryMsgByUniqueKey"){
  const id=opt("-i"), fileId=cfg.fileId||id, file=path.join(cfg.dir,fileId);
  if(!cfg.noWrite){fs.mkdirSync(cfg.dir,{recursive:true});fs.writeFileSync(file,cfg.body||"")}
  let paths=[file];
  const finish=()=>{
    if(sub==="queryMsgById") out("OffsetID:",id);
    out("Topic:",opt("-t")); out("Tags:","[TagA]"); out("Keys:","[ord-1]"); out("Queue ID:",3); out("Queue Offset:",42);
    out("CommitLog Offset:",4660); out("Reconsume Times:",0); out("Born Timestamp:","2026-10-13 07:00:00,123");
    out("Store Timestamp:","2026-10-13 07:00:00,130"); out("Born Host:","10.0.0.8:53412"); out("Store Host:","10.0.0.5:10911");
    out("System Flag:",0); out("Properties:","{UNIQ_KEY="+fileId+", KEYS=ord-1, TAGS=TagA}");
    for(const x of paths) out("Message Body Path:",x);
    process.stdout.write("\\n\\nWARN: No Consumer");
  };
  // waitFiles (barrier for the concurrency test): wait until that many body files exist, take the listing, then wait
  // until every process has taken its listing before printing, so no core deletes a file before all have listed.
  const wait=(cond,then)=>{const t0=Date.now();const t=()=>(!cond()&&Date.now()-t0<5000)?setTimeout(t,20):then();t()};
  const list=()=>{ if(cfg.listAll) paths=fs.readdirSync(cfg.dir).map((f)=>path.join(cfg.dir,f)); };
  setTimeout(()=>{
    if(!cfg.waitFiles){list();return finish();}
    wait(()=>fs.readdirSync(cfg.dir).length>=cfg.waitFiles,()=>{
      list(); fs.writeFileSync(path.join(__dirname,"listed-"+id),"");
      wait(()=>fs.readdirSync(__dirname).filter((f)=>f.startsWith("listed-")).length>=cfg.waitFiles,finish);
    });
  },cfg.delayMs||0);
} else console.log("TOPIC-STATUS orders brokerOffset=42 "+a.join(" "));
`);
  chmodSync(p, 0o755);
  return p;
}

const ID_A = "0A00000100002A9F0000000000001234";
const ID_B = "0A00000100002A9F0000000000005678";
const UNIQ = "7F0000010B1C18B4AAC2730A6B9F0000";

function setup(cfg: Record<string, unknown> = {}) {
  const bin = mkdtempSync(join(tmpdir(), "wt-mq-"));
  const dir = join(bin, "msgbodys");
  const conn: ConnectorConfig = { ...mq, messageBody: { ...preset.messageBody!, dir }, binary: mockMqadmin(bin, { dir, ...cfg }) };
  const { core, root } = mockCore({ secrets: [TOKEN], connectors: [conn] });
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
    expect(cliArgv(mq, ["queryMsgById", "-t", "orders", "-i", ID_A, "-c", "c1"])).toBeTruthy();
    for (const argv of [
      ["queryMsgById", "-t", "orders", "-i", ID_A, "-s", "true"],          // resend
      ["queryMsgById", "-t", "orders", "-i", ID_A, "-g", "g1", "-d", "c1"], // consumeMessageDirectly
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
      expect(r.log.cli).toEqual({ name: "mqadmin", version: "mqadmin 5.5.1-mock", profile: "readonly-ops" });
      expect(r.log.argv).not.toContain("--profile");
      expect(r.log.outputSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(r.log.outputSha256).toBe(r.evidence.sha256);
      expect(ev(id, r.evidence.id)).toContain("TOPIC-STATUS orders brokerOffset=42");
    } finally { delete process.env.NAMESRV_ADDR; }
  });

  it("queryMsgById: body file is read, redacted, truncated, stored as evidence and deleted; secret is nowhere in run files", async () => {
    const cap = preset.messageBody!.maxChars;
    const body = `auth=${TOKEN}\n\n${"x".repeat(cap * 3)}TAIL-MARKER`;
    const s = setup({ body });
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_A] });
    expect(existsSync(join(s.dir, ID_A))).toBe(false);
    const text = s.ev(id, r.evidence.id);
    expect(text).toContain(`OffsetID:            ${ID_A}`);
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

  it("queryMsgById: file named after the unique key (≠ requested offset id) is matched via the OffsetID line", async () => {
    const s = setup({ body: `hello ${TOKEN}`, fileId: UNIQ });
    const id = await s.start();
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_A] });
    expect(s.ev(id, r.evidence.id)).toMatch(/^Message Body: +hello \[REDACTED\]$/m);
    expect(existsSync(join(s.dir, UNIQ))).toBe(false);
    expect(s.runFiles(id)).not.toContain(TOKEN);
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
      await rejects(s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", bad] }), /hex message id/);
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
    const r = await s.core.runCli(id, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_A] });
    expect(s.ev(id, r.evidence.id)).toContain("[not read: not a regular file]");
    expect(lstatSync(join(s.dir, ID_A)).isSymbolicLink()).toBe(true);
    expect(readFileSync(target, "utf8")).toBe(`victim ${TOKEN}`);
    expect(s.runFiles(id)).not.toContain("victim");
  });

  it("two concurrent queries each read and delete only their own body file", async () => {
    const s = setup({ waitFiles: 2, listAll: true, body: "shared-body" });
    const [w1, w2] = [await s.start(), await s.start()];
    const [r1, r2] = await Promise.all([
      s.core.runCli(w1, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_A] }),
      s.core.runCli(w2, { connector: "mqadmin", argv: ["queryMsgById", "-t", "orders", "-i", ID_B] }),
    ]);
    const [t1, t2] = [s.ev(w1, r1.evidence.id), s.ev(w2, r2.evidence.id)];
    expect(t1).toMatch(new RegExp(`${ID_A} \\[read by core, original deleted\\]`));
    expect(t1).toMatch(new RegExp(`${ID_B}\\nMessage Body: +\\[not read: not this query's message id\\]`));
    expect(t2).toMatch(new RegExp(`${ID_B} \\[read by core, original deleted\\]`));
    expect(t2).toMatch(new RegExp(`${ID_A}\\nMessage Body: +\\[not read: not this query's message id\\]`));
    expect(readdirSync(s.dir)).toEqual([]);
  });
});
