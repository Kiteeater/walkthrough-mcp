import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CliRejectedError, LocalSandbox, PRESET_CONNECTORS, sh, tokenize, type ConnectorConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const SECRET = "LTAI-fake-secret-9f8e7d";

/** Fake CLI: records its argv as JSON lines into calls.jsonl next to itself and echoes. */
function fakeBin(dir: string, name: string, body = ""): string {
  const p = join(dir, name);
  writeFileSync(p, `#!/usr/bin/env node
const fs=require("fs"),path=require("path");
if(process.argv[2]==="--version"){console.log("${name} 9.9.9-fake");process.exit(0)}
fs.appendFileSync(path.join(__dirname,"calls.jsonl"),JSON.stringify(process.argv.slice(2))+"\\n");
${body}
console.log("ok "+process.argv.slice(2).join(" "));
`);
  chmodSync(p, 0o755);
  return p;
}

function setup(extra: Partial<Record<string, string>> = {}) {
  const bin = mkdtempSync(join(tmpdir(), "wt-bin-"));
  const connectors: ConnectorConfig[] = PRESET_CONNECTORS.map((c) => ({ ...c, binary: fakeBin(bin, c.name, extra[c.name]), ...(c.name === "mqadmin" ? { namesrvs: ["ns:9876"] } : {}) }));
  const { core, root } = mockCore({ secrets: [SECRET], connectors });
  const calls = () => (existsSync(join(bin, "calls.jsonl")) ? readFileSync(join(bin, "calls.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]) : []);
  const start = async () => (await core.startWalkthrough({ title: "cli", sandbox: { cwd: root, up: "true", down: "true" } })).id;
  return { core, root, bin, calls, start };
}

const rejects = async (p: Promise<unknown>, re: RegExp) => { await expect(p).rejects.toBeInstanceOf(CliRejectedError); await expect(p).rejects.toThrow(re); };

describe("run_cli whitelist (default config)", () => {
  it("runs a whitelisted read-only subcommand via argv and stores executed-by-core evidence", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    const r = await core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", "--project", "p", "--logstore", "app", "--query", "status: 500"] });
    expect(r.exitCode).toBe(0);
    expect(calls()).toEqual([["sls", "GetLogs", "--project", "p", "--logstore", "app", "--query", "status: 500"]]);
    expect(r.evidence.executedBy).toBe("core");
    expect(r.evidence.kind).toBe("cli_output");
    expect(r.log.cli).toEqual({ name: "aliyun", version: "aliyun 9.9.9-fake" });
    expect(r.log.outputSha256).toBe(r.evidence.sha256);
  });

  it("rejects non-whitelisted subcommands and unknown connectors without spawning", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["ecs", "DeleteInstance", "--InstanceId", "i-1"] }), /not in whitelist/);
    await rejects(core.runCli(id, { connector: "mqadmin", argv: ["deleteTopic", "-t", "x"] }), /not in whitelist/);
    await rejects(core.runCli(id, { connector: "bash", argv: ["-c", "id"] }), /unknown connector/);
    expect(calls()).toEqual([]);
  });

  it.each([
    ["x; touch PWNED"], ["a && touch PWNED"], ["$(touch PWNED)"], ["`touch PWNED`"], ["a | tee PWNED"], ["a > PWNED"],
  ])("shell-concat bypass %j is rejected and nothing executes", async (bad) => {
    const { core, root, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", "--query", bad] }), /shell syntax/);
    expect(calls()).toEqual([]);
    expect(existsSync(join(root, "PWNED"))).toBe(false);
  });

  it("rejects credential flags and agent-chosen profiles", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", "--access-key-secret", SECRET] }), /flag not allowed/);
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", `--access-key-id=${SECRET}`] }), /flag not allowed/);
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", "--profile", "prod-admin"] }), /flag not allowed/);
    expect(calls()).toEqual([]);
  });

  it("rejects a cwd outside the walkthrough root", async () => {
    const { core, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "aliyun", argv: ["sls", "ListProject"], cwd: "../.." }), /outside/);
  });
});

describe("run_cli mongosh: fixed templates only", () => {
  it("--eval write in argv is rejected (no free-form eval)", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "mongosh", argv: ["--eval", "db.orders.deleteMany({})"] }), /only a query template/);
    await rejects(core.runCli(id, { connector: "mongosh", argv: ["--quiet", "--eval", "db.orders.find()"] }), /only a query template/);
    expect(calls()).toEqual([]);
  });

  it.each(["drop", "insertOne", "insertMany", "deleteMany", "updateOne", "eval"])("template %s is rejected", async (name) => {
    const { core, calls, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "mongosh", template: { name: name as never, db: "shop", collection: "orders" } }), /must be find\|aggregate\|countDocuments/);
    expect(calls()).toEqual([]);
  });

  it.each([
    [[{ $match: {} }, { $out: "stolen" }]], [[{ $merge: { into: "x" } }]], [[{ $facet: { a: [{ $out: "x" }] } }]],
    [[{ $lookup: { from: "x", as: "y", pipeline: [{ $merge: "z" }] } }]], [[{ $match: { $where: "sleep(1)" } }]],
  ])("aggregate pipeline %j is rejected", async (pipeline) => {
    const { core, calls, start } = setup();
    const id = await start();
    await expect(core.runCli(id, { connector: "mongosh", template: { name: "aggregate", db: "shop", collection: "orders", pipeline } })).rejects.toBeInstanceOf(CliRejectedError);
    expect(calls()).toEqual([]);
  });

  it("rejects stages outside the whitelist and $where in find filters", async () => {
    const { core, start } = setup();
    const id = await start();
    await rejects(core.runCli(id, { connector: "mongosh", template: { name: "aggregate", db: "shop", collection: "orders", pipeline: [{ $collStats: {} }] } }), /stage not allowed/);
    await rejects(core.runCli(id, { connector: "mongosh", template: { name: "find", db: "shop", collection: "orders", filter: { $where: "1" } } }), /\$where/);
    await rejects(core.runCli(id, { connector: "mongosh", template: { name: "find", db: "shop'); db.dropDatabase(); ('", collection: "o" } }), /invalid db/);
  });

  it("renders find as a fixed script with the filter as a JSON literal", async () => {
    const { core, calls, start } = setup();
    const id = await start();
    const filter = { note: "'); db.dropDatabase(); //", status: 500 };
    await core.runCli(id, { connector: "mongosh", template: { name: "find", db: "shop", collection: "orders", filter, limit: 5 } });
    const [argv] = calls();
    expect(argv.slice(0, 3)).toEqual(["--quiet", "--norc", "--eval"]);
    expect(argv[3]).toBe(`print(EJSON.stringify(db.getSiblingDB("shop").getCollection("orders").find(EJSON.parse(${JSON.stringify(JSON.stringify(filter))}), EJSON.parse("{}")).sort(EJSON.parse("{}")).limit(5).toArray()))`);
  });
});

describe("command log", () => {
  async function withEntries() {
    const s = setup();
    const id = await s.start();
    await s.core.runCli(id, { connector: "aliyun", argv: ["sls", "ListProject"] });
    await s.core.runCli(id, { connector: "mqadmin", argv: ["topicList", "-n", "ns:9876"] });
    await s.core.runCli(id, { connector: "mongosh", template: { name: "countDocuments", db: "shop", collection: "orders" } });
    const file = join(s.root, ".walkthrough", id, "commands.jsonl");
    return { ...s, id, file, lines: () => readFileSync(file, "utf8").split("\n").filter(Boolean) };
  }

  it("is one hash-chained line per call and verifies", async () => {
    const { core, id, lines } = await withEntries();
    expect(lines()).toHaveLength(3);
    const es = lines().map((l) => JSON.parse(l));
    expect(es[1].prev).toBe(es[0].hash);
    expect(es.map((e) => e.connector)).toEqual(["aliyun", "mqadmin", "mongosh"]);
    expect(core.verifyCommandLog(id)).toEqual({ ok: true, entries: 3 });
  });

  it("detects an edited entry", async () => {
    const { core, id, file, lines } = await withEntries();
    const l = lines(); l[1] = l[1].replace('"exitCode":0', '"exitCode":1');
    writeFileSync(file, `${l.join("\n")}\n`);
    expect(core.verifyCommandLog(id)).toMatchObject({ ok: false, error: expect.stringMatching(/line 2: hash mismatch/) });
  });

  it("detects a deleted middle entry, a truncated tail and a modified evidence file", async () => {
    const a = await withEntries();
    const l = a.lines();
    writeFileSync(a.file, `${[l[0], l[2]].join("\n")}\n`);
    expect(a.core.verifyCommandLog(a.id).ok).toBe(false);
    writeFileSync(a.file, `${l.slice(0, 2).join("\n")}\n`);
    expect(a.core.verifyCommandLog(a.id)).toMatchObject({ ok: false, error: expect.stringMatching(/head mismatch/) });
    writeFileSync(a.file, `${l.join("\n")}\n`);
    expect(a.core.verifyCommandLog(a.id).ok).toBe(true);
    const ev = JSON.parse(l[0]).evidenceId;
    writeFileSync(join(a.root, ".walkthrough", a.id, "evidence", `${ev}.txt`), "forged");
    expect(a.core.verifyCommandLog(a.id)).toMatchObject({ ok: false, error: expect.stringMatching(/modified/) });
  });

  it("never contains credentials: CLI output and argv are redacted in log and evidence", async () => {
    const s = setup({ aliyun: `console.log("AccessKeySecret=${SECRET}");` });
    const id = await s.start();
    await s.core.runCli(id, { connector: "aliyun", argv: ["sls", "GetLogs", "--query", `token ${SECRET}`] });
    const dir = join(s.root, ".walkthrough", id);
    const all = [readFileSync(join(dir, "commands.jsonl"), "utf8"), readFileSync(join(dir, "walkthrough.json"), "utf8"), readFileSync(join(dir, "evidence", "ev-1.txt"), "utf8")].join("\n");
    expect(all).toContain("[REDACTED]");
    expect(all).not.toContain(SECRET);
  });
});

describe("sandbox never uses a shell", () => {
  it("tokenize rejects shell syntax", () => {
    for (const bad of ["a; b", "a && b", "a $(b)", "a `b`", "a | b", "a > f"]) expect(() => tokenize(bad)).toThrow(/metacharacter/);
    expect(tokenize(`node -e 'console.log(1); x()' "a b"`)).toEqual(["node", "-e", "console.log(1); x()", "a b"]);
  });

  it("sh() refuses a chained command instead of running it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wt-sh-"));
    const r = await sh("echo hi; touch PWNED", dir);
    expect(r.exitCode).toBe(126);
    expect(existsSync(join(dir, "PWNED"))).toBe(false);
    const ok = await sh(["node", "-e", "console.log(process.argv[1])", "a; touch PWNED"], dir);
    expect(ok.output.trim()).toBe("a; touch PWNED");
    expect(existsSync(join(dir, "PWNED"))).toBe(false);
  });

  it("local up() refuses a chained command", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wt-sh-"));
    const r = await new LocalSandbox({ backend: "local", cwd: dir, up: "x", down: "x", local: { up: "node -e 1 && touch PWNED" } }).up();
    expect(r.exitCode).toBe(126);
    expect(existsSync(join(dir, "PWNED"))).toBe(false);
  });
});
