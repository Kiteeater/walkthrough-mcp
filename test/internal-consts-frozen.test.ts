import { describe, expect, it } from "vitest";
import { AGG_STAGES, CliRejectedError, mongoArgv, MONGO_FORBIDDEN, type ConnectorConfig } from "../src/core/runcli.js";
import { CREDENTIALED_CLIS, execDecision, WRAPPERS } from "../src/core/execpolicy.js";
import { MCP_IMPORT_PRESETS } from "../src/core/imports.js";
import { allowlistEnv, DEFAULT_LOCAL_ENV } from "../src/core/sandbox.js";
import { METRIC_OPS, metricExpectProblem } from "../src/core/metrics.js";
import { expandEnv, FLOW_ENV_ALLOWLIST, FLOW_ENV_VARS } from "../src/core/flow.js";
import { mockCore, SB } from "./helpers.js";

const CONSTS: [string, unknown][] = [
  ["AGG_STAGES", AGG_STAGES], ["MONGO_FORBIDDEN", MONGO_FORBIDDEN], ["CREDENTIALED_CLIS", CREDENTIALED_CLIS], ["WRAPPERS", WRAPPERS],
  ["MCP_IMPORT_PRESETS", MCP_IMPORT_PRESETS], ["DEFAULT_LOCAL_ENV", DEFAULT_LOCAL_ENV], ["METRIC_OPS", METRIC_OPS], ["FLOW_ENV_VARS", FLOW_ENV_VARS],
  ["FLOW_ENV_ALLOWLIST", FLOW_ENV_ALLOWLIST],
];
const T = (f: () => unknown) => expect(f).toThrow(TypeError);
const tryAll = (fs: (() => unknown)[]) => { for (const f of fs) try { f(); } catch { /* frozen */ } };
const mongo: ConnectorConfig = { name: "mongosh", binary: "mongosh", kind: "mongo", uri: "mongodb://127.0.0.1:27017/app" };

describe("internal security constants are deep-frozen", () => {
  it.each(CONSTS)("%s: every level frozen, push / write / delete throw, contents unchanged", (_n, v) => {
    const walk = (x: unknown): void => { if (x && typeof x === "object") { expect(Object.isFrozen(x)).toBe(true); Object.values(x).forEach(walk); } };
    walk(v);
    const snap = JSON.stringify(v);
    if (Array.isArray(v)) { T(() => (v as unknown[]).push("evil")); T(() => { (v as unknown[])[0] = "evil"; }); T(() => { (v as unknown[]).length = 0; }); }
    else { T(() => { (v as Record<string, unknown>).EVIL = { redact: false }; }); T(() => { delete (v as Record<string, unknown>).PORT; }); }
    expect(JSON.stringify(v)).toBe(snap);
  });
  it("nested: MCP_IMPORT_PRESETS tool lists and FLOW_ENV_VARS entries", () => {
    T(() => MCP_IMPORT_PRESETS[0].tools.push("drop-database"));
    T(() => { MCP_IMPORT_PRESETS[0].name = "x"; });
    T(() => { (FLOW_ENV_VARS.DEMO_HEALTH_TOKEN as { redact: boolean }).redact = false; });
  });
});

describe("after tampering attempts, the checks still refuse", () => {
  tryAll([
    () => (MONGO_FORBIDDEN as string[]).splice(0), () => (AGG_STAGES as string[]).push("$out", "$merge"),
    () => (WRAPPERS as string[]).splice(0), () => (CREDENTIALED_CLIS as string[]).splice(0),
    () => (METRIC_OPS as string[]).push("~"), () => (DEFAULT_LOCAL_ENV as string[]).push("API_KEY"),
    () => MCP_IMPORT_PRESETS[0].tools.push("drop-database"), () => { (FLOW_ENV_VARS.DEMO_HEALTH_TOKEN as { redact: boolean }).redact = false; },
    () => { (FLOW_ENV_VARS as Record<string, unknown>).SECRET = { redact: false }; },
  ]);
  it("mongo: $out / $merge / $where stages and filters", () => {
    for (const st of [{ $out: "x" }, { $merge: { into: "x" } }]) expect(() => mongoArgv(mongo, { name: "aggregate", db: "app", collection: "c", pipeline: [st] })).toThrow(CliRejectedError);
    expect(() => mongoArgv(mongo, { name: "find", db: "app", collection: "c", filter: { $where: "1" } })).toThrow(CliRejectedError);
  });
  it("run_in_sandbox exec: wrappers and credentialed CLIs", () => {
    for (const cmd of ["sh -c id", "env curl http://127.0.0.2", "sudo id", "curl http://127.0.0.2", "mongosh mongodb://127.0.0.1", "kubectl get pods"])
      expect(() => execDecision(cmd, {}), cmd).toThrow(CliRejectedError);
  });
  it("metric op, sandbox env allowlist, mcp import tools, flow env", async () => {
    expect(metricExpectProblem({ op: "~", value: 1 })).toMatch(/metric op must be one of > >= < <= == !=$/);
    expect(allowlistEnv([], { PATH: "/bin", API_KEY: "x" })).toEqual({ PATH: "/bin" });
    const { core } = mockCore();
    const id = core.startWalkthrough({ title: "t", sandbox: SB }).id;
    await expect(core.importMcpResult(id, { connector: "mongodb", tool: "drop-database", params: {}, result: {}, links: [] } as never)).rejects.toThrow(/not in the read-only import list/);
    expect(() => expandEnv("${SECRET}", "f", { SECRET: "s" })).toThrow(/not allowed/);
    const used: string[] = []; expandEnv("${DEMO_HEALTH_TOKEN}", "f", { DEMO_HEALTH_TOKEN: "tok" }, used);
    expect(used).toEqual(["tok"]);
  });
});
