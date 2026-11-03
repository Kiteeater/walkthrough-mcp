// Config files are checked by strict schemas: unknown fields, wrong types, missing required fields and broken JSON
// are a ConfigError naming the file and the field path. Before this, <root>/walkthrough.config.json errors were
// swallowed (replay config silently became "none") and flow configs were cast without any check.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createCore, loadFlowConfig } from "../src/core/index.js";

const tmp = () => mkdtempSync(join(tmpdir(), "wt-cfg-"));
const rootWith = (text: string) => { const d = tmp(); writeFileSync(join(d, "walkthrough.config.json"), text); return d; };
const flowFile = (cfg: unknown) => { const f = join(tmp(), "flow.json"); writeFileSync(f, typeof cfg === "string" ? cfg : JSON.stringify(cfg)); return f; };
const okFlow = () => ({ title: "t", sandbox: { cwd: ".", up: "true", down: "true" }, captures: [], claims: [] });
const CLI = resolve("dist/cli/index.js");

describe("walkthrough.config.json is strict (createCore)", () => {
  afterEach(() => { delete process.env.WALKTHROUGH_CONFIG; });
  it("no file → no replay config, no error", () => {
    expect(() => createCore(tmp())).not.toThrow();
  });
  it("a valid file loads", () => {
    expect(() => createCore(rootWith(JSON.stringify({ replay: { allowHosts: ["127.0.0.1:1"], allowCidrs: ["127.0.0.1/32"], capture: { allowWebSocketHosts: ["127.0.0.1:1"] } } })))).not.toThrow();
  });
  it.each<[string, unknown, RegExp]>([
    ["unknown top-level field", { replays: { allowHosts: ["a"] } }, /\(root\): unknown field\(s\) replays/],
    ["unknown replay field (typo)", { replay: { allowHost: ["a"] } }, /replay: unknown field\(s\) allowHost/],
    ["unknown nested field", { replay: { allowHosts: ["a"], capture: { allowWebsocketHosts: ["a"] } } }, /replay\.capture: unknown field\(s\) allowWebsocketHosts/],
    ["wrong type", { replay: { allowHosts: "a" } }, /replay\.allowHosts: Expected array, received string/],
    ["wrong type in an array", { replay: { allowHosts: ["a"], allowCidrs: [1] } }, /replay\.allowCidrs\.0: Expected string, received number/],
    ["wrong number", { replay: { allowHosts: ["a"], timeoutMs: -1 } }, /replay\.timeoutMs: Number must be greater than 0/],
    ["missing required field", { replay: {} }, /replay\.allowHosts: Required/],
    ["missing required nested field", { replay: { allowHosts: ["a"], auth: { header: "x" } } }, /replay\.auth\.valueEnv: Required/],
  ])("%s → ConfigError with the field path", (_n, cfg, re) => {
    const d = rootWith(JSON.stringify(cfg));
    expect(() => createCore(d)).toThrow(re);
    expect(() => createCore(d)).toThrow(join(d, "walkthrough.config.json"));
  });
  it("not JSON → ConfigError naming the file (no longer treated as 'no config')", () => {
    const d = rootWith("{ replay: ");
    expect(() => createCore(d)).toThrow(/invalid config .*walkthrough\.config\.json: not valid JSON/);
  });
  it("WALKTHROUGH_CONFIG file gets the same check", () => {
    const f = join(tmp(), "other.json"); writeFileSync(f, JSON.stringify({ replay: { allowHosts: ["a"], maxRedirect: 3 } }));
    process.env.WALKTHROUGH_CONFIG = f;
    expect(() => createCore(tmp())).toThrow(/other\.json: replay: unknown field\(s\) maxRedirect/);
  });
  it("a replay object passed in code gets the same check", () => {
    expect(() => createCore(tmp(), undefined, { allowHosts: ["a"], allowCidr: ["127.0.0.1/32"] } as never)).toThrow(/createCore\(replay\): .*unknown field\(s\) allowCidr/);
  });
  it("CLI: a broken root config fails the command with the path, exit 1", () => {
    const d = rootWith(JSON.stringify({ replay: { allowHosts: ["a"], extra: 1 } }));
    const r = spawnSync(process.execPath, [CLI, "render", "w_x", "--root", d], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/invalid config .*walkthrough\.config\.json: replay: unknown field\(s\) extra/);
  });
});

describe("flow configs are strict (loadFlowConfig)", () => {
  it("a minimal valid flow loads", () => {
    expect(loadFlowConfig(flowFile(okFlow())).title).toBe("t");
  });
  it.each<[string, (c: Record<string, any>) => void, RegExp]>([
    ["unknown top-level field", (c) => { c.capture = []; }, /\(root\): unknown field\(s\) capture/],
    ["unknown nested field", (c) => { c.waitFor = { url: "http://127.0.0.1:1/", headers: {} }; }, /waitFor: unknown field\(s\) headers/],
    ["unknown sandbox field", (c) => { c.sandbox.allowexec = true; }, /sandbox: unknown field\(s\) allowexec/],
    ["wrong type", (c) => { c.sources = [{ as: "s", file: "f", line: "16" }]; }, /sources\.0\.line: Expected number, received string/],
    ["wrong enum value", (c) => { c.claims = [{ question: "q", conclusion: "c", kind: "guessed" }]; }, /claims\.0\.kind: Invalid enum value/],
    ["unknown capture type", (c) => { c.captures = [{ as: "a", type: "video", url: "u" }]; }, /captures\.0\.type: Invalid discriminator value/],
    ["missing required field", (c) => { delete c.claims; }, /claims: Required/],
    ["missing required nested field", (c) => { delete c.sandbox.up; }, /sandbox\.up: Required/],
    ["empty sandbox.up without backend local", (c) => { c.sandbox.up = ""; }, /sandbox\.up: must not be empty unless backend is "local"/],
    ["empty sandbox.down with backend compose", (c) => { c.sandbox.backend = "compose"; c.sandbox.down = ""; }, /sandbox\.down: must not be empty unless backend is "local"/],
  ])("%s → ConfigError with the field path", (_n, edit, re) => {
    const c = okFlow() as Record<string, any>; edit(c);
    const f = flowFile(c);
    expect(() => loadFlowConfig(f)).toThrow(re);
    expect(() => loadFlowConfig(f)).toThrow(`invalid config ${f}`);
  });
  it("backend local may leave sandbox.up/down empty (local.up runs)", () => {
    expect(loadFlowConfig(flowFile({ ...okFlow(), sandbox: { backend: "local", cwd: ".", up: "", down: "", local: { up: "true" } } })).sandbox.up).toBe("");
  });
  it("not JSON → ConfigError naming the file", () => {
    const f = flowFile("{ title: ");
    expect(() => loadFlowConfig(f)).toThrow(`invalid config ${f}: not valid JSON`);
  });
  it("CLI run: a broken flow config is refused with the path, exit 1", () => {
    const f = flowFile({ ...okFlow(), keepRuning: true });
    const r = spawnSync(process.execPath, [CLI, "run", "--config", f, "--root", tmp()], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(`invalid config ${f}: (root): unknown field(s) keepRuning`);
  });
});

describe("committed example configs pass the strict schema as-is", () => {
  const env = { PORT: "3000", DEMO_HEALTH_TOKEN: "tok" };
  it.each(["examples/walkthrough.config.json", "examples/walkthrough.local.json"])("%s", (f) => {
    const saved = { ...process.env }; Object.assign(process.env, env);
    try { expect(loadFlowConfig(f).agent?.baseUrl).toBe("http://127.0.0.1:3000"); } finally { process.env = saved; }
  });
  it("examples/trace-demo/walkthrough.trace.json (placeholders filled the way run.mjs does)", () => {
    const text = readFileSync("examples/trace-demo/walkthrough.trace.json", "utf8").replaceAll("${SERVICE_URL}", "http://127.0.0.1:3000").replaceAll("${HEALTH_TOKEN}", "tok");
    expect(loadFlowConfig(flowFile(text)).agent?.orders).toEqual(["ord-1", "ord-3"]);
  });
});
