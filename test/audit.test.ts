import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { planFromRoutes } from "../src/demo-agent/planner.js";
import {
  ClaimRejectedError, createSandboxFactory, Redactor, renderWalkthrough, WalkthroughCore,
  type Capturer, type Check, type Walkthrough,
} from "../src/core/index.js";
import { mockCore, SB } from "./helpers.js";

const fakeCapturer: Capturer = { screenshot: async (_u, out) => writeFileSync(out, "png") };
const ROUTES = [{ path: "/health" }, { path: "/a" }, { path: "/b" }];

/** A tiny real service. `bug` picks which route throws (or none); the planner never sees this. */
function makeService(bug: "a" | "b" | null) {
  const root = mkdtempSync(join(tmpdir(), "wt-audit-"));
  const svc = join(root, "svc");
  mkdirSync(svc);
  writeFileSync(join(svc, "package.json"), '{"type":"commonjs"}');
  writeFileSync(join(svc, "lib.js"), [
    "function a() {",
    `  return ${bug === "a" ? "undefined.value" : '"a-ok"'};`,
    "}",
    "",
    "function b() {",
    `  return ${bug === "b" ? "undefined.value" : '"b-ok"'};`,
    "}",
    "module.exports = { a, b };",
  ].join("\n"));
  writeFileSync(join(svc, "server.js"), `const http = require("node:http");
const lib = require("./lib");
http.createServer((req, res) => {
  try {
    if (req.url === "/health") return res.end("ok");
    if (req.url === "/a") return res.end(lib.a());
    if (req.url === "/b") return res.end(lib.b());
    res.statusCode = 404; res.end();
  } catch (err) { console.error(err.stack); res.statusCode = 500; res.end("internal error"); }
}).listen(Number(process.env.PORT), () => console.log("listening"));`);
  return { root, svc };
}

async function runReal(bug: "a" | "b" | null) {
  const { root, svc } = makeService(bug);
  const port = 40000 + Math.floor(Math.random() * 20000);
  process.env.WT_AUDIT_PORT = String(port);
  const core = new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer: fakeCapturer, redactor: new Redactor([]) });
  const w = await core.startWalkthrough({
    title: "audit", sandbox: { backend: "local", cwd: svc, up: "", down: "", local: { up: "PORT=$WT_AUDIT_PORT exec node server.js", passEnv: ["WT_AUDIT_PORT"], killTimeoutMs: 1000 } },
  });
  await core.runInSandbox(w.id, "up");
  try {
    for (let i = 0; i < 50; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) break; } catch { /* wait */ } await new Promise((r) => setTimeout(r, 100)); }
    await core.planChecks(w.id, { goal: "all routes work", checks: planFromRoutes(ROUTES, { baseUrl: `http://127.0.0.1:${port}`, service: "app" }) });
    const results = await core.runChecks(w.id, { settleMs: 150 });
    return { core, w: core.load(w.id), results };
  } finally {
    await core.runInSandbox(w.id, "down");
    delete process.env.WT_AUDIT_PORT;
  }
}
const rootCauseOf = (w: Walkthrough, i = 0) => {
  const f = w.findings![i];
  const s = w.sources.find((x) => x.id === f.rootCause?.sourceId)!;
  return { checkId: f.checkId, loc: `${s.file}:${s.line}`, summary: f.rootCause?.summary };
};

describe("agent-run checks find the real bug (planner knows nothing about it)", () => {
  it("bug in /a → one finding traced to svc/lib.js:2", async () => {
    const { w, results } = await runReal("a");
    expect(results.map((r) => r.status)).toEqual(["pass", "fail", "pass"]);
    expect(results[1].actual.status).toBe(500);
    expect(w.findings).toHaveLength(1);
    expect(w.findings![0]).toMatchObject({ severity: "high", kind: "observed", draft: true });
    expect(rootCauseOf(w)).toMatchObject({ checkId: "chk-2", loc: "svc/lib.js:2" });
    expect(rootCauseOf(w).summary).toMatch(/TypeError/);
  });

  it("bug moved to /b → finding moves and root cause updates to svc/lib.js:6", async () => {
    const { w, results } = await runReal("b");
    expect(results.map((r) => r.status)).toEqual(["pass", "pass", "fail"]);
    expect(w.findings).toHaveLength(1);
    expect(rootCauseOf(w)).toMatchObject({ checkId: "chk-3", loc: "svc/lib.js:6" });
  });

  it("bug fixed → every check passes and there are no findings", async () => {
    const { core, w, results } = await runReal(null);
    expect(results.every((r) => r.status === "pass")).toBe(true);
    expect(w.findings ?? []).toHaveLength(0);
    const html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html).toContain('data-findings="0"');
    expect(html).toContain("checks: 3/3 passed");
  });
});

describe("run_checks auto-judging (mocked sandbox)", () => {
  it("judges command checks pass/fail and drafts findings only for failures", async () => {
    let log = "";
    const core = new WalkthroughCore({
      root: mkdtempSync(join(tmpdir(), "wt-j-")), capturer: fakeCapturer, redactor: new Redactor([]),
      sandboxFactory: () => ({
        up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), logs: async () => log,
        exec: async (c) => { if (c === "x") log += "FATAL boom\n"; return { exitCode: 0, output: `${c}: ok` }; },
      }),
    });
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    const checks: Check[] = [
      { id: "c1", name: "echo", action: { type: "command", command: "echo hi" }, expect: { exitCode: 0, bodyIncludes: "echo hi" } },
      { id: "c2", name: "wrong text", action: { type: "command", command: "echo hi" }, expect: { bodyIncludes: "bye" } },
      { id: "c3", name: "alert", action: { type: "command", command: "x" }, watch: { logs: ["web"], alerts: ["FATAL"] }, expect: {} },
    ];
    await core.planChecks(w.id, { goal: "g", checks });
    const r = await core.runChecks(w.id, { settleMs: 0 });
    expect(r.map((x) => x.status)).toEqual(["pass", "fail", "fail"]);
    expect(r[1].reasons[0]).toMatch(/body missing/);
    const saved = core.load(w.id);
    expect(saved.findings?.map((f) => f.checkId)).toEqual(["c2", "c3"]);
    expect(saved.checkResults).toHaveLength(3);
  });

  it("rejects checks without a machine-checkable expect", async () => {
    const { core } = mockCore();
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    await expect(core.planChecks(w.id, { goal: "g", checks: [{ id: "n", name: "n", action: { type: "command", command: "x" }, expect: {} }] })).rejects.toThrow(/machine-checkable/);
    await expect(core.planChecks(w.id, { goal: "g", checks: [{ id: "n", name: "n", action: { type: "command", command: "x" } } as never] })).rejects.toThrow(/machine-checkable/);
  });

  it("rejects unknown sources/verifiers, and accepts a registered connector without changing run_checks", async () => {
    const { core } = mockCore();
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    const conn: Check = { id: "k1", name: "probe", action: { type: "connector:fake", query: "q" }, expect: { bodyIncludes: "rows=3" } };
    await expect(core.planChecks(w.id, { goal: "g", checks: [conn] })).rejects.toThrow(/no action source/);
    await expect(core.planChecks(w.id, { goal: "g", checks: [{ ...conn, action: { type: "command", command: "x" }, expect: { exitCode: 0 }, verify: { type: "computer-use" } }] })).rejects.toThrow(/not available/);
    core.registry.registerAction({ type: "connector:fake", run: async () => ({ body: "rows=3", evidenceText: "rows=3", repro: "probe fake" }) });
    await core.planChecks(w.id, { goal: "g", checks: [conn] });
    expect((await core.runChecks(w.id, { settleMs: 0 }))[0].status).toBe("pass");
  });
});

describe("record_finding", () => {
  const base = { title: "t", severity: "high" as const, whatHappened: "x", kind: "observed" as const };
  it("rejects observed findings without valid evidence", async () => {
    const { core } = mockCore();
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
    await expect(core.recordFinding(w.id, base)).rejects.toThrow(ClaimRejectedError);
    await expect(core.recordFinding(w.id, { ...base, evidenceIds: ["ev-9"] })).rejects.toThrow(/evidence not found/);
    writeFileSync(join(core.dir(w.id), ev.path), "tampered");
    await expect(core.recordFinding(w.id, { ...base, evidenceIds: [ev.id] })).rejects.toThrow(/hash mismatch/);
    await expect(core.recordFinding(w.id, { ...base, severity: "urgent" as never, kind: "inferred" })).rejects.toThrow(/severity/);
    await expect(core.recordFinding(w.id, { ...base, kind: "inferred", rootCause: { sourceId: "src-9" } })).rejects.toThrow(/source link/);
    expect((await core.recordFinding(w.id, { ...base, kind: "inferred" })).id).toBe("finding-1");
  });
});

describe("audit view + sign-off", () => {
  it("first screen shows count, severity and root cause; sign-off round-trips", async () => {
    const { core, w } = await runReal("a");
    let html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    const first = html.split('id="verdict"')[1].split("</section>")[0];
    expect(first).toContain('data-findings="1"');
    expect(first).toMatch(/data-sev="high">high 1</);
    expect(first).toContain("svc/lib.js:2");
    expect(first).toContain("TypeError");
    expect(first).toContain("认可");
    expect(first).toContain("打回");
    expect(html.indexOf('id="verdict"')).toBeLessThan(html.indexOf('class="claims"'));

    await core.importReview({ walkthroughId: w.id, signoff: { decision: "reject", comment: `fix <b>lib</b> first` } });
    expect(core.load(w.id).signoff).toEqual({ decision: "reject", comment: "fix <b>lib</b> first" });
    html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html).toContain('value="reject" checked');
    expect(html).toContain("fix &lt;b&gt;lib&lt;/b&gt; first");
    expect(html).toContain("out.signoff");
    await expect(core.importReview({ walkthroughId: w.id, signoff: { decision: "maybe" } })).rejects.toThrow(/sign-off/);
    await core.importReview({ walkthroughId: w.id, decisions: [], signoff: { decision: "approve" } });
    expect(core.load(w.id).signoff).toEqual({ decision: "approve" });
  });
});
