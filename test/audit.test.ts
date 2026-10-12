import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runDemoAgent } from "../src/demo-agent/agent.js";
import {
  createSandboxFactory, Redactor, renderWalkthrough, WalkthroughCore,
  type Capturer, type CheckResult, type Walkthrough,
} from "../src/core/index.js";

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
    const results = await runDemoAgent(core, w.id, ROUTES, { goal: "all routes work", baseUrl: `http://127.0.0.1:${port}`, service: "app", settleMs: 150 });
    return { core, w: core.load(w.id), results };
  } finally {
    await core.runInSandbox(w.id, "down");
    delete process.env.WT_AUDIT_PORT;
  }
}
const rootCauseOf = (w: Walkthrough, i = 0) => {
  const f = w.findings![i];
  const step = f.root_cause_chain.find((l) => l.source_ref)!;
  const s = w.sources.find((x) => x.id === step.source_ref)!;
  return { checkId: f.checkId, loc: `${s.file}:${s.line}`, summary: step.claim };
};
const statuses = (rs: CheckResult[]) => rs.filter((r) => /^chk-\d+$/.test(r.checkId)).map((r) => r.status);

describe("demo agent executes, core judges, finding points at the real bug (planner knows nothing about it)", () => {
  it("bug in /a → one finding traced to svc/lib.js:2", async () => {
    const { w, results } = await runReal("a");
    expect(statuses(results)).toEqual(["pass_needs_review", "fail", "pass_needs_review"]) // http-only checks: agent-reported evidence (PR #7);
    expect(results.find((r) => r.checkId === "chk-2-logs")?.status).toBe("fail");
    expect(results.find((r) => r.checkId === "chk-2")?.reasons[0]).toMatch(/status 500/);
    expect(w.findings).toHaveLength(1);
    expect(w.findings![0]).toMatchObject({ severity: "high", kind: "observed" });
    expect(rootCauseOf(w)).toMatchObject({ checkId: "chk-2", loc: "svc/lib.js:2" });
    expect(rootCauseOf(w).summary).toMatch(/TypeError/);
    // every piece of evidence the agent relied on is marked as reported by the agent or captured by us
    expect(w.evidence.filter((e) => e.checkId).every((e) => e.executedBy === (e.kind === "http" ? "agent" : "core"))).toBe(true);
  });

  it("bug moved to /b → finding moves and root cause updates to svc/lib.js:6", async () => {
    const { w, results } = await runReal("b");
    expect(statuses(results)).toEqual(["pass_needs_review", "pass_needs_review", "fail"]);
    expect(w.findings).toHaveLength(1);
    expect(rootCauseOf(w)).toMatchObject({ checkId: "chk-3", loc: "svc/lib.js:6" });
  });

  it("bug fixed → every check passes and there are no findings", async () => {
    const { core, w, results } = await runReal(null);
    // log checks (captured by us) pass; http-only checks (agent-reported) are at most pass_needs_review
    expect(results.every((r) => r.status === (r.checkId.endsWith("-logs") ? "pass" : "pass_needs_review"))).toBe(true);
    expect(w.findings ?? []).toHaveLength(0);
    const html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html).toContain('data-findings="0"');
    expect(html).toContain("checks: 6/6 passed");
  });
});

describe("audit view + sign-off", () => {
  it("first screen shows count, severity and root cause; sign-off accept|reject round-trips", async () => {
    const { core, w } = await runReal("a");
    let html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    const first = html.split('id="verdict"')[1].split("</section>")[0];
    expect(first).toContain('data-findings="1"');
    expect(first).toMatch(/data-sev="high">high 1</);
    expect(first).toContain("svc/lib.js:2");
    expect(first).toContain("TypeError");
    expect(first).toContain('value="accept"');
    expect(first).toContain("打回");
    expect(html).toContain('class="chain"');
    expect(html.indexOf('id="verdict"')).toBeLessThan(html.indexOf('class="claims"'));

    await core.importReview({ walkthroughId: w.id, signoff: { decision: "reject", comment: `fix <b>lib</b> first` } });
    expect(core.load(w.id).signoff).toEqual({ decision: "reject", comment: "fix <b>lib</b> first" });
    html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html).toContain('value="reject" checked');
    expect(html).toContain("fix &lt;b&gt;lib&lt;/b&gt; first");
    await expect(core.importReview({ walkthroughId: w.id, signoff: { decision: "approve" } })).rejects.toThrow(/sign-off/);
    // signed off → read-only (PR #13): no second signature
    await expect(core.signOff(w.id, { decision: "accept" })).rejects.toThrow(/signed off; it is read-only/);
    expect(readFileSync(renderWalkthrough(core, w.id), "utf8")).toContain('value="reject" checked');
  });
});
