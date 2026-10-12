// Failed checks that share one root cause are ONE problem on the audit page (「问题 1」 with its checks under it).
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const chk = (id: string) => ({ id, intent: `检查 ${id}`, method: "http" as const, target: `GET /${id}`, expect: { type: "status" as const, value: 200 }, severity_if_fail: "high" as const });

async function setup(ids: string[]) {
  const core = new WalkthroughCore({ root: mkdtempSync(join(tmpdir(), "wt-group-")), sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, o) => writeFileSync(o, "png") }, redactor: new Redactor([]) });
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: ids.map(chk) });
  const ev: Record<string, string> = {};
  for (const id of ids) {
    ev[id] = (await core.captureEvidence(w.id, { type: "submit", checkId: id, kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" })).id;
    await core.evaluateCheck(w.id, { checkId: id, evidenceIds: [ev[id]] });
  }
  return { core, id: w.id, ev };
}
const between = (html: string, a: string, b: string) => html.slice(html.indexOf(a), html.indexOf(b, html.indexOf(a)));

describe("problem grouping on the first screen", () => {
  it("4 failed checks behind one root cause → 「问题 1」 with 4 checks; headline says 1 problem, not 4", async () => {
    const { core, id, ev } = await setup(["a", "a-logs", "a-trace", "a-doc"]);
    await core.recordFinding(id, { title: "GET /a 返回 500", severity: "high", symptom: "GET /a 返回 500", check_id: "a",
      root_cause_chain: ["a", "a-logs", "a-trace", "a-doc"].map((c) => ({ claim: c, kind: "observed" as const, evidence_ids: [ev[c]] })) });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    const first = between(html, '<section class="verdict"', '<div class="check-lists">');
    expect(first).toMatch(/data-findings="1">发现 <b>1<\/b> 个问题/);
    expect(first).toContain('<div class="headline-sub" data-failed="4" data-problems="1">4 项检查失败，归为 1 个问题</div>');
    expect(first).toMatch(/class="top-finding problem" data-problem="1"[^>]*data-checks="4"/);
    expect(first).toContain('<h3 class="problem-title">问题 1 <span class="meta">（4 项失败检查，同一根因）</span></h3>');
    const list = between(first, '<ul class="problem-checks"', "</ul>");
    for (const c of ["a", "a-logs", "a-trace", "a-doc"]) expect(list).toContain(`data-check="${c}"`);
    expect(first).not.toContain("问题 2");
    expect(first).not.toContain('class="unattributed"');
  });

  it("failed checks not tied to any finding are listed separately; two findings → 问题 1 and 问题 2", async () => {
    const { core, id, ev } = await setup(["a", "a-logs", "b", "orphan"]);
    await core.recordFinding(id, { title: "GET /a 返回 500", severity: "high", symptom: "500", check_id: "a", root_cause_chain: [{ claim: "x", kind: "observed", evidence_ids: [ev.a, ev["a-logs"]] }] });
    await core.recordFinding(id, { title: "GET /b 返回 500", severity: "medium", symptom: "500", check_id: "b", root_cause_chain: [{ claim: "y", kind: "observed", evidence_ids: [ev.b] }] });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    const first = between(html, '<section class="verdict"', '<div class="check-lists">');
    expect(first).toContain("4 项检查失败，归为 2 个问题（另有 1 项失败未归入问题）");
    expect(first).toMatch(/data-problem="1"[^>]*data-checks="2"/);
    expect(first).toMatch(/data-problem="2"[^>]*data-checks="1"/);
    expect(between(first, 'class="unattributed"', "</details>")).toContain('data-check="orphan"');
  });
});
