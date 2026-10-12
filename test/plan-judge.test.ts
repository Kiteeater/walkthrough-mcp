import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ClaimRejectedError, evaluateExpect, type Check, type Expect } from "../src/core/index.js";
import { mockCore, SB } from "./helpers.js";

const chk = (id: string, expect: Expect, extra: Partial<Check> = {}): Check =>
  ({ id, intent: `intent ${id}`, method: "http", target: "GET http://x/", expect, severity_if_fail: "high", ...extra });

async function setup(checks: Check[]) {
  const { core } = mockCore();
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  const plan = await core.planChecks(w.id, { goal: "g", checks });
  const submit = (checkId: string, content: string, kind: "http" | "cli_output" | "log" = "http") =>
    core.captureEvidence(w.id, { type: "submit", checkId, kind, source: { tool: "test" }, content });
  return { core, id: w.id, plan, submit };
}

describe("evaluateExpect: each of the 5 expect types passes and fails", () => {
  const cases: [Expect, string, string][] = [
    [{ type: "status", value: [200, 299] }, "GET /\nHTTP 204 No Content", "GET /\nHTTP 500 Internal Server Error"],
    [{ type: "status", value: 404 }, '{"status": 404}', '{"status": 200}'],
    [{ type: "count", value: { pattern: "ERROR", max: 1 } }, "ok\nERROR one", "ERROR a\nERROR b"],
    [{ type: "count", value: 3 }, "[1,2,3]", "[1,2]"],
    [{ type: "regex", value: "orders: \\d+" }, "orders: 12", "orders: none"],
    [{ type: "threshold", value: { pattern: "p99=(\\d+)ms", max: 300 } }, "p99=120ms", "p99=900ms"],
    [{ type: "absent", value: "Error:|FATAL" }, "listening", "TypeError: boom"],
  ];
  it.each(cases)("%j", (e, passText, failText) => {
    expect(evaluateExpect(e, [passText]).status).toBe("pass");
    const f = evaluateExpect(e, [failText]);
    expect(f.status).toBe("fail");
    expect(f.reasons.length).toBeGreaterThan(0);
  });
  it("is inconclusive with no evidence or no readable value", () => {
    expect(evaluateExpect({ type: "absent", value: "x" }, []).status).toBe("inconclusive");
    expect(evaluateExpect({ type: "status", value: 200 }, ["GET /\nrequest failed: ECONNREFUSED"]).status).toBe("inconclusive");
    expect(evaluateExpect({ type: "threshold", value: { pattern: "p99=(\\d+)", max: 1 } }, ["nothing"]).status).toBe("inconclusive");
  });
});

describe("plan_checks", () => {
  it("rejects checks without a machine-checkable expect", async () => {
    const { core } = mockCore();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    const bad: unknown[] = [
      undefined, {}, { type: "status" }, { type: "status", value: "2xx" }, { type: "regex", value: "(" }, { type: "absent", value: "" },
      { type: "count", value: {} }, { type: "threshold", value: { pattern: "\\d+", max: 1 } }, { type: "vibes", value: 1 },
    ];
    for (const e of bad) await expect(core.planChecks(w.id, { goal: "g", checks: [chk("n", e as Expect)] })).rejects.toThrow(/machine-checkable/);
    await expect(core.planChecks(w.id, { goal: "g", checks: [chk("n", { type: "status", value: 200 }, { method: "telepathy" as never })] })).rejects.toThrow(/method/);
    await expect(core.planChecks(w.id, { goal: "g", checks: [chk("n", { type: "status", value: 200 }, { severity_if_fail: "urgent" as never })] })).rejects.toThrow(/severity_if_fail/);
    await expect(core.planChecks(w.id, { goal: "g", checks: [chk("n", { type: "status", value: 200 }, { verify: { type: "computer-use" } })] })).rejects.toThrow(/not available/);
  });

  it("returns next_actions telling the agent to execute, capture_evidence, then evaluate_check", async () => {
    const { plan } = await setup([chk("a", { type: "status", value: 200 }), chk("b", { type: "regex", value: "x" }, { method: "mcp", target: "mongodb.find orders" })]);
    expect(plan.next_actions.map((n) => n.check_id)).toEqual(["a", "b"]);
    expect(plan.next_actions[1].do).toMatch(/external MCP tool yourself: mongodb\.find orders/);
    expect(plan.next_actions[1].then[0]).toMatch(/capture_evidence\(check_id="b", kind="mcp_result"/);
    expect(plan.next_actions[0].then[1]).toMatch(/evaluate_check\(check_id="a"/);
  });
});

describe("evaluate_check: the core judges, the agent cannot override", () => {
  it("judges from submitted evidence and ignores any verdict the agent sends", async () => {
    const { core, id, submit } = await setup([chk("a", { type: "status", value: [200, 299] })]);
    const ev = await submit("a", "GET /\nHTTP 500 Internal Server Error\n\nboom");
    expect(ev).toMatchObject({ executedBy: "agent", kind: "http", checkId: "a", type: "response" });
    const r = await core.evaluateCheck(id, { checkId: "a", evidenceIds: [ev.id], status: "pass", reasons: [] } as never);
    expect(r.status).toBe("fail");
    expect(core.load(id).checkResults).toEqual([r]);
    // writing a finding or a sign-off does not touch the verdict
    await core.recordFinding(id, { title: "t", severity: "low", symptom: "s", root_cause_chain: [{ claim: "it passed really", kind: "inferred", evidence_ids: [] }] });
    await core.signOff(id, { decision: "accept" });
    expect(core.load(id).checkResults![0].status).toBe("fail");
    // re-evaluating replaces the result only with another core judgement
    const ok = await submit("a", "GET /\nHTTP 200 OK");
    expect((await core.evaluateCheck(id, { checkId: "a", evidenceIds: [ok.id] })).status).toBe("pass");
    expect(core.load(id).checkResults).toHaveLength(1);
  });

  it("is inconclusive without evidence; rejects foreign, missing or tampered evidence", async () => {
    const { core, id, submit } = await setup([chk("a", { type: "absent", value: "Error:" }), chk("b", { type: "absent", value: "Error:" })]);
    expect((await core.evaluateCheck(id, { checkId: "a", evidenceIds: [] })).status).toBe("inconclusive");
    const evB = await submit("b", "TypeError: x", "log");
    await expect(core.evaluateCheck(id, { checkId: "a", evidenceIds: [evB.id] })).rejects.toThrow(/not captured for a/);
    await expect(core.evaluateCheck(id, { checkId: "a", evidenceIds: ["ev-99"] })).rejects.toThrow(/evidence not found/);
    const evA = await submit("a", "TypeError: x", "log");
    writeFileSync(join(core.dir(id), evA.path), "all good");
    await expect(core.evaluateCheck(id, { checkId: "a", evidenceIds: [evA.id] })).rejects.toThrow(/hash mismatch/);
    await expect(core.evaluateCheck(id, { checkId: "zzz", evidenceIds: [] })).rejects.toThrow(/unknown check/);
  });

  it("capture_evidence validates submissions and redacts them", async () => {
    const { core } = mockCore({ secrets: ["s3cr3t-token"] });
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.planChecks(w.id, { goal: "g", checks: [chk("a", { type: "regex", value: "ok" })] });
    await expect(core.captureEvidence(w.id, { type: "submit", checkId: "nope", kind: "http", source: { tool: "t" }, content: "x" })).rejects.toThrow(/unknown check/);
    await expect(core.captureEvidence(w.id, { type: "submit", checkId: "a", kind: "bogus" as never, source: { tool: "t" }, content: "x" })).rejects.toThrow(/kind/);
    await expect(core.captureEvidence(w.id, { type: "submit", checkId: "a", kind: "http", source: { tool: "t" }, path: "/etc/passwd" })).rejects.toThrow(/only accepted for screenshot\/har/);
    const ev = await core.captureEvidence(w.id, { type: "submit", checkId: "a", kind: "cli_output", source: { tool: "sh", command: "curl -H s3cr3t-token" }, content: "ok s3cr3t-token" });
    expect(ev.source).not.toContain("s3cr3t-token");
    expect(core.readEvidenceText(core.load(w.id), ev)).toBe("ok [REDACTED]");
  });
});

describe("record_finding with root_cause_chain", () => {
  it("rejects observed steps without valid evidence and unknown source refs", async () => {
    const { core, id, submit } = await setup([chk("a", { type: "absent", value: "Error:" })]);
    const ev = await submit("a", "TypeError: boom\n    at f (/app/x.js:3:1)", "log");
    const base = { title: "t", severity: "high" as const, symptom: "500 on /a" };
    await expect(core.recordFinding(id, { ...base, root_cause_chain: [] })).rejects.toThrow(/at least one step/);
    await expect(core.recordFinding(id, { ...base, root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: [] }] })).rejects.toThrow(ClaimRejectedError);
    await expect(core.recordFinding(id, { ...base, root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: ["ev-9"] }] })).rejects.toThrow(/evidence not found/);
    await expect(core.recordFinding(id, { ...base, root_cause_chain: [{ claim: "c", kind: "inferred", evidence_ids: [], source_ref: "src-9" }] })).rejects.toThrow(/source link/);
    await expect(core.recordFinding(id, { ...base, severity: "urgent" as never, root_cause_chain: [{ claim: "c", kind: "inferred", evidence_ids: [] }] })).rejects.toThrow(/severity/);
    const src = await core.linkSource(id, { file: "x.js", line: 3 });
    const f = await core.recordFinding(id, { ...base, check_id: "a", repro_steps: ["curl /a"], root_cause_chain: [
      { claim: "500 on /a", kind: "observed", evidence_ids: [ev.id] },
      { claim: "thrown at x.js:3", kind: "observed", evidence_ids: [ev.id], source_ref: src.id },
    ] });
    expect(f).toMatchObject({ id: "finding-1", kind: "observed", evidenceIds: [ev.id], checkId: "a" });
    const mixed = await core.recordFinding(id, { ...base, root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: [ev.id] }, { claim: "probably the cache", kind: "inferred", evidence_ids: [] }] });
    expect(mixed.kind).toBe("inferred");
    writeFileSync(join(core.dir(id), ev.path), "tampered");
    await expect(core.recordFinding(id, { ...base, root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: [ev.id] }] })).rejects.toThrow(/hash mismatch/);
  });
});

describe("connector seam", () => {
  it("a registered connector:<name> action source runs through the registry; its output is judged like any other", async () => {
    const { core, id, submit } = await setup([chk("k", { type: "count", value: { pattern: "^row", eq: 3 } }, { method: "mcp", target: "connector:fake rows" })]);
    core.registry.registerAction({ type: "connector:fake", run: async () => ({ body: "", evidenceText: "row\nrow\nrow", repro: "probe fake" }) });
    const out = await core.registry.action("connector:fake").run({ type: "connector:fake" }, { walkthrough: core.load(id), sandbox: undefined as never });
    const ev = await submit("k", out.evidenceText, "cli_output");
    expect((await core.evaluateCheck(id, { checkId: "k", evidenceIds: [ev.id] })).status).toBe("pass");
    expect(() => core.registry.action("connector:missing")).toThrow(/no action source/);
  });
});
