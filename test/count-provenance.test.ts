import { describe, expect, it } from "vitest";
import type { Check } from "../src/core/index.js";
import { mockCore, SB } from "./helpers.js";

// count aggregates across evidence, so per-evidence results are not computed; provenance must still be honoured.
const check: Check = { id: "k", intent: "3 rows", method: "cli", target: "x", expect: { type: "count", value: { pattern: "^row", eq: 3 } }, severity_if_fail: "high" };

async function setup() {
  const { core } = mockCore({ logs: "row" });
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [check] });
  return { core, id: w.id };
}

describe("count checks with >=2 evidence: provenance", () => {
  it("one core-executed evidence -> pass", async () => {
    const { core, id } = await setup();
    const agent = await core.captureEvidence(id, { type: "submit", checkId: "k", kind: "cli_output", source: { tool: "t" }, content: "row\nrow" });
    const logs = await core.captureEvidence(id, { type: "logs", service: "web", checkId: "k" }); // core-executed, contains "row" below
    const w = core.load(id);
    expect(w.evidence.find((e) => e.id === logs.id)!.executedBy).toBe("core");
    const r = await core.evaluateCheck(id, { checkId: "k", evidenceIds: [agent.id, logs.id] });
    expect(r.status).toBe("pass");
  });
  it("all agent-reported -> pass_needs_review; failing count -> fail", async () => {
    const { core, id } = await setup();
    const a = await core.captureEvidence(id, { type: "submit", checkId: "k", kind: "cli_output", source: { tool: "t" }, content: "row\nrow" });
    const b = await core.captureEvidence(id, { type: "submit", checkId: "k", kind: "cli_output", source: { tool: "t" }, content: "row" });
    expect((await core.evaluateCheck(id, { checkId: "k", evidenceIds: [a.id, b.id] })).status).toBe("pass_needs_review");
    const c = await core.captureEvidence(id, { type: "submit", checkId: "k", kind: "cli_output", source: { tool: "t" }, content: "row" });
    expect((await core.evaluateCheck(id, { checkId: "k", evidenceIds: [a.id, b.id, c.id] })).status).toBe("fail");
  });
});
