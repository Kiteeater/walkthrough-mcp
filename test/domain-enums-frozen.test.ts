import { describe, expect, it } from "vitest";
import * as core from "../src/core/index.js";
import * as enums from "../src/core/domain/enums.js";
import { mockCore, SB } from "./helpers.js";

const lists = Object.entries(enums).filter(([, v]) => Array.isArray(v)) as [string, string[]][];
// Only the domain enum lists re-exported by core/index (other public arrays are out of scope here).
const publicLists = Object.entries(core).filter(([k, v]) => Array.isArray(v) && k in enums) as [string, string[]][];

describe("domain enum lists are frozen (public exports cannot widen core validation)", () => {
  it("every list in enums.ts is frozen; core/index re-exports the same frozen objects", () => {
    expect(lists.length).toBe(11);
    expect(publicLists.length).toBe(9);
    for (const [name, l] of publicLists) expect(l, name).toBe((enums as Record<string, unknown>)[name]);
    for (const [name, l] of lists) expect(Object.isFrozen(l), name).toBe(true);
  });
  it.each(publicLists)("core/index %s: push / index write / length change throw", (_name, l) => {
    const before = [...l];
    expect(() => (l as string[]).push("evil")).toThrow(TypeError);
    expect(() => { (l as string[])[0] = "evil"; }).toThrow(TypeError);
    expect(() => { (l as string[]).length = 0; }).toThrow(TypeError);
    expect([...l]).toEqual(before);
  });
  it("after tampering attempts, plan_checks / capture_evidence / record_finding still reject unknown values", async () => {
    for (const l of [core.CHECK_METHODS, core.SEVERITIES, core.SUBMITTABLE_EVIDENCE_KINDS]) try { (l as unknown as string[]).push("evil"); } catch { /* frozen */ }
    const { core: c } = mockCore();
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const chk = (o: Record<string, unknown>) => ({ id: "c1", intent: "i", target: "t", method: "http", expect: { type: "status", value: 200 }, severity_if_fail: "high", ...o });
    await expect(c.planChecks(w.id, { goal: "g", checks: [chk({ method: "evil" })] } as never)).rejects.toThrow(/method must be one of cli\|mcp\|ui\|http\|script$/);
    await expect(c.planChecks(w.id, { goal: "g", checks: [chk({ severity_if_fail: "evil" })] } as never)).rejects.toThrow(/severity_if_fail must be one of critical\|high\|medium\|low$/);
    await expect(c.captureEvidence(w.id, { type: "submit", kind: "evil", source: { tool: "x" }, content: "x" } as never)).rejects.toThrow(/invalid evidence kind: evil/);
    await expect(c.recordFinding(w.id, { title: "t", severity: "evil" } as never)).rejects.toThrow(/invalid severity: evil/);
  });
});
