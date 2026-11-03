import { describe, expect, it } from "vitest";
import { z } from "zod";
import { CHECK_METHODS, CLAIM_KINDS, EVIDENCE_KINDS, EXPECT_TYPES, SANDBOX_BACKENDS, SEVERITIES, SUBMITTABLE_EVIDENCE_KINDS, VERDICTS, isOneOf } from "../dist/core/domain/enums.js";
import { captureEvidenceShape, checkSchema, recordFindingShape } from "../dist/core/schemas.js";

const opts = (s: z.ZodType) => (z.toJSONSchema(s) as { enum?: string[] }).enum;

describe("domain enums: one source, unchanged members and order", () => {
  it("members and order are the pre-refactor literals", () => {
    expect(SEVERITIES).toEqual(["critical", "high", "medium", "low"]);
    expect(CHECK_METHODS).toEqual(["cli", "mcp", "ui", "http", "script"]);
    expect(EXPECT_TYPES).toEqual(["status", "count", "regex", "threshold", "absent", "ui", "metric", "sls_empty"]);
    expect(CLAIM_KINDS).toEqual(["observed", "inferred"]);
    expect(VERDICTS).toEqual(["pass", "pass_needs_review", "fail", "inconclusive"]);
    expect(SANDBOX_BACKENDS).toEqual(["compose", "local"]);
    expect(SUBMITTABLE_EVIDENCE_KINDS).toEqual(["cli_output", "mcp_result", "http", "screenshot", "har", "log"]);
    expect(EVIDENCE_KINDS).toEqual([...SUBMITTABLE_EVIDENCE_KINDS, "metric", "alert", "blocked"]);
  });
  it("MCP zod schemas use the same tuples", () => {
    expect(opts(checkSchema.shape.method)).toEqual([...CHECK_METHODS]);
    expect(opts(checkSchema.shape.severity_if_fail)).toEqual([...SEVERITIES]);
    expect(opts(recordFindingShape.severity)).toEqual([...SEVERITIES]);
    expect(opts(captureEvidenceShape.kind.unwrap())).toEqual([...SUBMITTABLE_EVIDENCE_KINDS]);
  });
  it("isOneOf: exact, case-sensitive membership", () => {
    expect(isOneOf(SEVERITIES, "high")).toBe(true);
    expect(isOneOf(SEVERITIES, "HIGH")).toBe(false);
    expect(isOneOf(SUBMITTABLE_EVIDENCE_KINDS, "metric")).toBe(false);
    expect(isOneOf(CHECK_METHODS, undefined)).toBe(false);
  });
});
