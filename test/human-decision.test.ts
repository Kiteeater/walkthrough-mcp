// HumanDecision helpers: the one place that validates verdicts, builds the persisted Review / SignOff,
// and answers "is this walkthrough signed off". Persisted shapes must stay byte-compatible.
import { describe, expect, it } from "vitest";
import { isReviewDecision, isSignedOff, isSignOffDecision, toReview, toSignOff } from "../src/core/domain/decisions.js";
import type { Walkthrough } from "../src/core/types.js";

const cli = { via: "cli", decidedAt: "2026-01-02T03:04:05.000Z" } as const;

describe("human decisions", () => {
  it("claim verdicts are agree|flag only; report verdicts are accept|reject only", () => {
    expect(["agree", "flag"].every(isReviewDecision)).toBe(true);
    expect(["accept", "reject", "", undefined, 1, "Agree"].some(isReviewDecision)).toBe(false);
    expect(["accept", "reject"].every(isSignOffDecision)).toBe(true);
    expect(["agree", "flag", "", undefined, null, "ACCEPT"].some(isSignOffDecision)).toBe(false);
  });

  it("persisted forms keep the old shape and key order; source never reaches disk", () => {
    expect(JSON.stringify(toReview({ scope: "claim", claimId: "claim-1", verdict: "flag", note: "n", source: cli }))).toBe('{"decision":"flag","note":"n"}');
    expect(JSON.stringify(toReview({ scope: "claim", claimId: "claim-1", verdict: "agree", note: "", source: cli }))).toBe('{"decision":"agree"}');
    expect(JSON.stringify(toSignOff({ scope: "report", verdict: "accept", comment: "c", autoFinalizedWatches: [{ watchId: "w1", outcome: "stopped_early" }], source: cli })))
      .toBe('{"decision":"accept","comment":"c","autoFinalizedWatches":[{"watchId":"w1","outcome":"stopped_early"}]}');
    expect(JSON.stringify(toSignOff({ scope: "report", verdict: "reject", comment: "", autoFinalizedWatches: [], source: { via: "review_import", decidedAt: cli.decidedAt } }))).toBe('{"decision":"reject"}');
  });

  it("signed off means a signoff is present", () => {
    const w = { claims: [] } as unknown as Walkthrough;
    expect(isSignedOff(w)).toBe(false);
    expect(isSignedOff({ ...w, signoff: { decision: "reject" } })).toBe(true);
  });
});
