// Human decisions: the one place that validates verdicts, builds the persisted Review / SignOff, and answers
// "is this walkthrough signed off". The persisted shapes (and so walkthrough.json bytes) are unchanged.
import { isOneOf, REVIEW_DECISIONS, SIGNOFF_DECISIONS, type ReviewDecision, type SignOffDecision } from "./enums.js";
import type { ClaimDecision, ReportDecision, Review, SignOff, Walkthrough } from "../types.js";

export const isReviewDecision = (v: unknown): v is ReviewDecision => isOneOf(REVIEW_DECISIONS, v);
export const isSignOffDecision = (v: unknown): v is SignOffDecision => isOneOf(SIGNOFF_DECISIONS, v);

/** A signed-off walkthrough is read-only. */
export const isSignedOff = (w: Walkthrough): boolean => Boolean(w.signoff);

/** Persisted form of a claim decision (`claims[].review`); the source stays in memory. */
export function toReview(d: ClaimDecision): Review {
  return { decision: d.verdict, ...(d.note ? { note: String(d.note) } : {}) };
}

/** Persisted form of a report decision (`signoff`); the source stays in memory. */
export function toSignOff(d: ReportDecision): SignOff {
  return { decision: d.verdict, ...(d.comment ? { comment: String(d.comment) } : {}), ...(d.autoFinalizedWatches?.length ? { autoFinalizedWatches: d.autoFinalizedWatches } : {}) };
}
