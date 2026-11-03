// Human review ops moved from WalkthroughCore (ops/ split step 10). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
// Not on the MCP surface: signOff / importReview are reached only from the CLI.
import type { WatchState } from "../alerts.js";
import { isReviewDecision, isSignOffDecision, toReview, toSignOff } from "../domain/decisions.js";
import type { AlertWatch, Evidence, Finding, ReportDecision, Review, SignOff, SignOffDecision, Walkthrough } from "../types.js";

/** Narrow view of WalkthroughCore: only the members the review ops touch. */
export interface ReviewCore {
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  listWatches(walkthroughId?: string): WatchState[];
  stopPoller(watchId: string): Promise<WatchState>;
  finalizeWatch(w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] };
  readonly now: () => Date;
}

/**
 * Caller holds the walkthrough lock and is about to sign off. Open watches are auto-finalized with what was observed
 * so far (documented in README); the report lists them. Each finalizeWatch saves the walkthrough, so callers must
 * load the walkthrough again afterwards. Shared by signOff and importReview so both sign-off paths behave the same.
 */
async function finalizeOpenWatches(core: ReviewCore, id: string): Promise<NonNullable<ReportDecision["autoFinalizedWatches"]>> {
  const open = core.listWatches(id).filter((s) => s.status !== "finalized");
  const auto: NonNullable<ReportDecision["autoFinalizedWatches"]> = [];
  for (const s0 of open) {
    const s = await core.stopPoller(s0.id);
    const r = core.finalizeWatch(core.load(id), s, "sign_off");
    auto.push({ watchId: s.id, outcome: r.watch.outcome });
  }
  return auto;
}

export function signOff(core: ReviewCore, id: string, input: { decision: string; comment?: string }): Promise<SignOff> {
  const verdict = input.decision;
  if (!isSignOffDecision(verdict)) return Promise.reject(new Error(`invalid sign-off: ${input.decision} (accept|reject)`));
  return core.withLock(id, async () => {
    const auto = await finalizeOpenWatches(core, id);
    const w = core.load(id);
    w.signoff = toSignOff({ scope: "report", verdict, comment: input.comment, autoFinalizedWatches: auto, source: { via: "cli", decidedAt: core.now().toISOString() } });
    core.save(w);
    return w.signoff;
  });
}

export function importReview(core: ReviewCore, review: unknown): Promise<{ id: string; applied: number }> {
  const r = review as {
    walkthroughId?: string; decisions?: { claimId: string; decision: string; note?: string }[]; signoff?: { decision?: string; comment?: string };
  };
  if (!r || typeof r.walkthroughId !== "string" || !(Array.isArray(r.decisions) || r.signoff)) return Promise.reject(new Error("invalid review file"));
  const decisions = r.decisions ?? [];
  const signoff = r.signoff;
  let reportVerdict: SignOffDecision | undefined;
  let reportComment: string | undefined;
  if (signoff) {
    if (!isSignOffDecision(signoff.decision)) return Promise.reject(new Error(`invalid sign-off: ${signoff.decision}`));
    reportVerdict = signoff.decision;
    reportComment = signoff.comment;
  }
  const id = r.walkthroughId;
  return core.withLock(id, async () => {
  // Validate every claim decision first (same checks, same order), so a rejected file finalizes no watch.
  const w0 = core.load(id);
  const reviews: { claimId: string; review: Review }[] = [];
  for (const d of decisions) {
    const c = w0.claims.find((x) => x.id === d.claimId);
    if (!c) throw new Error(`unknown claim in review: ${d.claimId}`);
    if (!isReviewDecision(d.decision)) throw new Error(`invalid decision: ${d.decision}`);
    reviews.push({ claimId: c.id, review: toReview({ scope: "claim", claimId: c.id, verdict: d.decision, note: d.note, source: { via: "review_import", decidedAt: core.now().toISOString() } }) });
  }
  // A sign-off closes open watches exactly like signOff; finalizeWatch saves, so reload before applying.
  const auto = reportVerdict ? await finalizeOpenWatches(core, id) : [];
  const w = reportVerdict ? core.load(id) : w0;
  for (const x of reviews) {
    const c = w.claims.find((y) => y.id === x.claimId);
    if (!c) throw new Error(`unknown claim in review: ${x.claimId}`);
    c.review = x.review;
  }
  if (reportVerdict) w.signoff = toSignOff({ scope: "report", verdict: reportVerdict, comment: reportComment, autoFinalizedWatches: auto, source: { via: "review_import", decidedAt: core.now().toISOString() } });
  core.save(w);
  return { id: w.id, applied: reviews.length };
  });
}
