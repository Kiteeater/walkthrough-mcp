// Human review ops moved from WalkthroughCore (ops/ split step 10). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
// Not on the MCP surface: signOff / importReview are reached only from the CLI.
import type { WatchState } from "../alerts.js";
import type { AlertWatch, Evidence, Finding, Review, SignOff, Walkthrough } from "../types.js";

/** Narrow view of WalkthroughCore: only the members the review ops touch. */
export interface ReviewCore {
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  listWatches(walkthroughId?: string): WatchState[];
  stopPoller(watchId: string): Promise<WatchState>;
  finalizeWatch(w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] };
}

export function signOff(core: ReviewCore, id: string, input: { decision: string; comment?: string }): Promise<SignOff> {
  if (input.decision !== "accept" && input.decision !== "reject") return Promise.reject(new Error(`invalid sign-off: ${input.decision} (accept|reject)`));
  return core.withLock(id, async () => {
    // Open watches are auto-finalized with what was observed so far (documented in README); the report lists them.
    const open = core.listWatches(id).filter((s) => s.status !== "finalized");
    const auto: { watchId: string; outcome: string }[] = [];
    for (const s0 of open) {
      const s = await core.stopPoller(s0.id);
      const r = core.finalizeWatch(core.load(id), s, "sign_off");
      auto.push({ watchId: s.id, outcome: r.watch.outcome });
    }
    const w = core.load(id);
    w.signoff = { decision: input.decision as SignOff["decision"], ...(input.comment ? { comment: String(input.comment) } : {}), ...(auto.length ? { autoFinalizedWatches: auto } : {}) };
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
  if (signoff && signoff.decision !== "accept" && signoff.decision !== "reject") return Promise.reject(new Error(`invalid sign-off: ${signoff.decision}`));
  return core.withLock(r.walkthroughId, () => {
  const w = core.load(r.walkthroughId as string);
  let applied = 0;
  for (const d of decisions) {
    const c = w.claims.find((x) => x.id === d.claimId);
    if (!c) throw new Error(`unknown claim in review: ${d.claimId}`);
    if (d.decision !== "agree" && d.decision !== "flag") throw new Error(`invalid decision: ${d.decision}`);
    c.review = { decision: d.decision, ...(d.note ? { note: String(d.note) } : {}) } as Review;
    applied++;
  }
  if (signoff) w.signoff = { decision: signoff.decision, ...(signoff.comment ? { comment: String(signoff.comment) } : {}) } as SignOff;
  core.save(w);
  return { id: w.id, applied };
  });
}
