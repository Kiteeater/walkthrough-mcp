// Metrics / alert-watch ops moved from WalkthroughCore (ops/ split step 7). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
// State (`pollers`) stays an instance field on WalkthroughCore; this module holds no state.
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import {
  ALERTS_EVIDENCE, ALERT_WATCH_MAX_INTERVAL_S, ALERT_WATCH_MAX_POLLS, ALERT_WATCH_MAX_WINDOW_S, ALERT_WATCH_MIN_INTERVAL_S,
  MAX_ACTIVE_WATCHES, WATCH_ID_RE, alertKey, alertMatches, matcherProblem, redactAlert, severityOf, type AlertMatcher, type PromAlert, type WatchPoll, type WatchState,
} from "../alerts.js";
import { checkHop, ReplayRejectedError } from "../egress/policy.js";
import { ClaimRejectedError } from "../errors.js";
import { sha256File } from "../hash.js";
import { METRIC_EVIDENCE, MetricsError, PROM_ALERTS_PATH, promGet, promInstantQuery, promUrl } from "../metrics.js";
import type { Redactor } from "../redact.js";
import { appendLogEntry } from "../runcli.js";
import type { AlertWatch, Check, Evidence, Finding, Walkthrough } from "../types.js";
import type { CoreDeps } from "../walkthrough.js";

/** Narrow view of WalkthroughCore: only the members the metrics / watch ops touch. */
export interface MetricsCore {
  readonly base: string;
  readonly deps: Pick<CoreDeps, "prometheus" | "replay" | "env" | "resolver" | "sleep">;
  readonly redactor: Redactor;
  readonly now: () => Date;
  readonly pollers: Map<string, { stop: () => void; done: Promise<void> }>;
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  dir(id: string): string;
  ts(): string;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  watchFile(watchId: string): string;
  readWatch(watchId: string): WatchState;
  writeWatch(s: WatchState): void;
  listWatches(walkthroughId?: string): WatchState[];
  startWatch(id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[]; background?: "in-process" | "none" }): Promise<WatchState>;
  spawnPoller(watchId: string): void;
  runPoller(watchId: string, stopped?: () => boolean): Promise<void>;
  stopPoller(watchId: string): Promise<WatchState>;
  collectWatch(watchId: string, opts?: { reason?: "collect" | "sign_off" }): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }>;
  finalizeWatch(w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] };
}

export async function queryMetrics(core: MetricsCore, id: string, input: { query: string; checkId?: string; time?: string }): Promise<Evidence> {
  const prom = core.deps.prometheus;
  if (!prom) throw new MetricsError("Prometheus is not configured (WALKTHROUGH_PROMETHEUS_URL)");
  const cfg = core.deps.replay;
  if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("query_metrics needs replay.allowHosts (same policy as replay)");
  const env = core.deps.env ?? process.env;
  const token = env[prom.tokenEnv ?? "WALKTHROUGH_PROMETHEUS_TOKEN"];
  // Validate the current walkthrough under the lock, then release it while the network request runs. The commit
  // below re-acquires the lock and re-checks sign-off, so a concurrent writer cannot corrupt the ledger.
  await core.withLock(id, () => {
    const w = core.load(id);
    if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
  });
  let r;
  try {
    r = await promInstantQuery(prom, cfg, input.query, { time: input.time, resolver: core.deps.resolver, env });
  } catch (e) {
    throw new (e instanceof Error ? (e.constructor as ErrorConstructor) : Error)(core.redactor.with([token, token && `Bearer ${token}`]).text(String((e as Error).message)));
  }
  return core.withLock(id, () => {
    const w = core.load(id);
    if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
    const red = core.redactor.with([...r.sentSecrets, token]);
    const evId = `ev-${w.evidence.length + 1}`;
    const rel = `evidence/${evId}.json`;
    const doc = { format: METRIC_EVIDENCE, endpoint: red.text(new URL(r.url).origin + new URL(r.url).pathname), query: input.query, time: input.time ?? null, httpStatus: r.status, response: red.value(r.json) };
    writeFileSync(join(core.dir(id), rel), red.text(JSON.stringify(doc, null, 2)));
    const sha = sha256File(join(core.dir(id), rel));
    const log = appendLogEntry(join(core.dir(id), "commands.jsonl"), {
      ts: core.ts(), walkthroughId: id, type: "metrics_query", checkId: input.checkId, endpoint: doc.endpoint, query: red.text(input.query),
      time: input.time ?? null, httpStatus: r.status, promStatus: r.json.status ?? null, hops: r.hops.map((h) => ({ ...h, url: red.text(h.url) })),
      outputSha256: sha, evidenceId: evId, executedBy: "core",
    });
    w.commandLogHead = { seq: log.seq, hash: log.hash };
    const ev: Evidence = { id: evId, type: "response", kind: "metric", path: rel, sha256: sha, createdAt: core.ts(), executedBy: "core",
      ...(input.checkId ? { checkId: input.checkId } : {}), source: red.text(`prometheus:${doc.endpoint} ${input.query}`).slice(0, 500) };
    w.evidence.push(ev);
    core.save(w);
    return ev;
  });
}

export function watchFile(core: MetricsCore, watchId: string): string {
  if (typeof watchId !== "string" || !WATCH_ID_RE.test(watchId)) throw new ClaimRejectedError(`invalid watch id: ${JSON.stringify(watchId)}`);
  const dir = resolve(core.base, "watches");
  const f = resolve(dir, `${watchId}.json`);
  if (!f.startsWith(dir + sep)) throw new ClaimRejectedError("watch path escapes .walkthrough/watches");
  return f;
}

export function readWatch(core: MetricsCore, watchId: string): WatchState {
  const f = core.watchFile(watchId);
  if (!existsSync(f)) throw new ClaimRejectedError(`watch not found: ${watchId}`);
  return JSON.parse(readFileSync(f, "utf8")) as WatchState;
}

export function writeWatch(core: MetricsCore, s: WatchState): void {
  const f = core.watchFile(s.id);
  mkdirSync(resolve(core.base, "watches"), { recursive: true });
  writeFileSync(`${f}.tmp`, JSON.stringify(s, null, 2));
  renameSync(`${f}.tmp`, f);
}

export function listWatches(core: MetricsCore, walkthroughId?: string): WatchState[] {
  const dir = resolve(core.base, "watches");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((n) => /^w_[0-9a-f]{16}\.json$/.test(n)).map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")) as WatchState)
    .filter((s) => !walkthroughId || s.walkthroughId === walkthroughId);
}

export function startWatch(core: MetricsCore, id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[]; background?: "in-process" | "none" }): Promise<WatchState> {
  return core.withLock(id, async () => {
    const prom = core.deps.prometheus;
    if (!prom) throw new MetricsError("Prometheus is not configured (WALKTHROUGH_PROMETHEUS_URL)");
    const cfg = core.deps.replay;
    if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("start_watch needs replay.allowHosts (same policy as replay)");
    const windowS = input.windowS ?? 60, intervalS = input.intervalS ?? 15;
    if (!Number.isFinite(windowS) || windowS < 1 || windowS > ALERT_WATCH_MAX_WINDOW_S) throw new ClaimRejectedError(`window_s must be 1-${ALERT_WATCH_MAX_WINDOW_S}`);
    if (!Number.isFinite(intervalS) || intervalS < ALERT_WATCH_MIN_INTERVAL_S || intervalS > ALERT_WATCH_MAX_INTERVAL_S) throw new ClaimRejectedError(`interval_s must be ${ALERT_WATCH_MIN_INTERVAL_S}-${ALERT_WATCH_MAX_INTERVAL_S}`);
    const w = core.load(id);
    for (const x of input.matchers ?? []) {
      if (!(w.checks ?? []).some((c) => c.id === x.checkId)) throw new ClaimRejectedError(`unknown check: ${x.checkId}`);
      const p = matcherProblem(x.labels); if (p) throw new ClaimRejectedError(p);
    }
    promUrl(prom.url, PROM_ALERTS_PATH); // validates the base URL before anything starts
    await checkHop(cfg, new URL(prom.url), core.deps.resolver); // fail fast on allowlist / IP policy
    const active = core.listWatches().filter((s) => s.status === "running");
    if (active.length >= MAX_ACTIVE_WATCHES) throw new ClaimRejectedError(`too many active watches (${active.length}/${MAX_ACTIVE_WATCHES}); collect one first`);
    const now = core.now();
    const s: WatchState = {
      id: `w_${randomBytes(8).toString("hex")}`, walkthroughId: id, windowS, intervalS, matchers: input.matchers ?? [],
      start: now.toISOString(), deadline: new Date(now.getTime() + windowS * 1000).toISOString(), status: "running",
      polls: [], heartbeat: now.toISOString(), pid: process.pid,
    };
    core.writeWatch(s);
    if ((input.background ?? "in-process") === "in-process") core.spawnPoller(s.id);
    return s;
  });
}

export function spawnPoller(core: MetricsCore, watchId: string): void {
  let stopped = false;
  const done = core.runPoller(watchId, () => stopped).catch(() => undefined).finally(() => core.pollers.delete(watchId));
  core.pollers.set(watchId, { stop: () => { stopped = true; }, done });
}

export async function runPoller(core: MetricsCore, watchId: string, stopped: () => boolean = () => false): Promise<void> {
  const prom = core.deps.prometheus!, cfg = core.deps.replay!;
  const env = core.deps.env ?? process.env;
  const sleep = core.deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const url = promUrl(prom.url, PROM_ALERTS_PATH);
  let s = core.readWatch(watchId);
  s.pid = process.pid; core.writeWatch(s);
  const token = env[prom.tokenEnv ?? "WALKTHROUGH_PROMETHEUS_TOKEN"];
  for (let i = 0; i < ALERT_WATCH_MAX_POLLS; i++) {
    s = core.readWatch(watchId);
    if (s.status !== "running" || s.stopRequested || stopped()) break;
    if (i && core.now().getTime() > Date.parse(s.deadline)) break;
    const at = core.ts();
    let red = core.redactor.with([token, token && `Bearer ${token}`]);
    let rec: WatchPoll;
    try {
      const r = await promGet(prom, cfg, url, PROM_ALERTS_PATH, { resolver: core.deps.resolver, env });
      red = red.with(r.sentSecrets);
      if (r.json.status !== "success") rec = { at, httpStatus: r.status, error: red.text(`status ${r.json.status ?? "?"} ${r.json.error ?? ""}`).trim(), firing: [], pending: 0 };
      else {
        const alerts = ((((r.json.data as { alerts?: PromAlert[] })?.alerts) ?? []) as PromAlert[]).slice(0, 500);
        // Redacted BEFORE it is written anywhere (the state file included).
        rec = { at, httpStatus: r.status, firing: alerts.filter((a) => a?.state === "firing").map((a) => redactAlert(a, red)), pending: alerts.filter((a) => a?.state === "pending").length,
          hops: r.hops.map((h) => ({ ...h, url: red.text(h.url) })) };
      }
    } catch (e) {
      rec = { at, error: red.text(String((e as Error).message)), firing: [], pending: 0 };
    }
    s = core.readWatch(watchId);
    if (s.status !== "running") break;
    s.polls.push(rec); s.heartbeat = core.ts();
    core.writeWatch(s);
    if (core.now().getTime() + s.intervalS * 1000 > Date.parse(s.deadline) + 1) break;
    if (core.deps.sleep) await sleep(s.intervalS * 1000);
    else for (let t = 0; t < s.intervalS * 1000 && !stopped() && !core.readWatch(watchId).stopRequested; t += 200) await sleep(200); // stop-aware wait
  }
  s = core.readWatch(watchId);
  if (s.status === "running") { s.status = (s.stopRequested || stopped()) && core.now().getTime() < Date.parse(s.deadline) ? "stopped" : "done"; s.heartbeat = core.ts(); core.writeWatch(s); }
}

/** Stop the poller (own process: abort + await; other process: request stop and wait briefly). Returns final state. */
export async function stopPoller(core: MetricsCore, watchId: string): Promise<WatchState> {
  const p = core.pollers.get(watchId);
  if (p) { p.stop(); await p.done; return core.readWatch(watchId); }
  let s = core.readWatch(watchId);
  if (s.status !== "running") return s;
  s.stopRequested = true; core.writeWatch(s);
  const alive = (() => { try { process.kill(s.pid, 0); return s.pid !== process.pid; } catch { return false; } })();
  if (alive) {
    const until = Date.now() + Math.min(15_000, (s.intervalS + 11) * 1000);
    while (Date.now() < until) { await new Promise((r) => setTimeout(r, 200)); s = core.readWatch(watchId); if (s.status !== "running") return s; }
  }
  // No live poller finished it: whatever was observed is partial. Never reported as a quiet window.
  s = core.readWatch(watchId);
  if (s.status === "running") { s.status = "interrupted"; core.writeWatch(s); }
  return s;
}

export async function collectWatch(core: MetricsCore, watchId: string, opts: { reason?: "collect" | "sign_off" } = {}): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
  const s0 = core.readWatch(watchId);
  if (s0.status === "finalized") throw new ClaimRejectedError(`watch ${watchId} already collected`);
  const s = await core.stopPoller(watchId);
  return core.withLock(s.walkthroughId, async () => core.finalizeWatch(core.load(s.walkthroughId), core.readWatch(watchId), opts.reason ?? "collect"));
}

/** Caller holds the walkthrough lock. Saves w. */
export function finalizeWatch(core: MetricsCore, w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] } {
  const id = w.id;
  if (s.status === "finalized") throw new ClaimRejectedError(`watch ${s.id} already collected`);
  const outcome: AlertWatch["outcome"] = s.status === "interrupted" ? "interrupted" : s.status === "done" ? "completed" : "stopped_early"; // "stopped"/"running" = collected before the deadline
  const red = core.redactor;
  const prom = core.deps.prometheus;
  const endpoint = prom ? red.text(promUrl(prom.url, PROM_ALERTS_PATH).origin + PROM_ALERTS_PATH) : "(unconfigured)";
  const log = (e: Record<string, unknown>) => { const l = appendLogEntry(join(core.dir(id), "commands.jsonl"), { ts: core.ts(), walkthroughId: id, executedBy: "core", ...e }); w.commandLogHead = { seq: l.seq, hash: l.hash }; };
  for (const [i, p] of s.polls.entries()) log({ type: "alerts_poll", watchId: s.id, poll: i + 1, polledAt: p.at, endpoint, httpStatus: p.httpStatus ?? null, error: p.error ?? null, firing: p.firing.map((a) => a.labels.alertname ?? "?"), pending: p.pending, hops: p.hops ?? [] });
  const end = s.polls.at(-1)?.at ?? s.start;
  const firing = new Map<string, { alert: PromAlert; firstSeenAt: string }>();
  for (const p of s.polls) for (const a of p.firing) if (!firing.has(alertKey(a))) firing.set(alertKey(a), { alert: a, firstSeenAt: p.at });
  const pendingSeen = Math.max(0, ...s.polls.map((p) => p.pending));
  const errors = s.polls.filter((p) => p.error).length;
  const fired = [...firing.values()].map((x) => ({ ...x.alert, firstSeenAt: x.firstSeenAt }));
  const note = outcome === "interrupted"
    ? `已中断（interrupted）：轮询 ${s.polls.length} 次后停止；${end} 之后的数据缺失（不代表窗口内无告警）${fired.length ? `；此前看到 ${fired.length} 条触发中的告警` : ""}`
    : fired.length ? `窗口内 ${fired.length} 条告警触发` : errors === s.polls.length && s.polls.length ? `没有一次轮询成功（${errors} 次错误）；不代表窗口内无告警` : "窗口内无告警";
  const evId = `ev-${w.evidence.length + 1}`;
  const rel = `evidence/${evId}.json`;
  const doc = { format: ALERTS_EVIDENCE, watchId: s.id, endpoint, outcome, finalizedBy: reason, window: { start: s.start, end, deadline: s.deadline, requestedS: s.windowS, intervalS: s.intervalS },
    polls: s.polls.map((p) => ({ at: p.at, httpStatus: p.httpStatus ?? null, error: p.error ?? null, firing: p.firing.map((a) => a.labels.alertname ?? "?"), pending: p.pending })),
    firing: fired, pendingSeen, note };
  writeFileSync(join(core.dir(id), rel), red.text(JSON.stringify(doc, null, 2)));
  const ev: Evidence = { id: evId, type: "response", kind: "alert", path: rel, sha256: sha256File(join(core.dir(id), rel)), createdAt: core.ts(), executedBy: "core",
    source: red.text(`prometheus:${endpoint} ${s.start}..${end} (${outcome})`) };
  w.evidence.push(ev);
  const matchersFor = (c: Check) => [...(c.alertMatchers ?? []), ...s.matchers.filter((x) => x.checkId === c.id).map((x) => x.labels)];
  const watch: AlertWatch = { watchId: s.id, evidenceId: evId, start: s.start, end, polls: s.polls.length, outcome, ...(errors ? { errors: [...new Set(s.polls.flatMap((p) => p.error ? [p.error] : []))].slice(0, 5) } : {}), finalizedBy: reason, matched: [], unmatched: [], pendingSeen };
  const newFindings: Finding[] = [];
  for (const a of fired) {
    const name = a.labels.alertname ?? "(unnamed alert)";
    const checkIds = (w.checks ?? []).filter((c) => matchersFor(c).some((mm) => alertMatches(a, mm))).map((c) => c.id);
    if (!checkIds.length) { watch.unmatched.push({ alertname: name, labels: a.labels, severity: severityOf(a), activeAt: a.activeAt, firstSeenAt: a.firstSeenAt }); continue; }
    const claim = `Prometheus alert ${name} firing (activeAt ${a.activeAt ?? "?"}, first seen by walkthrough at ${a.firstSeenAt}) (${Object.entries(a.labels).filter(([k]) => k !== "alertname").map(([k, v]) => `${k}=${v}`).join(", ")})${a.annotations.summary ? `: ${a.annotations.summary}` : ""} — related to ${checkIds.join(", ")}`;
    const existing = (w.findings ?? []).find((f) => f.checkId && checkIds.includes(f.checkId));
    if (existing) {
      // Corroborating signal, NOT a causal step: the root-cause chain is left untouched.
      existing.corroborating = [...(existing.corroborating ?? []), { kind: "alert", claim, evidence_ids: [evId], alertname: name, activeAt: a.activeAt, firstSeenAt: a.firstSeenAt, alsoMatched: checkIds.filter((c) => c !== existing.checkId) }];
      if (!existing.evidenceIds.includes(evId)) existing.evidenceIds.push(evId);
      watch.matched.push({ alertname: name, checkIds, findingId: existing.id, attached: true, activeAt: a.activeAt, firstSeenAt: a.firstSeenAt });
    } else {
      const f: Finding = { id: `finding-${(w.findings ?? []).length + 1}`, title: `Alert ${name} firing`, severity: severityOf(a), symptom: claim,
        repro_steps: [`GET ${endpoint}`], root_cause_chain: [{ claim, kind: "observed", evidence_ids: [evId] }], evidenceIds: [evId], kind: "observed", checkId: checkIds[0] };
      w.findings = [...(w.findings ?? []), f];
      newFindings.push(f);
      watch.matched.push({ alertname: name, checkIds, findingId: f.id, attached: false, activeAt: a.activeAt, firstSeenAt: a.firstSeenAt });
    }
  }
  w.alertWatches = [...(w.alertWatches ?? []), watch];
  log({ type: "alerts_watch", watchId: s.id, evidenceId: evId, outputSha256: ev.sha256, start: s.start, end, outcome, finalizedBy: reason, polls: s.polls.length,
    firing: fired.length, pendingSeen, matched: watch.matched.map((x) => ({ alertname: x.alertname, checkIds: x.checkIds, findingId: x.findingId, attached: x.attached })), unmatched: watch.unmatched.map((x) => x.alertname) });
  core.save(w);
  core.writeWatch({ ...s, status: "finalized", outcome, evidenceId: evId });
  return { evidence: ev, watch, findings: newFindings };
}

export async function watchAlerts(core: MetricsCore, id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[] }): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
  const s = await core.startWatch(id, { ...input, background: "in-process" });
  await core.pollers.get(s.id)?.done;
  return core.collectWatch(s.id);
}
