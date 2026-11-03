import { createHash, randomBytes } from "node:crypto";
import { isSignedOff } from "./domain/decisions.js";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, writeSync, existsSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { acquireFileLock } from "./lockfile.js";
import { BLOCKED_EVIDENCE, type Capturer, type NavigationGuard, type PageCapture } from "./capture.js";
import { isIP } from "node:net";
import { Redactor } from "./redact.js";
import {
  appendLogEntry,
  type CommandLogEntry, type ConnectorConfig, type MongoTemplate,
} from "./runcli.js";
import type { Sandbox } from "./sandbox.js";
import type { Registry } from "./registry.js";
import { defaultRegistry } from "./sources.js";
import { parseHar, redactHar, redactUrl, redactUrlsIn, safeRegex } from "./har.js";
import { checkHop, flowPolicy, ReplayRejectedError, type Resolver } from "./egress/policy.js";
import { guardedGet, guardedRequest, replayRequest } from "./egress/fetch.js";
import { guardedWebSocket } from "./egress/ws.js";
import { allowedHostnames } from "./egress/allowhosts.js";
import { type ReplayConfig } from "./replay.js";
import type { NextAction, SubmittedEvidence } from "./ops/next-action.js";
import { ClaimRejectedError, SignedOffError } from "./errors.js";
import { sha256File } from "./hash.js";
import { agentFile, captureEvidence, captureEvidenceWith, importMcpResult, readEvidenceText } from "./ops/evidence.js";
import { importReview, signOff } from "./ops/review.js";
import { evaluateCheck, linkSource, planChecks, recordClaim, recordFinding, sourceLine, verifyEvidence } from "./ops/judge.js";
import { cliVersion, runCli, verifyCommandLogOp } from "./ops/cli.js";
import { collectWatch, finalizeWatch, listWatches, queryMetrics, readWatch, runPoller, spawnPoller, startWatch, stopPoller, watchAlerts, watchFile, writeWatch } from "./ops/metrics.js";
import { runInSandbox, sandboxCommand, sandboxExec } from "./ops/sandbox.js";
import { blockedUrlSecrets, maskAllQuery, wsHostKey } from "./ops/capture-urls.js";
import { flowScreenshot } from "./flow-capture.internal.js";
import { loadLoginState, captureSecretValues } from "./loginstate.js";
import { type PrometheusConfig } from "./metrics.js";
import { type AlertMatcher, type WatchState } from "./alerts.js";
import { type McpImportConnector } from "./imports.js";
import type {
  AlertWatch, Check, CheckResult, EvidenceKind, Finding, RootCauseLink, Severity, SignOff,
  Claim, ClaimKind, Evidence, RunRecord, SandboxConfig, SourceLink, Walkthrough,
} from "./types.js";

const safeId = (id: string) => id.replace(/[^\w.-]/g, "_");
export { ClaimRejectedError, SignedOffError } from "./errors.js";

export interface CoreDeps {
  /** Root directory that holds `.walkthrough/`. */
  root: string;
  sandboxFactory: (cfg: SandboxConfig, key?: string) => Sandbox;
  /** Action / observe / verifier registry for checks (defaults to http, command, log, rule). */
  registry?: Registry;
  capturer: Capturer;
  redactor?: Redactor;
  now?: () => Date;
  /** run_cli connectors (default: read-only presets aliyun / mqadmin / mongosh). */
  connectors?: ConnectorConfig[];
  /** MCP servers whose results may be imported (default: read-only presets mongodb / langfuse / aliyun). */
  mcpImports?: McpImportConnector[];
  /** HAR replay policy (host allowlist, CIDR exceptions, test-account auth). No config → replay is disabled. */
  replay?: ReplayConfig;
  /** DNS resolver for replay (injectable for tests). */
  resolver?: Resolver;
  /** Env used for replay test-account credentials (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** Read-only Prometheus endpoint (instant queries). Uses `replay` as its host allowlist + IP policy. */
  prometheus?: PrometheusConfig;
  /** Sleep used between alert polls (injectable for tests). */
  sleep?: (ms: number) => Promise<void>;
}

export interface ImportMcpInput {
  checkId?: string; connector: string; tool: string; params?: unknown; result: unknown;
  /** At least one: earlier evidence id + correlation key that must appear in both (e.g. trace id, order id). */
  links: { evidenceId: string; key: string }[];
}

export interface RunCliInput {
  checkId?: string; connector: string; argv?: string[]; template?: MongoTemplate; timeoutS?: number; cwd?: string;
}


export type { NextAction, SubmittedEvidence } from "./ops/next-action.js";

export { sha256File } from "./hash.js";

export { blockedUrlSecrets, maskAllQuery } from "./ops/capture-urls.js";

const READ_ONLY_METHODS = new Set(["GET", "HEAD"]);

export class WalkthroughCore {
  readonly base: string;
  /** @internal */
  redactor: Redactor;
  /** @internal */
  readonly now: () => Date;
  readonly registry: Registry;
  private readonly locks = new Map<string, Promise<unknown>>();
  /** Last raw log text seen per walkthrough+service, for `delta` log captures. */
  /** @internal */
  readonly logMarks = new Map<string, string>();

  /** Per-id serial lock (promise-chain mutex) around read-modify-write of walkthrough.json. */
  /** Serializes per walkthrough. Every write path goes through here; once signed off, writes are rejected. */
  /** @internal */
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts: { allowSigned?: boolean } = {}): Promise<T> {
    // In-process mutex first, then a cross-process lockfile; the sign-off state is re-read only AFTER both are held
    // (no check-then-lock window).
    const fn = async () => {
      const release = await acquireFileLock(join(this.base, `${safeId(id)}.lock`));
      try {
        if (!opts.allowSigned && existsSync(join(this.dir(id), "walkthrough.json")) && isSignedOff(this.load(id)))
          throw new SignedOffError(`walkthrough ${id} is signed off; it is read-only now`);
        return await fn0();
      } finally { release(); }
    };
    const prev = this.locks.get(id) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    const tail = next.catch(() => undefined);
    this.locks.set(id, tail);
    void tail.then(() => { if (this.locks.get(id) === tail) this.locks.delete(id); });
    return next;
  }

  constructor(/** @internal */ readonly deps: CoreDeps) {
    this.base = resolve(deps.root, ".walkthrough");
    this.redactor = deps.redactor ?? Redactor.fromEnv();
    this.now = deps.now ?? (() => new Date());
    this.registry = deps.registry ?? defaultRegistry();
    // Flow screenshot (runFlow only, via the internal WeakMap capability): same guarded path under flowPolicy(url) —
    // own host only; core blocklist and IP rules still apply. The policy is derived from the URL, never passed in.
    flowScreenshot.set(this, async (id, url) => this.captureEvidenceWith(id, { type: "screenshot", url }, await flowPolicy(url)));
  }

  get root(): string { return this.deps.root; }
  /** Also mask these values in everything written from now on (e.g. per-run values substituted into a flow config). */
  addRedactions(values: string[]): void { this.redactor = this.redactor.with(values); }

  dir(id: string): string {
    if (!/^[\w-]+$/.test(id)) throw new Error(`invalid walkthrough id: ${id}`);
    return join(this.base, id);
  }

  load(id: string): Walkthrough {
    const file = join(this.dir(id), "walkthrough.json");
    if (!existsSync(file)) throw new Error(`walkthrough not found: ${id}`);
    return JSON.parse(readFileSync(file, "utf8")) as Walkthrough;
  }

  /** @internal */
  save(w: Walkthrough): void {
    // Never overwrite the manifest in place: a process dying during write must leave the previous
    // snapshot readable. The random temporary name also avoids concurrent writers clobbering one
    // another before the walkthrough lock is acquired (for example during recovery).
    const file = join(this.dir(w.id), "walkthrough.json");
    const tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
    const body = JSON.stringify(this.redactor.value(w), null, 2);
    try {
      const fd = openSync(tmp, "w", 0o600);
      try { writeSync(fd, Buffer.from(body, "utf8")); fsyncSync(fd); } finally { closeSync(fd); }
      renameSync(tmp, file);
    } catch (e) {
      try { rmSync(tmp, { force: true }); } catch { /* preserve the original failure */ }
      throw e;
    }
  }

  /** @internal */
  ts(): string { return this.now().toISOString(); }

  startWalkthrough(input: { title: string; sandbox: SandboxConfig; id?: string }): Walkthrough {
    const id = input.id ?? `wt-${this.ts().replace(/[^0-9]/g, "").slice(0, 14)}-${randomBytes(3).toString("hex")}`;
    mkdirSync(join(this.dir(id), "evidence"), { recursive: true });
    const w: Walkthrough = {
      id, title: input.title, createdAt: this.ts(), sandbox: input.sandbox,
      runs: [], evidence: [], sources: [], claims: [],
    };
    this.save(w);
    return w;
  }

  runInSandbox(id: string, action: "up" | "down" | "exec", command?: string): Promise<RunRecord> {
    return runInSandbox(this, id, action, command);
  }

  /** @internal Body lives in ops/sandbox.ts. */
  sandboxExec(id: string, command?: string): Promise<RunRecord> {
    return sandboxExec(this, id, command);
  }

  /**
   * capture_evidence. `screenshot` / `logs` are captured by the core (executedBy core); `submit` stores raw output the
   * agent obtained itself (executedBy agent). Everything is redacted and sha256-hashed. `delta` logs = only new lines
   * since the previous capture of that service in this process.
   */
  captureEvidence(
    id: string,
    input: { type: "screenshot"; url: string; checkId?: string } | { type: "logs"; service: string; checkId?: string; delta?: boolean } | SubmittedEvidence,
  ): Promise<Evidence> {
    return captureEvidence(this, id, input);
  }

  /** @internal Body lives in ops/evidence.ts. */
  captureEvidenceWith(
    id: string,
    input: { type: "screenshot"; url: string; checkId?: string } | { type: "logs"; service: string; checkId?: string; delta?: boolean } | SubmittedEvidence,
    policy?: ReplayConfig,
  ): Promise<Evidence> {
    return captureEvidenceWith(this, id, input, policy);
  }

  /** @internal Body lives in ops/evidence.ts. */
  agentFile(p: string, kind: "har" | "screenshot"): string {
    return agentFile(this, p, kind);
  }

  /**
   * replay_request: walkthrough itself re-sends ONE GET/HEAD request found in a HAR evidence item (core-executed).
   * Host allowlist + IP policy from config, HAR cookies/auth never forwarded, redirects re-checked hop by hop. The result
   * is stored as a one-entry HAR (executedBy core) and appended to the hash-chained command log.
   */
  replayHar(id: string, input: { checkId: string; evidenceId: string; urlMatch?: string; method?: string }): Promise<Evidence> {
    return this.withLock(id, async () => {
      const cfg = this.deps.replay;
      if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("replay is not configured (no replay.allowHosts)");
      const w = this.load(id);
      if (!(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
      this.verifyEvidence(w, "observed", [input.evidenceId]);
      const src = w.evidence.find((e) => e.id === input.evidenceId)!;
      if (src.type !== "har") throw new ClaimRejectedError(`${src.id} is not HAR evidence`);
      const har = parseHar(readFileSync(join(this.dir(id), src.path), "utf8"))!;
      const re = input.urlMatch ? safeRegex(input.urlMatch) : undefined;
      const entry = har.log.entries.find((e) => (!re || re.test(String(e.request.url).slice(0, 2048))) && (!input.method || e.request.method.toUpperCase() === input.method.toUpperCase()));
      if (!entry) throw new ClaimRejectedError(`no HAR entry in ${src.id} matching ${input.urlMatch ?? "(any)"}`);
      // Only method + URL are taken from the HAR; its headers/cookies/body are never sent.
      const r = await replayRequest(cfg, { method: entry.request.method, url: entry.request.url }, { resolver: this.deps.resolver, env: this.deps.env });
      // Everything written for this run is redacted with the account value too (its env name may not look secret).
      const env = this.deps.env ?? process.env;
      const red = this.redactor.with([...r.sentSecrets, cfg.auth ? env[cfg.auth.valueEnv] : undefined]);
      const evId = `ev-${w.evidence.length + 1}`;
      const rel = `evidence/${evId}.har`;
      const out = { log: { version: "1.2", creator: { name: "walkthrough-replay", version: "1" }, entries: [{
        startedDateTime: this.ts(), request: { method: r.method, url: r.url, headers: [], cookies: [], queryString: [] },
        response: { status: r.status, headers: Object.entries(r.headers).map(([name, value]) => ({ name, value })), cookies: [], content: { mimeType: r.headers["content-type"] ?? "", text: r.body } },
        _hops: r.hops,
      }] } };
      writeFileSync(join(this.dir(id), rel), redactHar(JSON.stringify(out), red));
      const sha = sha256File(join(this.dir(id), rel));
      const log = appendLogEntry(join(this.dir(id), "commands.jsonl"), {
        ts: this.ts(), walkthroughId: id, type: "replay", checkId: input.checkId, fromEvidenceId: src.id,
        method: r.method, url: red.text(r.url), hops: r.hops.map((h) => ({ ...h, url: red.text(h.url) })), status: r.status,
        outputSha256: sha, evidenceId: evId, executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      const ev: Evidence = { id: evId, type: "har", kind: "har", path: rel, sha256: sha, createdAt: this.ts(), checkId: input.checkId, executedBy: "core",
        source: red.text(`replay:${r.method} ${r.url} (from ${src.id})`) };
      w.evidence.push(ev);
      this.save(w);
      return ev;
    });
  }

  /**
   * method: ui fallback when the host agent has no computer use: walkthrough loads the page itself (Playwright) and
   * stores screenshot + HAR + DOM text as core-executed evidence. Throws if the capturer has no page support.
   */
  capturePage(id: string, input: { url: string; checkId: string }): Promise<Evidence[]> {
    return this.withLock(id, async () => {
      if (!this.deps.capturer.page) throw new Error("page capture is not available (no Playwright capturer)");
      const cfg = this.deps.replay;
      if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("capture_page needs replay.allowHosts (same policy as replay)");
      const w = this.load(id);
      if (!(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
      // Login state (issue #19): read from the configured path now; its values are secrets for this capture.
      const login = cfg.capture?.storageStatePath ? loadLoginState(cfg, cfg.capture.storageStatePath) : undefined;
      const p = await this.guardedPage(cfg, input.url, login?.storageState);
      // Every query value / userinfo of a BLOCKED URL is treated as a secret for this capture, wherever it shows up
      // (blocked evidence, HAR — incl. the page HTML that embeds it —, DOM text, command log, report).
      const r = this.redactor.with([...blockedUrlSecrets((p.blocked ?? []).map((b) => b.url)), ...(login?.secrets ?? []), ...captureSecretValues(p.setCookieValues ?? [])]);
      const src = r.text(`playwright:${input.url}`);
      const out: Evidence[] = [];
      const add = (type: Evidence["type"], kind: EvidenceKind, ext: string, data: Buffer | string) => {
        const id2 = `ev-${w.evidence.length + 1}`, rel = `evidence/${id2}.${ext}`;
        writeFileSync(join(this.dir(id), rel), data);
        const ev: Evidence = { id: id2, type, kind, path: rel, source: src, executedBy: "core", checkId: input.checkId, sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts() };
        w.evidence.push(ev); out.push(ev);
      };
      add("screenshot", "screenshot", "png", p.screenshot);
      add("har", "har", "har", redactHar(p.har, r));
      add("response", "http", "txt", r.text(p.text));
      // Blocked requests are evidence too: URL redacted (secret params, userinfo, token patterns), reason, type.
      const blocked = (p.blocked ?? []).slice(0, 500).map((b) => ({ url: maskAllQuery(redactUrl(b.url, r)), method: b.method, type: b.type, reason: r.text(redactUrlsIn(b.reason, r)) }));
      const websockets = (p.websockets ?? []).slice(0, 200).map((x) => ({ ...x, url: redactUrl(x.url, r) }));
      // Every page→server message (forwarded or dropped) is evidence, redacted; binary payloads by size + sha256 only.
      const messages = (p.wsMessages ?? []).slice(0, 1000).map((m) => ({ url: redactUrl(m.url, r), direction: "page→server", forwarded: m.forwarded, bytes: m.bytes,
        ...(m.binary ? { binary: true, sha256: createHash("sha256").update(Buffer.from(m.data, "base64")).digest("hex") } : { data: r.text(redactUrlsIn(m.data.slice(0, 64 * 1024), r)) }) }));
      if (websockets.length || messages.length) add("response", "http", "json", JSON.stringify({ format: "walkthrough-websockets/1", url: redactUrl(input.url, r), websockets, messages }, null, 2));
      if (blocked.length) add("blocked", "blocked", "json", JSON.stringify({ format: BLOCKED_EVIDENCE, url: redactUrl(input.url, r), count: (p.blocked ?? []).length, blocked }, null, 2));
      const log = appendLogEntry(join(this.dir(id), "commands.jsonl"), {
        ts: this.ts(), walkthroughId: id, type: "capture_page", checkId: input.checkId,
        navigations: p.navigations.map((n) => ({ ...n, url: maskAllQuery(redactUrl(n.url, r)) })),
        subresources: p.subresources.slice(0, 200).map((s) => ({ ...s, url: maskAllQuery(redactUrl(s.url, r)) })),
        blocked: blocked.length,
        websockets,
        // counts only: no path, cookie names or values
        ...(login ? { loginState: login.summary } : {}),
        evidenceIds: out.map((e) => e.id), executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      this.save(w);
      return out;
    });
  }

  /** The one browser entry point: pre-check (clear error before any browser starts), then load under the pinned guard. */
  /** @internal */
  async guardedPage(cfg: ReplayConfig, url: string, storageState?: NavigationGuard["storageState"]): Promise<PageCapture> {
    if (!this.deps.capturer.page) throw new Error("page capture is not available (no Playwright capturer)");
    const guard = await this.pinnedGuard(cfg);
    await checkHop(cfg, new URL(url), guard.resolver); // same pinned resolution the browser will use
    return this.deps.capturer.page(url, storageState ? { ...guard, storageState } : guard);
  }

  /**
   * Guard for capture_page: each host is resolved ONCE per capture and the checked IP is pinned for every request
   * (our fetcher) and for Chromium itself (--host-resolver-rules); a rebinding resolver cannot move it later.
   */
  private async pinnedGuard(cfg: ReplayConfig): Promise<NavigationGuard & { resolver: Resolver }> {
    const base = this.deps.resolver ?? (async (h: string) => (await import("node:dns/promises")).lookup(h).then((r) => r.address));
    const pins = new Map<string, Promise<string>>();
    const resolver = (h: string) => { const k = h.toLowerCase(); if (!pins.has(k)) pins.set(k, base(k)); return pins.get(k)!; };
    const rules: string[] = [];
    for (const h of allowedHostnames(cfg)) {
      if (isIP(h.replace(/^\[|\]$/g, ""))) continue;
      try {
        const authority = isIP(h) === 6 ? `[${h}]` : h;
        const ip = await checkHop(cfg, new URL(`http://${authority}/`), resolver).catch(() => checkHop(cfg, new URL(`https://${authority}/`), resolver));
        rules.push(`MAP ${h} ${isIP(ip) === 6 ? `[${ip}]` : ip}`);
      } catch { /* not allowed / unresolvable: stays ~NOTFOUND for Chromium; our fetcher rejects it per request */ }
    }
    rules.push("MAP * ~NOTFOUND");
    return {
      resolver,
      hostResolverRules: rules.join(", "),
      fetch: (u, headers) => guardedGet(cfg, u, { resolver, headers }),
      // Issue #18: ws(s) URL judged exactly like http(s) (allowlist, IP rules, pinned resolution).
      // Issue #18: off unless capture.allowWebSocketHosts lists the host; then allowHosts + IP rules still apply.
      websocket: async (u, headers) => {
        const url = new URL(u);
        const key = wsHostKey(cfg.capture?.allowWebSocketHosts ?? [], url);
        if (!key) throw new ReplayRejectedError(`websocket to ${url.host} blocked (WebSockets are off by default; host not in capture.allowWebSocketHosts)`);
        const conn = await guardedWebSocket(cfg, u, { resolver, headers });
        return Object.assign(conn, { outbound: [...(cfg.capture?.webSocketOutbound?.[key] ?? [])] });
      },
      // Read-only like replay: only GET/HEAD are forwarded; anything else is blocked (and recorded) by the capturer.
      request: (r) => { if (!READ_ONLY_METHODS.has(r.method.toUpperCase())) throw new ReplayRejectedError(`${r.method.toUpperCase()} blocked (read-only: capture_page forwards only GET/HEAD)`); return guardedRequest(cfg, r.url, { method: r.method, headers: r.headers, body: r.body, resolver, maxBodyBytes: 5 * 1024 * 1024 }); },
    };
  }

  /**
   * query_metrics: walkthrough runs ONE Prometheus instant query itself (GET /api/v1/query only) and stores the
   * response as core-executed evidence (redacted, sha256) + a hash-chained commands.jsonl entry. The endpoint is
   * subject to replay.allowHosts and the IP policy; the bearer token is redacted from everything written.
   */
  queryMetrics(id: string, input: { query: string; checkId?: string; time?: string }): Promise<Evidence> {
    return queryMetrics(this, id, input);
  }

  // ---------------- alert watches (start_watch / collect_watch) ----------------
  // Process model: the poller only ever writes its OWN state file (.walkthrough/watches/<watchId>.json, single
  // writer) and never takes the walkthrough lock. In the MCP server it runs in-process in the background; the CLI
  // spawns it as a detached child (`walkthrough watch _poll`). collect_watch (or sign_off) stops it, then — briefly
  // under the walkthrough lock — appends every poll + the result to commands.jsonl and writes evidence/findings.
  /** @internal */
  readonly pollers = new Map<string, { stop: () => void; done: Promise<void> }>();

  /** @internal Body lives in ops/metrics.ts. */
  watchFile(watchId: string): string {
    return watchFile(this, watchId);
  }
  readWatch(watchId: string): WatchState {
    return readWatch(this, watchId);
  }
  /** @internal Body lives in ops/metrics.ts. */
  writeWatch(s: WatchState): void {
    return writeWatch(this, s);
  }
  /** @internal Body lives in ops/metrics.ts. */
  listWatches(walkthroughId?: string): WatchState[] {
    return listWatches(this, walkthroughId);
  }

  /**
   * start_watch: validate, persist the watch state and start polling GET /api/v1/alerts in the background. Returns
   * immediately; other tools stay callable. `background: "in-process"` (MCP, tests) or `"none"` (the CLI spawns a
   * detached poller itself).
   */
  startWatch(id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[]; background?: "in-process" | "none" }): Promise<WatchState> {
    return startWatch(this, id, input);
  }

  /** @internal Body lives in ops/metrics.ts. */
  spawnPoller(watchId: string): void {
    return spawnPoller(this, watchId);
  }

  /** The poll loop (in-process or in the CLI's detached child). Writes only the watch state file. */
  runPoller(watchId: string, stopped: () => boolean = () => false): Promise<void> {
    return runPoller(this, watchId, stopped);
  }

  /** @internal Body lives in ops/metrics.ts. */
  stopPoller(watchId: string): Promise<WatchState> {
    return stopPoller(this, watchId);
  }

  /** collect_watch: stop polling and finalize: evidence + findings (same matching/redaction), log entries. */
  collectWatch(watchId: string, opts: { reason?: "collect" | "sign_off" } = {}): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
    return collectWatch(this, watchId, opts);
  }

  /** @internal Body lives in ops/metrics.ts. */
  finalizeWatch(w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] } {
    return finalizeWatch(this, w, s, reason);
  }

  /** Convenience wrapper (tests / scripts): start_watch, wait for the window, collect_watch. Holds no lock while waiting. */
  watchAlerts(id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[] }): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
    return watchAlerts(this, id, input);
  }

  /** @internal */
  readonly versions = new Map<string, string>();

  /** @internal Body lives in ops/cli.ts. */
  cliVersion(c: ConnectorConfig, env: NodeJS.ProcessEnv, cwd: string): Promise<string> {
    return cliVersion(this, c, env, cwd);
  }

  /**
   * run_cli: execute a whitelisted read-only CLI ourselves (spawn(file,args), no shell), store the redacted output as
   * evidence (executedBy core) and append a hash-chained line to commands.jsonl. Rejections throw CliRejectedError and
   * never spawn anything.
   */
  runCli(id: string, input: RunCliInput): Promise<{ evidence: Evidence; log: CommandLogEntry; exitCode: number }> {
    return runCli(this, id, input);
  }

  /** Verify the command log chain, its head, and that each entry's output hash still matches its evidence file. */
  verifyCommandLog(id: string): { ok: boolean; entries: number; error?: string } {
    return verifyCommandLogOp(this, id);
  }

  /** @internal Body lives in ops/sandbox.ts. */
  sandboxCommand(w: Walkthrough, action: "up" | "down"): string {
    return sandboxCommand(this, w, action);
  }

  linkSource(id: string, input: { file: string; line: number; note?: string }): Promise<SourceLink> {
    return linkSource(this, id, input);
  }

  /** Validate evidence references; throws ClaimRejectedError for unverifiable observed claims. */
  verifyEvidence(w: Walkthrough, kind: ClaimKind, evidenceIds: string[]): void {
    return verifyEvidence(this, w, kind, evidenceIds);
  }

  recordClaim(id: string, input: {
    question: string; conclusion: string; kind: ClaimKind; evidenceIds?: string[]; sourceIds?: string[];
  }): Promise<Claim> {
    return recordClaim(this, id, input);
  }

  /** plan_checks: record the agent's plan. Every check needs a machine-checkable expect; returns next_actions. */
  planChecks(id: string, input: { goal: string; checks: Check[]; append?: boolean; triggeringEvidenceId?: string }): Promise<{ checks: Check[]; next_actions: NextAction[] }> {
    return planChecks(this, id, input);
  }

  /**
   * evaluate_check: the core judges pass/fail/inconclusive from verified evidence submitted for this check.
   * The input carries no verdict; the stored result can only be replaced by another core evaluation.
   */
  evaluateCheck(id: string, input: { checkId: string; evidenceIds: string[] }): Promise<CheckResult> {
    return evaluateCheck(this, id, input);
  }

  /** record_finding: symptom + repro + root_cause_chain. Observed steps need verified evidence; source refs must exist. */
  recordFinding(id: string, input: {
    title: string; severity: Severity; symptom: string; repro_steps?: string[]; root_cause_chain: RootCauseLink[]; check_id?: string;
    ruled_out?: { claim: string; check_id?: string; evidence_ids: string[] }[];
    inconclusive?: { claim: string; reason: string; check_id?: string; evidence_ids: string[] }[];
  }): Promise<Finding> {
    return recordFinding(this, id, input);
  }

  /** sign_off: the human's single report-level decision. */
  signOff(id: string, input: { decision: string; comment?: string }): Promise<SignOff> {
    return signOff(this, id, input);
  }

  /**
   * import_mcp_result: store a result the agent got from another MCP server (connector:<name>) as agent-reported
   * evidence. Rejected: unknown connector, tool not in its read-only list, no correlation link, linked evidence missing /
   * tampered, or correlation key absent from either side. Params: credential keys dropped, URI userinfo stripped, redacted.
   */
  importMcpResult(id: string, input: ImportMcpInput): Promise<Evidence> {
    return importMcpResult(this, id, input);
  }

  /** Read one line of a linked source file (inside root only), for showing the root cause inline. */
  sourceLine(file: string, line: number): string | undefined {
    return sourceLine(this, file, line);
  }

  /** Apply a downloaded review.json back into the walkthrough JSON. */
  importReview(review: unknown): Promise<{ id: string; applied: number }> {
    return importReview(this, review);
  }

  readEvidenceText(w: Walkthrough, ev: Evidence): string {
    return readEvidenceText(this, w, ev);
  }

  redact(s: string): string { return this.redactor.text(s); }

  /** The replay policy this core enforces (runFlow checks flow hosts against it). */
  replayPolicy(): Readonly<ReplayConfig> | undefined { return this.deps.replay; }
}
