import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync, existsSync, realpathSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { acquireFileLock } from "./lockfile.js";
import { execDecision } from "./execpolicy.js";
import { BLOCKED_EVIDENCE, type Capturer, type NavigationGuard } from "./capture.js";
import { isIP } from "node:net";
import { Redactor } from "./redact.js";
import {
  appendCommandLog, appendLogEntry, cliArgv, CliRejectedError, mongoArgv, PRESET_CONNECTORS, verifyCommandLog,
  type CommandLogEntry, type ConnectorConfig, type MongoTemplate,
  CLI_ENV_DENY,
} from "./runcli.js";
import { allowlistEnv, run } from "./sandbox.js";
import type { Sandbox } from "./sandbox.js";
import { expectProblem } from "./checks.js";
import type { Registry } from "./registry.js";
import { defaultRegistry } from "./sources.js";
import { HAR_MAX_BYTES, SCREENSHOT_MAX_BYTES, parseHar, redactHar, redactUrl, redactUrlsIn, safeRegex } from "./har.js";
import { checkHop, guardedGet, guardedRequest, replayRequest, ReplayRejectedError, type ReplayConfig, type Resolver } from "./replay.js";
import { METRIC_EVIDENCE, MetricsError, PROM_ALERTS_PATH, promGet, promInstantQuery, promUrl, type PrometheusConfig } from "./metrics.js";
import {
  ALERTS_EVIDENCE, ALERT_WATCH_MAX_INTERVAL_S, ALERT_WATCH_MAX_POLLS, ALERT_WATCH_MAX_WINDOW_S, ALERT_WATCH_MIN_INTERVAL_S,
  MAX_ACTIVE_WATCHES, WATCH_ID_RE, alertKey, alertMatches, matcherProblem, redactAlert, severityOf, type AlertMatcher, type PromAlert, type WatchPoll, type WatchState,
} from "./alerts.js";
import { MCP_IMPORT_PRESETS, sanitizeParams, scrub, type McpImportConnector } from "./imports.js";
import type {
  AlertWatch, Check, CheckResult, EvidenceKind, Finding, RootCauseLink, Severity, SignOff,
  Claim, ClaimKind, Evidence, Review, RunRecord, SandboxConfig, SourceLink, Walkthrough,
} from "./types.js";

const safeId = (id: string) => id.replace(/[^\w.-]/g, "_");
export class SignedOffError extends Error { constructor(m: string) { super(m); this.name = "SignedOffError"; } }
export class ClaimRejectedError extends Error {
  constructor(message: string) { super(message); this.name = "ClaimRejectedError"; }
}

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

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const METHODS = ["cli", "mcp", "ui", "http", "script"];
const KINDS: EvidenceKind[] = ["cli_output", "mcp_result", "http", "screenshot", "har", "log"];

/** Raw output the host agent obtained itself (own tools / external MCP / computer use) and submits for a check. */
export interface SubmittedEvidence {
  type: "submit"; checkId: string; kind: EvidenceKind;
  source: { tool: string; server?: string; command?: string };
  content?: string; path?: string;
}

/** Instruction returned to the host agent: what to do next (design: guide via next_actions, no server→agent calls). */
export interface NextAction { check_id: string; do: string; then: string[] }

function nextActionFor(c: Check): NextAction {
  const how: Record<string, [string, EvidenceKind]> = {
    http: [`send the request yourself: ${c.target}`, "http"],
    cli: [`run it yourself (or via run_cli when available): ${c.target}`, "cli_output"],
    mcp: [`call the external MCP tool yourself: ${c.target}`, "mcp_result"],
    ui: [`operate the page with computer use / Playwright: ${c.target}; judge by HAR or DOM text, not the screenshot`, "har"],
    script: [`run the script yourself: ${c.target}`, "cli_output"],
  };
  const [d, kind] = how[c.method];
  return {
    check_id: c.id, do: d,
    then: [`capture_evidence(check_id="${c.id}", kind="${kind}", content=<raw output, unedited>)`, `evaluate_check(check_id="${c.id}", evidence_ids=[...])`],
  };
}

export const sha256File = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

/** Query values (any name) and userinfo of the given URLs, as extra secrets. */
export function blockedUrlSecrets(urls: string[]): string[] {
  const out = new Set<string>();
  for (const u of urls) {
    try {
      const x = new URL(u);
      for (const v of x.searchParams.values()) if (v.length >= 3) { out.add(v); out.add(encodeURIComponent(v)); }
      if (x.username.length >= 3) out.add(decodeURIComponent(x.username));
      if (x.password.length >= 3) out.add(decodeURIComponent(x.password));
      if (x.search.length > 4) out.add(x.search.slice(1));
    } catch { /* unparseable: regex fallback in maskAllQuery */ }
  }
  return [...out];
}

/** Mask every query parameter value (not only known secret names) and any userinfo. */
export function maskAllQuery(u: string): string {
  try {
    const x = new URL(u);
    for (const k of [...new Set(x.searchParams.keys())]) x.searchParams.set(k, "[REDACTED]");
    if (x.username || x.password) { x.username = "[REDACTED]"; x.password = ""; }
    return x.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
  } catch { return u.replace(/([?&;][^=&#\s]*)=[^&#\s]*/g, "$1=[REDACTED]"); }
}

const READ_ONLY_METHODS = new Set(["GET", "HEAD"]);

export class WalkthroughCore {
  readonly base: string;
  private readonly redactor: Redactor;
  private readonly now: () => Date;
  readonly registry: Registry;
  private readonly locks = new Map<string, Promise<unknown>>();
  /** Last raw log text seen per walkthrough+service, for `delta` log captures. */
  private readonly logMarks = new Map<string, string>();

  /** Per-id serial lock (promise-chain mutex) around read-modify-write of walkthrough.json. */
  /** Serializes per walkthrough. Every write path goes through here; once signed off, writes are rejected. */
  private withLock<T>(id: string, fn0: () => T | Promise<T>, opts: { allowSigned?: boolean } = {}): Promise<T> {
    // In-process mutex first, then a cross-process lockfile; the sign-off state is re-read only AFTER both are held
    // (no check-then-lock window).
    const fn = async () => {
      const release = await acquireFileLock(join(this.base, `${safeId(id)}.lock`));
      try {
        if (!opts.allowSigned && existsSync(join(this.dir(id), "walkthrough.json")) && this.load(id).signoff)
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

  constructor(private readonly deps: CoreDeps) {
    this.base = resolve(deps.root, ".walkthrough");
    this.redactor = deps.redactor ?? Redactor.fromEnv();
    this.now = deps.now ?? (() => new Date());
    this.registry = deps.registry ?? defaultRegistry();
  }

  get root(): string { return this.deps.root; }

  dir(id: string): string {
    if (!/^[\w-]+$/.test(id)) throw new Error(`invalid walkthrough id: ${id}`);
    return join(this.base, id);
  }

  load(id: string): Walkthrough {
    const file = join(this.dir(id), "walkthrough.json");
    if (!existsSync(file)) throw new Error(`walkthrough not found: ${id}`);
    return JSON.parse(readFileSync(file, "utf8")) as Walkthrough;
  }

  private save(w: Walkthrough): void {
    writeFileSync(join(this.dir(w.id), "walkthrough.json"), JSON.stringify(this.redactor.value(w), null, 2));
  }

  private ts(): string { return this.now().toISOString(); }

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
    if (action === "exec") return this.sandboxExec(id, command);
    return this.withLock(id, async () => {
    const w = this.load(id);
    const sb = this.deps.sandboxFactory(w.sandbox, w.id);
    const res = action === "up" ? await sb.up() : await sb.down();
    const rec: RunRecord = {
      id: `run-${w.runs.length + 1}`,
      command: this.redactor.text(this.sandboxCommand(w, action)),
      exitCode: res.exitCode,
      output: this.redactor.text(res.output).slice(-20_000),
      createdAt: this.ts(),
    };
    w.runs.push(rec);
    this.save(w);
    return rec;
    });
  }

  /**
   * run_in_sandbox exec (issue #8). Off unless sandbox.allowExec: true. A command naming a known credentialed CLI
   * (aliyun, mqadmin, mongosh, …, by any path/case) never runs here: connector CLIs are routed through run_cli's
   * allowlist, the rest are rejected; shells/wrappers are rejected. Spawned as file + args, never via a shell.
   * Every exec is recorded (run record + hash-chained `sandbox_exec` log entry) and flagged red on the report.
   */
  private async sandboxExec(id: string, command?: string): Promise<RunRecord> {
    if (!command) throw new Error("exec requires a command");
    const w0 = this.load(id);
    if (w0.signoff) throw new SignedOffError(`walkthrough ${id} is signed off; it is read-only now`); // re-checked under the lock
    if (w0.sandbox.allowExec !== true) throw new CliRejectedError("run_in_sandbox exec is disabled (set sandbox.allowExec: true in the walkthrough config to enable arbitrary commands); use run_cli for CLIs");
    const d = execDecision(command, process.env, this.deps.connectors ?? PRESET_CONNECTORS);
    if (d.kind === "route") {
      const r = await this.runCli(id, { connector: d.connector.name, argv: d.argv });
      return this.withLock(id, () => {
        const w = this.load(id);
        const rec: RunRecord = { id: `run-${w.runs.length + 1}`, command: this.redactor.text(command), exitCode: r.exitCode, output: `routed to run_cli (${d.connector.name}), evidence ${r.evidence.id}`, createdAt: this.ts(), via: "run_cli" };
        w.runs.push(rec);
        this.save(w);
        return rec;
      });
    }
    return this.withLock(id, async () => {
      const w = this.load(id);
      const sb = this.deps.sandboxFactory(w.sandbox, w.id);
      const res = await sb.exec([d.file, ...d.args]);
      const rec: RunRecord = { id: `run-${w.runs.length + 1}`, command: this.redactor.text(command), exitCode: res.exitCode, output: this.redactor.text(res.output).slice(-20_000), createdAt: this.ts(), via: "exec" };
      w.runs.push(rec);
      const l = appendLogEntry(join(this.dir(id), "commands.jsonl"), { ts: rec.createdAt, walkthroughId: id, type: "sandbox_exec", runId: rec.id, command: rec.command, exitCode: rec.exitCode,
        outputSha256: createHash("sha256").update(rec.output).digest("hex"), executedBy: "core" });
      w.commandLogHead = { seq: l.seq, hash: l.hash };
      this.save(w);
      return rec;
    });
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
    return this.withLock(id, async () => {
    const w = this.load(id);
    if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
    const evId = `ev-${w.evidence.length + 1}`;
    const abs = (rel: string) => join(this.dir(id), rel);
    let ev: Omit<Evidence, "sha256" | "createdAt">;
    if (input.type === "screenshot") {
      ev = { id: evId, type: "screenshot", kind: "screenshot", path: `evidence/${evId}.png`, source: this.redactor.text(input.url), executedBy: "core" };
      await this.deps.capturer.screenshot(input.url, abs(ev.path));
    } else if (input.type === "logs") {
      ev = { id: evId, type: "logs", kind: "log", path: `evidence/${evId}.log`, source: `${w.sandbox.backend === "local" ? "local" : "docker"}:${input.service}`, executedBy: "core" };
      const raw = await this.deps.sandboxFactory(w.sandbox, w.id).logs(input.service);
      const key = `${id}\0${input.service}`;
      const prev = this.logMarks.get(key) ?? "";
      this.logMarks.set(key, raw);
      writeFileSync(abs(ev.path), this.redactor.text(input.delta && raw.startsWith(prev) ? raw.slice(prev.length) : raw));
    } else {
      if (!KINDS.includes(input.kind)) throw new Error(`invalid evidence kind: ${input.kind}`);
      if (!input.source?.tool) throw new Error("source.tool is required");
      const binary = input.kind === "screenshot" || input.kind === "har";
      if (binary && input.path && input.content === undefined) input = { ...input, path: this.agentFile(input.path, input.kind as "har" | "screenshot") };
      if (input.content === undefined && !(binary && input.path)) throw new Error(input.path ? "path is only accepted for screenshot/har; send text as content" : "content is required");
      const ext = input.kind === "screenshot" ? "png" : input.kind === "har" ? "har" : input.kind === "log" ? "log" : "txt";
      const s = input.source;
      ev = {
        id: evId, type: input.kind === "screenshot" ? "screenshot" : input.kind === "log" ? "logs" : "response", kind: input.kind,
        path: `evidence/${evId}.${ext}`, executedBy: "agent",
        source: this.redactor.text(`agent:${s.tool}${s.server ? `@${s.server}` : ""}${s.command ? ` ${s.command}` : ""}`),
      };
      if (input.kind === "har") ev.type = "har";
      const cap = input.kind === "screenshot" ? SCREENSHOT_MAX_BYTES : HAR_MAX_BYTES;
      const raw: Buffer = input.content !== undefined ? (input.kind === "screenshot" ? Buffer.from(input.content, "base64") : Buffer.from(input.content, "utf8")) : readFileSync(input.path!);
      if (raw.length > cap) throw new ClaimRejectedError(`${input.kind} too large: ${raw.length} bytes > ${cap}`);
      writeFileSync(abs(ev.path), input.kind === "screenshot" ? raw : input.kind === "har" ? redactHar(raw.toString("utf8"), this.redactor) : this.redactor.text(raw.toString("utf8")));
    }
    const full: Evidence = { ...ev, ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha256File(abs(ev.path)), createdAt: this.ts() };
    w.evidence.push(full);
    this.save(w);
    return full;
    });
  }

  /**
   * A screenshot/HAR file the agent hands over by path must live under `.walkthrough/` (after realpath, so a symlink
   * can't point outside) and stay under the size cap. Returns the resolved path.
   */
  private agentFile(p: string, kind: "har" | "screenshot"): string {
    let real: string;
    try { real = realpathSync(resolve(this.deps.root, p)); } catch { throw new ClaimRejectedError(`${kind} file not found: ${p}`); }
    const base = existsSync(this.base) ? realpathSync(this.base) : this.base;
    if (!real.startsWith(base + sep)) throw new ClaimRejectedError(`${kind} path must be inside ${this.base} (resolved to ${real})`);
    const st = statSync(real);
    if (!st.isFile()) throw new ClaimRejectedError(`${kind} path is not a regular file: ${p}`);
    const cap = kind === "har" ? HAR_MAX_BYTES : SCREENSHOT_MAX_BYTES;
    if (st.size > cap) throw new ClaimRejectedError(`${kind} too large: ${st.size} bytes > ${cap}`);
    return real;
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
      // Pre-check gives a clear error before any browser starts; every navigation hop is re-checked by the guard.
      const guard = await this.pinnedGuard(cfg);
      await checkHop(cfg, new URL(input.url), guard.resolver); // same pinned resolution the browser will use
      const p = await this.deps.capturer.page(input.url, guard);
      // Every query value / userinfo of a BLOCKED URL is treated as a secret for this capture, wherever it shows up
      // (blocked evidence, HAR — incl. the page HTML that embeds it —, DOM text, command log, report).
      const r = this.redactor.with(blockedUrlSecrets((p.blocked ?? []).map((b) => b.url)));
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
      if (blocked.length) add("blocked", "blocked", "json", JSON.stringify({ format: BLOCKED_EVIDENCE, url: redactUrl(input.url, r), count: (p.blocked ?? []).length, blocked }, null, 2));
      const log = appendLogEntry(join(this.dir(id), "commands.jsonl"), {
        ts: this.ts(), walkthroughId: id, type: "capture_page", checkId: input.checkId,
        navigations: p.navigations.map((n) => ({ ...n, url: redactUrl(n.url, r) })),
        subresources: p.subresources.slice(0, 200).map((s) => ({ ...s, url: redactUrl(s.url, r) })),
        blocked: blocked.length,
        evidenceIds: out.map((e) => e.id), executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      this.save(w);
      return out;
    });
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
    for (const h of new Set(cfg.allowHosts.map((x) => x.toLowerCase().split(/:(?=\d+$)/)[0]))) {
      if (isIP(h.replace(/^\[|\]$/g, ""))) continue;
      try {
        const ip = await checkHop(cfg, new URL(`http://${h}/`), resolver).catch(() => checkHop(cfg, new URL(`https://${h}/`), resolver));
        rules.push(`MAP ${h} ${isIP(ip) === 6 ? `[${ip}]` : ip}`);
      } catch { /* not allowed / unresolvable: stays ~NOTFOUND for Chromium; our fetcher rejects it per request */ }
    }
    rules.push("MAP * ~NOTFOUND");
    return {
      resolver,
      hostResolverRules: rules.join(", "),
      fetch: (u) => guardedGet(cfg, u, { resolver }),
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
    return this.withLock(id, async () => {
      const prom = this.deps.prometheus;
      if (!prom) throw new MetricsError("Prometheus is not configured (WALKTHROUGH_PROMETHEUS_URL)");
      const cfg = this.deps.replay;
      if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("query_metrics needs replay.allowHosts (same policy as replay)");
      const w = this.load(id);
      if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
      const env = this.deps.env ?? process.env;
      const token = env[prom.tokenEnv ?? "WALKTHROUGH_PROMETHEUS_TOKEN"];
      let r;
      try {
        r = await promInstantQuery(prom, cfg, input.query, { time: input.time, resolver: this.deps.resolver, env });
      } catch (e) {
        throw new (e instanceof Error ? (e.constructor as ErrorConstructor) : Error)(this.redactor.with([token, token && `Bearer ${token}`]).text(String((e as Error).message)));
      }
      const red = this.redactor.with([...r.sentSecrets, token]);
      const evId = `ev-${w.evidence.length + 1}`;
      const rel = `evidence/${evId}.json`;
      const doc = { format: METRIC_EVIDENCE, endpoint: red.text(new URL(r.url).origin + new URL(r.url).pathname), query: input.query, time: input.time ?? null, httpStatus: r.status, response: red.value(r.json) };
      writeFileSync(join(this.dir(id), rel), red.text(JSON.stringify(doc, null, 2)));
      const sha = sha256File(join(this.dir(id), rel));
      const log = appendLogEntry(join(this.dir(id), "commands.jsonl"), {
        ts: this.ts(), walkthroughId: id, type: "metrics_query", checkId: input.checkId, endpoint: doc.endpoint, query: red.text(input.query),
        time: input.time ?? null, httpStatus: r.status, promStatus: r.json.status ?? null, hops: r.hops.map((h) => ({ ...h, url: red.text(h.url) })),
        outputSha256: sha, evidenceId: evId, executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      const ev: Evidence = { id: evId, type: "response", kind: "metric", path: rel, sha256: sha, createdAt: this.ts(), executedBy: "core",
        ...(input.checkId ? { checkId: input.checkId } : {}), source: red.text(`prometheus:${doc.endpoint} ${input.query}`).slice(0, 500) };
      w.evidence.push(ev);
      this.save(w);
      return ev;
    });
  }

  // ---------------- alert watches (start_watch / collect_watch) ----------------
  // Process model: the poller only ever writes its OWN state file (.walkthrough/watches/<watchId>.json, single
  // writer) and never takes the walkthrough lock. In the MCP server it runs in-process in the background; the CLI
  // spawns it as a detached child (`walkthrough watch _poll`). collect_watch (or sign_off) stops it, then — briefly
  // under the walkthrough lock — appends every poll + the result to commands.jsonl and writes evidence/findings.
  private readonly pollers = new Map<string, { stop: () => void; done: Promise<void> }>();

  private watchFile(watchId: string): string {
    if (typeof watchId !== "string" || !WATCH_ID_RE.test(watchId)) throw new ClaimRejectedError(`invalid watch id: ${JSON.stringify(watchId)}`);
    const dir = resolve(this.base, "watches");
    const f = resolve(dir, `${watchId}.json`);
    if (!f.startsWith(dir + sep)) throw new ClaimRejectedError("watch path escapes .walkthrough/watches");
    return f;
  }
  readWatch(watchId: string): WatchState {
    const f = this.watchFile(watchId);
    if (!existsSync(f)) throw new ClaimRejectedError(`watch not found: ${watchId}`);
    return JSON.parse(readFileSync(f, "utf8")) as WatchState;
  }
  private writeWatch(s: WatchState): void {
    const f = this.watchFile(s.id);
    mkdirSync(resolve(this.base, "watches"), { recursive: true });
    writeFileSync(`${f}.tmp`, JSON.stringify(s, null, 2));
    renameSync(`${f}.tmp`, f);
  }
  private listWatches(walkthroughId?: string): WatchState[] {
    const dir = resolve(this.base, "watches");
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter((n) => /^w_[0-9a-f]{16}\.json$/.test(n)).map((n) => JSON.parse(readFileSync(join(dir, n), "utf8")) as WatchState)
      .filter((s) => !walkthroughId || s.walkthroughId === walkthroughId);
  }

  /**
   * start_watch: validate, persist the watch state and start polling GET /api/v1/alerts in the background. Returns
   * immediately; other tools stay callable. `background: "in-process"` (MCP, tests) or `"none"` (the CLI spawns a
   * detached poller itself).
   */
  startWatch(id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[]; background?: "in-process" | "none" }): Promise<WatchState> {
    return this.withLock(id, async () => {
      const prom = this.deps.prometheus;
      if (!prom) throw new MetricsError("Prometheus is not configured (WALKTHROUGH_PROMETHEUS_URL)");
      const cfg = this.deps.replay;
      if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("start_watch needs replay.allowHosts (same policy as replay)");
      const windowS = input.windowS ?? 60, intervalS = input.intervalS ?? 15;
      if (!Number.isFinite(windowS) || windowS < 1 || windowS > ALERT_WATCH_MAX_WINDOW_S) throw new ClaimRejectedError(`window_s must be 1-${ALERT_WATCH_MAX_WINDOW_S}`);
      if (!Number.isFinite(intervalS) || intervalS < ALERT_WATCH_MIN_INTERVAL_S || intervalS > ALERT_WATCH_MAX_INTERVAL_S) throw new ClaimRejectedError(`interval_s must be ${ALERT_WATCH_MIN_INTERVAL_S}-${ALERT_WATCH_MAX_INTERVAL_S}`);
      const w = this.load(id);
      for (const x of input.matchers ?? []) {
        if (!(w.checks ?? []).some((c) => c.id === x.checkId)) throw new ClaimRejectedError(`unknown check: ${x.checkId}`);
        const p = matcherProblem(x.labels); if (p) throw new ClaimRejectedError(p);
      }
      promUrl(prom.url, PROM_ALERTS_PATH); // validates the base URL before anything starts
      await checkHop(cfg, new URL(prom.url), this.deps.resolver); // fail fast on allowlist / IP policy
      const active = this.listWatches().filter((s) => s.status === "running");
      if (active.length >= MAX_ACTIVE_WATCHES) throw new ClaimRejectedError(`too many active watches (${active.length}/${MAX_ACTIVE_WATCHES}); collect one first`);
      const now = this.now();
      const s: WatchState = {
        id: `w_${randomBytes(8).toString("hex")}`, walkthroughId: id, windowS, intervalS, matchers: input.matchers ?? [],
        start: now.toISOString(), deadline: new Date(now.getTime() + windowS * 1000).toISOString(), status: "running",
        polls: [], heartbeat: now.toISOString(), pid: process.pid,
      };
      this.writeWatch(s);
      if ((input.background ?? "in-process") === "in-process") this.spawnPoller(s.id);
      return s;
    });
  }

  private spawnPoller(watchId: string): void {
    let stopped = false;
    const done = this.runPoller(watchId, () => stopped).catch(() => undefined).finally(() => this.pollers.delete(watchId));
    this.pollers.set(watchId, { stop: () => { stopped = true; }, done });
  }

  /** The poll loop (in-process or in the CLI's detached child). Writes only the watch state file. */
  async runPoller(watchId: string, stopped: () => boolean = () => false): Promise<void> {
    const prom = this.deps.prometheus!, cfg = this.deps.replay!;
    const env = this.deps.env ?? process.env;
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const url = promUrl(prom.url, PROM_ALERTS_PATH);
    let s = this.readWatch(watchId);
    s.pid = process.pid; this.writeWatch(s);
    const token = env[prom.tokenEnv ?? "WALKTHROUGH_PROMETHEUS_TOKEN"];
    for (let i = 0; i < ALERT_WATCH_MAX_POLLS; i++) {
      s = this.readWatch(watchId);
      if (s.status !== "running" || s.stopRequested || stopped()) break;
      if (i && this.now().getTime() > Date.parse(s.deadline)) break;
      const at = this.ts();
      let red = this.redactor.with([token, token && `Bearer ${token}`]);
      let rec: WatchPoll;
      try {
        const r = await promGet(prom, cfg, url, PROM_ALERTS_PATH, { resolver: this.deps.resolver, env });
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
      s = this.readWatch(watchId);
      if (s.status !== "running") break;
      s.polls.push(rec); s.heartbeat = this.ts();
      this.writeWatch(s);
      if (this.now().getTime() + s.intervalS * 1000 > Date.parse(s.deadline) + 1) break;
      if (this.deps.sleep) await sleep(s.intervalS * 1000);
      else for (let t = 0; t < s.intervalS * 1000 && !stopped() && !this.readWatch(watchId).stopRequested; t += 200) await sleep(200); // stop-aware wait
    }
    s = this.readWatch(watchId);
    if (s.status === "running") { s.status = (s.stopRequested || stopped()) && this.now().getTime() < Date.parse(s.deadline) ? "stopped" : "done"; s.heartbeat = this.ts(); this.writeWatch(s); }
  }

  /** Stop the poller (own process: abort + await; other process: request stop and wait briefly). Returns final state. */
  private async stopPoller(watchId: string): Promise<WatchState> {
    const p = this.pollers.get(watchId);
    if (p) { p.stop(); await p.done; return this.readWatch(watchId); }
    let s = this.readWatch(watchId);
    if (s.status !== "running") return s;
    s.stopRequested = true; this.writeWatch(s);
    const alive = (() => { try { process.kill(s.pid, 0); return s.pid !== process.pid; } catch { return false; } })();
    if (alive) {
      const until = Date.now() + Math.min(15_000, (s.intervalS + 11) * 1000);
      while (Date.now() < until) { await new Promise((r) => setTimeout(r, 200)); s = this.readWatch(watchId); if (s.status !== "running") return s; }
    }
    // No live poller finished it: whatever was observed is partial. Never reported as a quiet window.
    s = this.readWatch(watchId);
    if (s.status === "running") { s.status = "interrupted"; this.writeWatch(s); }
    return s;
  }

  /** collect_watch: stop polling and finalize: evidence + findings (same matching/redaction), log entries. */
  async collectWatch(watchId: string, opts: { reason?: "collect" | "sign_off" } = {}): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
    const s0 = this.readWatch(watchId);
    if (s0.status === "finalized") throw new ClaimRejectedError(`watch ${watchId} already collected`);
    const s = await this.stopPoller(watchId);
    return this.withLock(s.walkthroughId, async () => this.finalizeWatch(this.load(s.walkthroughId), this.readWatch(watchId), opts.reason ?? "collect"));
  }

  /** Caller holds the walkthrough lock. Saves w. */
  private finalizeWatch(w: Walkthrough, s: WatchState, reason: "collect" | "sign_off"): { evidence: Evidence; watch: AlertWatch; findings: Finding[] } {
    const id = w.id;
    if (s.status === "finalized") throw new ClaimRejectedError(`watch ${s.id} already collected`);
    const outcome: AlertWatch["outcome"] = s.status === "interrupted" ? "interrupted" : s.status === "done" ? "completed" : "stopped_early"; // "stopped"/"running" = collected before the deadline
    const red = this.redactor;
    const prom = this.deps.prometheus;
    const endpoint = prom ? red.text(promUrl(prom.url, PROM_ALERTS_PATH).origin + PROM_ALERTS_PATH) : "(unconfigured)";
    const log = (e: Record<string, unknown>) => { const l = appendLogEntry(join(this.dir(id), "commands.jsonl"), { ts: this.ts(), walkthroughId: id, executedBy: "core", ...e }); w.commandLogHead = { seq: l.seq, hash: l.hash }; };
    for (const [i, p] of s.polls.entries()) log({ type: "alerts_poll", watchId: s.id, poll: i + 1, polledAt: p.at, endpoint, httpStatus: p.httpStatus ?? null, error: p.error ?? null, firing: p.firing.map((a) => a.labels.alertname ?? "?"), pending: p.pending, hops: p.hops ?? [] });
    const end = s.polls.at(-1)?.at ?? s.start;
    const firing = new Map<string, { alert: PromAlert; firstSeenAt: string }>();
    for (const p of s.polls) for (const a of p.firing) if (!firing.has(alertKey(a))) firing.set(alertKey(a), { alert: a, firstSeenAt: p.at });
    const pendingSeen = Math.max(0, ...s.polls.map((p) => p.pending));
    const errors = s.polls.filter((p) => p.error).length;
    const fired = [...firing.values()].map((x) => ({ ...x.alert, firstSeenAt: x.firstSeenAt }));
    const note = outcome === "interrupted"
      ? `interrupted: poller stopped after ${s.polls.length} poll(s); data after ${end} is missing (NOT a quiet window)${fired.length ? `; ${fired.length} firing alert(s) seen before that` : ""}`
      : fired.length ? `${fired.length} firing alert(s) in window` : errors === s.polls.length && s.polls.length ? `no successful poll (${errors} error(s)); NOT a quiet window` : "no alerts in window";
    const evId = `ev-${w.evidence.length + 1}`;
    const rel = `evidence/${evId}.json`;
    const doc = { format: ALERTS_EVIDENCE, watchId: s.id, endpoint, outcome, finalizedBy: reason, window: { start: s.start, end, deadline: s.deadline, requestedS: s.windowS, intervalS: s.intervalS },
      polls: s.polls.map((p) => ({ at: p.at, httpStatus: p.httpStatus ?? null, error: p.error ?? null, firing: p.firing.map((a) => a.labels.alertname ?? "?"), pending: p.pending })),
      firing: fired, pendingSeen, note };
    writeFileSync(join(this.dir(id), rel), red.text(JSON.stringify(doc, null, 2)));
    const ev: Evidence = { id: evId, type: "response", kind: "alert", path: rel, sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts(), executedBy: "core",
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
    this.save(w);
    this.writeWatch({ ...s, status: "finalized", outcome, evidenceId: evId });
    return { evidence: ev, watch, findings: newFindings };
  }

  /** Convenience wrapper (tests / scripts): start_watch, wait for the window, collect_watch. Holds no lock while waiting. */
  async watchAlerts(id: string, input: { windowS?: number; intervalS?: number; matchers?: { checkId: string; labels: AlertMatcher }[] }): Promise<{ evidence: Evidence; watch: AlertWatch; findings: Finding[] }> {
    const s = await this.startWatch(id, { ...input, background: "in-process" });
    await this.pollers.get(s.id)?.done;
    return this.collectWatch(s.id);
  }

  private readonly versions = new Map<string, string>();

  private async cliVersion(c: ConnectorConfig, env: NodeJS.ProcessEnv, cwd: string): Promise<string> {
    const key = `${c.name}\0${c.binary}`;
    if (!this.versions.has(key)) {
      const r = await run(c.binary, c.versionArgs ?? ["--version"], { cwd, env, timeoutMs: 5_000, maxBytes: 4096 });
      this.versions.set(key, r.exitCode === 0 ? this.redactor.text(r.output.trim().split("\n")[0] ?? "").slice(0, 120) || "unknown" : "unknown");
    }
    return this.versions.get(key)!;
  }

  /**
   * run_cli: execute a whitelisted read-only CLI ourselves (spawn(file,args), no shell), store the redacted output as
   * evidence (executedBy core) and append a hash-chained line to commands.jsonl. Rejections throw CliRejectedError and
   * never spawn anything.
   */
  runCli(id: string, input: RunCliInput): Promise<{ evidence: Evidence; log: CommandLogEntry; exitCode: number }> {
    return this.withLock(id, async () => {
      const w = this.load(id);
      if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
      if ((input as { env?: unknown }).env !== undefined) throw new CliRejectedError("run_cli does not accept env from the caller");
      const c = (this.deps.connectors ?? PRESET_CONNECTORS).find((x) => x.name === input.connector);
      if (!c) throw new CliRejectedError(`unknown connector: ${input.connector}`);
      let argv: string[];
      if (c.kind === "mongo") {
        if (input.argv?.length) throw new CliRejectedError("mongosh accepts only a query template (find|aggregate|countDocuments), not argv");
        argv = mongoArgv(c, input.template as MongoTemplate);
      } else {
        if (input.template) throw new CliRejectedError(`${c.name} takes argv, not a template`);
        argv = cliArgv(c, input.argv ?? []);
      }
      const root = resolve(w.sandbox.cwd);
      const cwd = resolve(root, input.cwd ?? ".");
      if (cwd !== root && !cwd.startsWith(root + sep)) throw new CliRejectedError(`cwd outside the walkthrough root: ${input.cwd}`);
      const env = allowlistEnv([...(w.sandbox.local?.passEnv ?? []), ...(c.passEnv ?? [])].filter((n) => !CLI_ENV_DENY.test(n)));
      for (const n of Object.keys(env)) if (CLI_ENV_DENY.test(n)) delete env[n];
      const version = await this.cliVersion(c, env, cwd);
      const timeoutMs = Math.min(Math.max(1, input.timeoutS ?? 60), 600) * 1000;
      const res = await run(c.binary, argv, { cwd, env, timeoutMs });
      const shown = argv.map((a) => this.redactor.text(a));
      const evId = `ev-${w.evidence.length + 1}`;
      const rel = `evidence/${evId}.txt`;
      writeFileSync(join(this.dir(id), rel), this.redactor.text(`$ ${c.name} ${JSON.stringify(shown)}\nexit ${res.exitCode}\n\n${res.output}`));
      const sha = sha256File(join(this.dir(id), rel));
      const evidence: Evidence = {
        id: evId, type: "response", kind: "cli_output", path: rel, executedBy: "core",
        source: `run_cli:${c.name} ${shown.join(" ")}`.slice(0, 500), ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha, createdAt: this.ts(),
      };
      const log = appendCommandLog(join(this.dir(id), "commands.jsonl"), {
        ts: evidence.createdAt, walkthroughId: id, ...(input.checkId ? { checkId: input.checkId } : {}), connector: c.name,
        cli: { name: c.binary.split("/").pop()!, version, ...(c.profile ? { profile: c.profile } : {}) },
        argv: shown, cwd: input.cwd ?? ".", exitCode: res.exitCode, outputSha256: sha, evidenceId: evId, executedBy: "core",
      });
      w.evidence.push(evidence);
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      this.save(w);
      return { evidence, log, exitCode: res.exitCode };
    });
  }

  /** Verify the command log chain, its head, and that each entry's output hash still matches its evidence file. */
  verifyCommandLog(id: string): { ok: boolean; entries: number; error?: string } {
    const w = this.load(id);
    const file = join(this.dir(id), "commands.jsonl");
    const r = verifyCommandLog(file, w.commandLogHead);
    if (!r.ok || !existsSync(file)) return r;
    for (const line of readFileSync(file, "utf8").split("\n").filter(Boolean)) {
      const e = JSON.parse(line) as CommandLogEntry & { type?: string; checkSha256?: string; triggeringEvidenceId?: string };
      if (e.type === "plan_append") {
        const c = (w.checks ?? []).find((x) => x.id === e.checkId);
        const { appended: _a, ...plain } = c ?? ({} as Check);
        if (!c || createHash("sha256").update(JSON.stringify(plain)).digest("hex") !== e.checkSha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: appended check ${e.checkId} missing or modified` };
        if (!w.evidence.some((x) => x.id === e.triggeringEvidenceId)) return { ok: false, entries: r.entries, error: `seq ${e.seq}: triggering evidence ${e.triggeringEvidenceId} missing` };
        continue;
      }
      const multi = (e as unknown as { evidenceIds?: string[] }).evidenceIds;
      if (Array.isArray(multi)) { // capture_page: several evidence items, each checked against its stored hash
        for (const x of multi) {
          const ev2 = w.evidence.find((y) => y.id === x);
          if (!ev2 || !existsSync(join(this.dir(id), ev2.path)) || sha256File(join(this.dir(id), ev2.path)) !== ev2.sha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: evidence ${x} missing or modified` };
        }
        continue;
      }
      if (e.type === "sandbox_exec") { // tie to the stored run record
        const run = w.runs.find((x) => x.id === (e as unknown as { runId?: string }).runId);
        if (!run || createHash("sha256").update(run.output).digest("hex") !== e.outputSha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: sandbox exec run missing or modified` };
        continue;
      }
      if (e.evidenceId === undefined && e.type === "alerts_poll") continue; // per-poll record; the watch entry carries the evidence
      const ev = w.evidence.find((x) => x.id === e.evidenceId);
      const p = ev && join(this.dir(id), ev.path);
      if (!ev || ev.sha256 !== e.outputSha256 || !existsSync(p!) || sha256File(p!) !== e.outputSha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: evidence ${e.evidenceId} missing or modified` };
    }
    return r;
  }

  private sandboxCommand(w: Walkthrough, action: "up" | "down"): string {
    if (w.sandbox.backend === "local") return action === "up" ? (w.sandbox.local?.up ?? w.sandbox.up) : "kill local process group";
    return action === "up" ? w.sandbox.up : w.sandbox.down;
  }

  linkSource(id: string, input: { file: string; line: number; note?: string }): Promise<SourceLink> {
    return this.withLock(id, () => {
    if (!Number.isInteger(input.line) || input.line < 1) throw new Error("line must be a positive integer");
    const w = this.load(id);
    const link: SourceLink = { id: `src-${w.sources.length + 1}`, file: input.file, line: input.line, note: input.note };
    w.sources.push(link);
    this.save(w);
    return link;
    });
  }

  /** Validate evidence references; throws ClaimRejectedError for unverifiable observed claims. */
  verifyEvidence(w: Walkthrough, kind: ClaimKind, evidenceIds: string[]): void {
    if (kind === "observed" && evidenceIds.length === 0) {
      throw new ClaimRejectedError("observed claim must reference at least one evidence id");
    }
    for (const evId of evidenceIds) {
      const ev = w.evidence.find((e) => e.id === evId);
      if (!ev) throw new ClaimRejectedError(`evidence not found: ${evId}`);
      const file = join(this.dir(w.id), ev.path);
      if (!existsSync(file)) throw new ClaimRejectedError(`evidence file missing: ${evId}`);
      if (sha256File(file) !== ev.sha256) throw new ClaimRejectedError(`evidence hash mismatch: ${evId}`);
    }
  }

  recordClaim(id: string, input: {
    question: string; conclusion: string; kind: ClaimKind; evidenceIds?: string[]; sourceIds?: string[];
  }): Promise<Claim> {
    return this.withLock(id, () => {
    if (input.kind !== "observed" && input.kind !== "inferred") throw new ClaimRejectedError("kind must be observed or inferred");
    const w = this.load(id);
    const evidenceIds = input.evidenceIds ?? [];
    const sourceIds = input.sourceIds ?? [];
    this.verifyEvidence(w, input.kind, evidenceIds);
    for (const s of sourceIds) if (!w.sources.some((x) => x.id === s)) throw new ClaimRejectedError(`source link not found: ${s}`);
    const claim: Claim = {
      id: `claim-${w.claims.length + 1}`, question: input.question, conclusion: input.conclusion,
      kind: input.kind, evidenceIds, sourceIds,
    };
    w.claims.push(claim);
    this.save(w);
    return claim;
    });
  }

  /** plan_checks: record the agent's plan. Every check needs a machine-checkable expect; returns next_actions. */
  planChecks(id: string, input: { goal: string; checks: Check[]; append?: boolean; triggeringEvidenceId?: string }): Promise<{ checks: Check[]; next_actions: NextAction[] }> {
    return this.withLock(id, () => {
      const w = this.load(id);
      // append = follow-up checks discovered mid-run (e.g. while tracing a 500). Append-only: existing checks and
      // verdicts can't be changed or removed; each appended check is written to the hash-chained command log.
      const existing = new Map((input.append ? w.checks ?? [] : []).map((c) => [c.id, c]));
      if (input.append) {
        if (!input.triggeringEvidenceId) throw new ClaimRejectedError("append requires triggeringEvidenceId (the evidence that made you add these checks)");
        this.verifyEvidence(w, "observed", [input.triggeringEvidenceId]);
      }
      const ids = new Set<string>(existing.keys());
      for (const c of input.checks) {
        const prev = existing.get(c.id);
        if (prev) throw new ClaimRejectedError(`append-only: check ${c.id} already exists${JSON.stringify(prev.expect) !== JSON.stringify(c.expect) ? " (changing its expect is not allowed)" : ""}`);
        if (!c.id || ids.has(c.id)) throw new Error(`check ids must be unique and non-empty: ${c.id}`);
        const problem = expectProblem(c.expect);
        if (problem) throw new Error(`check ${c.id}: expect is not machine-checkable (${problem})`);
        if (!METHODS.includes(c.method)) throw new Error(`check ${c.id}: method must be one of ${METHODS.join("|")}`);
        if (!c.intent || !c.target) throw new Error(`check ${c.id}: intent and target are required`);
        if (!SEVERITIES.includes(c.severity_if_fail)) throw new Error(`check ${c.id}: severity_if_fail must be one of ${SEVERITIES.join("|")}`);
        if (c.verify && !this.registry.has("verifier", c.verify.type)) throw new Error(`check ${c.id}: verifier "${c.verify.type}" not available`);
        for (const mm of c.alertMatchers ?? []) { const p = matcherProblem(mm); if (p) throw new Error(`check ${c.id}: ${p}`); }
        ids.add(c.id);
      }
      if (!input.append) {
        w.goal = input.goal;
        w.checks = input.checks.map(({ appended: _a, ...c }) => c as Check);
        w.checkResults = [];
        this.save(w);
        return { checks: w.checks, next_actions: w.checks.map(nextActionFor) };
      }
      const added: Check[] = [];
      for (const raw of input.checks) {
        const { appended: _a, ...c } = raw;
        const at = this.ts();
        const log = appendLogEntry(join(this.dir(id), "commands.jsonl"), {
          ts: at, walkthroughId: id, type: "plan_append", checkId: c.id,
          checkSha256: createHash("sha256").update(JSON.stringify(c)).digest("hex"), triggeringEvidenceId: input.triggeringEvidenceId!, executedBy: "core",
        });
        w.commandLogHead = { seq: log.seq, hash: log.hash };
        added.push({ ...c, appended: { at, triggeringEvidenceId: input.triggeringEvidenceId!, logSeq: log.seq } });
      }
      w.checks = [...(w.checks ?? []), ...added];
      this.save(w);
      return { checks: w.checks, next_actions: added.map(nextActionFor) };
    });
  }

  /**
   * evaluate_check: the core judges pass/fail/inconclusive from verified evidence submitted for this check.
   * The input carries no verdict; the stored result can only be replaced by another core evaluation.
   */
  evaluateCheck(id: string, input: { checkId: string; evidenceIds: string[] }): Promise<CheckResult> {
    return this.withLock(id, async () => {
      const w = this.load(id);
      const check = (w.checks ?? []).find((c) => c.id === input.checkId);
      if (!check) throw new Error(`unknown check: ${input.checkId}`);
      const evidenceIds = [...new Set(input.evidenceIds ?? [])];
      this.verifyEvidence(w, "inferred", evidenceIds);
      const evs = evidenceIds.map((e) => w.evidence.find((x) => x.id === e)!);
      for (const ev of evs) if (ev.checkId !== check.id) throw new ClaimRejectedError(`evidence ${ev.id} was not captured for ${check.id}`);
      // Screenshots are for humans; blocked-request evidence is a security record, never page content.
      const judged = evs.filter((ev) => ev.type !== "screenshot" && ev.type !== "blocked");
      const texts = judged.map((ev) => readFileSync(join(this.dir(id), ev.path), "utf8"));
      const j = await this.registry.verifier(check.verify?.type ?? "rule").verify(check, texts);
      // Provenance rule: any piece of evidence that fails the expectation → fail, whoever executed it. If everything
      // satisfies it: ≥1 core-executed evidence that passes on its own → pass; agent-reported only → pass_needs_review.
      // (`count` aggregates across evidence, so it is judged on the combined texts only.)
      const per = check.expect.type === "count" || judged.length < 2 ? [] : await Promise.all(judged.map(async (ev, i) => ({ ev, j: await this.registry.verifier(check.verify?.type ?? "rule").verify(check, [texts[i]]) })));
      const failing = per.filter((x) => x.j.status === "fail");
      let status = j.status;
      let reasons = j.reasons;
      if (failing.length) {
        status = "fail";
        reasons = failing.map((x) => `${x.ev.id} (${x.ev.executedBy === "agent" ? "reported by agent" : "executed by walkthrough"}): ${x.j.reasons.join("; ")}`);
      } else if (status === "pass") {
        const coreOk = judged.length < 2 || check.expect.type === "count" ? judged.some((ev) => ev.executedBy !== "agent") : per.some((x) => x.ev.executedBy !== "agent" && x.j.status === "pass");
        if (!coreOk) {
          status = "pass_needs_review";
          reasons = [...j.reasons, "no evidence executed by walkthrough satisfies the expectation (agent-reported only): needs human review"];
        }
      }
      const result: CheckResult = { checkId: check.id, status, reasons, evidenceIds, at: this.ts() };
      w.checkResults = [...(w.checkResults ?? []).filter((r) => r.checkId !== check.id), result];
      this.save(w);
      return result;
    });
  }

  /** record_finding: symptom + repro + root_cause_chain. Observed steps need verified evidence; source refs must exist. */
  recordFinding(id: string, input: {
    title: string; severity: Severity; symptom: string; repro_steps?: string[]; root_cause_chain: RootCauseLink[]; check_id?: string;
  }): Promise<Finding> {
    return this.withLock(id, () => {
      if (!SEVERITIES.includes(input.severity)) throw new ClaimRejectedError(`invalid severity: ${input.severity}`);
      if (!input.title || !input.symptom) throw new ClaimRejectedError("title and symptom are required");
      const chain = input.root_cause_chain ?? [];
      if (!chain.length) throw new ClaimRejectedError("root_cause_chain needs at least one step");
      const w = this.load(id);
      if (input.check_id && !(w.checks ?? []).some((c) => c.id === input.check_id)) throw new ClaimRejectedError(`unknown check: ${input.check_id}`);
      for (const [i, l] of chain.entries()) {
        if (!l.claim) throw new ClaimRejectedError(`root_cause_chain[${i}]: claim is required`);
        if (l.kind !== "observed" && l.kind !== "inferred") throw new ClaimRejectedError(`root_cause_chain[${i}]: kind must be observed or inferred`);
        this.verifyEvidence(w, l.kind, l.evidence_ids ?? []);
        if (l.source_ref && !w.sources.some((s) => s.id === l.source_ref)) throw new ClaimRejectedError(`source link not found: ${l.source_ref}`);
      }
      w.findings ??= [];
      const finding: Finding = {
        id: `finding-${w.findings.length + 1}`, title: input.title, severity: input.severity, symptom: input.symptom,
        repro_steps: input.repro_steps ?? [],
        root_cause_chain: chain.map((l) => ({ claim: l.claim, kind: l.kind, evidence_ids: l.evidence_ids ?? [], ...(l.source_ref ? { source_ref: l.source_ref } : {}) })),
        evidenceIds: [...new Set(chain.flatMap((l) => l.evidence_ids ?? []))],
        kind: chain.every((l) => l.kind === "observed") ? "observed" : "inferred",
        ...(input.check_id ? { checkId: input.check_id } : {}),
      };
      w.findings.push(finding);
      this.save(w);
      return finding;
    });
  }

  /** sign_off: the human's single report-level decision. */
  signOff(id: string, input: { decision: string; comment?: string }): Promise<SignOff> {
    if (input.decision !== "accept" && input.decision !== "reject") return Promise.reject(new Error(`invalid sign-off: ${input.decision} (accept|reject)`));
    return this.withLock(id, async () => {
      // Open watches are auto-finalized with what was observed so far (documented in README); the report lists them.
      const open = this.listWatches(id).filter((s) => s.status !== "finalized");
      const auto: { watchId: string; outcome: string }[] = [];
      for (const s0 of open) {
        const s = await this.stopPoller(s0.id);
        const r = this.finalizeWatch(this.load(id), s, "sign_off");
        auto.push({ watchId: s.id, outcome: r.watch.outcome });
      }
      const w = this.load(id);
      w.signoff = { decision: input.decision as SignOff["decision"], ...(input.comment ? { comment: String(input.comment) } : {}), ...(auto.length ? { autoFinalizedWatches: auto } : {}) };
      this.save(w);
      return w.signoff;
    });
  }

  /**
   * import_mcp_result: store a result the agent got from another MCP server (connector:<name>) as agent-reported
   * evidence. Rejected: unknown connector, tool not in its read-only list, no correlation link, linked evidence missing /
   * tampered, or correlation key absent from either side. Params: credential keys dropped, URI userinfo stripped, redacted.
   */
  importMcpResult(id: string, input: ImportMcpInput): Promise<Evidence> {
    return this.withLock(id, async () => {
      const w = this.load(id);
      const c = (this.deps.mcpImports ?? MCP_IMPORT_PRESETS).find((x) => x.name === input.connector);
      if (!c) throw new ClaimRejectedError(`unknown MCP connector: ${input.connector}`);
      if (!c.tools.includes(input.tool)) throw new ClaimRejectedError(`tool ${input.connector}.${input.tool} is not in the read-only import list`);
      if (input.checkId !== undefined && !(w.checks ?? []).some((x) => x.id === input.checkId)) throw new ClaimRejectedError(`unknown check: ${input.checkId}`);
      if (input.result === undefined) throw new ClaimRejectedError("result is required");
      const links = input.links ?? [];
      if (!links.length) throw new ClaimRejectedError("imported evidence must link to earlier evidence (links: [{evidenceId, key}])");
      const raw = typeof input.result === "string" ? input.result : JSON.stringify(input.result, null, 2);
      this.verifyEvidence(w, "observed", links.map((l) => l.evidenceId));
      for (const l of links) {
        if (!l.key || String(l.key).length < 1) throw new ClaimRejectedError("link key is required");
        const ev = w.evidence.find((e) => e.id === l.evidenceId)!;
        if (!readFileSync(join(this.dir(id), ev.path), "utf8").includes(String(l.key))) throw new ClaimRejectedError(`unlinked: key "${l.key}" not found in ${l.evidenceId}`);
        if (!raw.includes(String(l.key))) throw new ClaimRejectedError(`unlinked: key "${l.key}" not found in the imported result`);
      }
      const params = sanitizeParams(input.params ?? {}, this.redactor);
      const out = await this.registry.action(`connector:${c.name}`).run({ type: `connector:${c.name}`, tool: input.tool, params, result: input.result } as never, { walkthrough: w, sandbox: undefined as never });
      const evId = `ev-${w.evidence.length + 1}`;
      const rel = `evidence/${evId}.json.txt`;
      writeFileSync(join(this.dir(id), rel), scrub(out.evidenceText, this.redactor));
      const ev: Evidence = {
        id: evId, type: "response", kind: "mcp_result", path: rel, executedBy: "agent",
        source: `connector:${c.name}`, mcpCall: { connector: c.name, server: c.server, tool: input.tool, params },
        links: links.map((l) => ({ evidenceId: l.evidenceId, key: scrub(String(l.key), this.redactor) })),
        ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts(),
      };
      w.evidence.push(ev);
      this.save(w);
      return ev;
    });
  }

  /** Read one line of a linked source file (inside root only), for showing the root cause inline. */
  sourceLine(file: string, line: number): string | undefined {
    const root = resolve(this.deps.root);
    const p = resolve(root, file);
    if (!p.startsWith(root + sep) || !existsSync(p)) return undefined;
    return readFileSync(p, "utf8").split("\n")[line - 1]?.trim();
  }

  /** Apply a downloaded review.json back into the walkthrough JSON. */
  importReview(review: unknown): Promise<{ id: string; applied: number }> {
    const r = review as {
      walkthroughId?: string; decisions?: { claimId: string; decision: string; note?: string }[]; signoff?: { decision?: string; comment?: string };
    };
    if (!r || typeof r.walkthroughId !== "string" || !(Array.isArray(r.decisions) || r.signoff)) return Promise.reject(new Error("invalid review file"));
    const decisions = r.decisions ?? [];
    const signoff = r.signoff;
    if (signoff && signoff.decision !== "accept" && signoff.decision !== "reject") return Promise.reject(new Error(`invalid sign-off: ${signoff.decision}`));
    return this.withLock(r.walkthroughId, () => {
    const w = this.load(r.walkthroughId as string);
    let applied = 0;
    for (const d of decisions) {
      const c = w.claims.find((x) => x.id === d.claimId);
      if (!c) throw new Error(`unknown claim in review: ${d.claimId}`);
      if (d.decision !== "agree" && d.decision !== "flag") throw new Error(`invalid decision: ${d.decision}`);
      c.review = { decision: d.decision, ...(d.note ? { note: String(d.note) } : {}) } as Review;
      applied++;
    }
    if (signoff) w.signoff = { decision: signoff.decision, ...(signoff.comment ? { comment: String(signoff.comment) } : {}) } as SignOff;
    this.save(w);
    return { id: w.id, applied };
    });
  }

  readEvidenceText(w: Walkthrough, ev: Evidence): string {
    return this.redactor.text(readFileSync(join(this.dir(w.id), ev.path), "utf8"));
  }

  redact(s: string): string { return this.redactor.text(s); }
}
