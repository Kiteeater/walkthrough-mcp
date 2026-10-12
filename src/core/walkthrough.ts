import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import type { Capturer } from "./capture.js";
import { Redactor } from "./redact.js";
import type { Sandbox } from "./sandbox.js";
import { hasMachineExpect, severityFor, traceStack } from "./checks.js";
import type { Registry } from "./registry.js";
import { defaultRegistry } from "./sources.js";
import type {
  Check, CheckResult, ObserveSpec, Finding, RootCause, Severity, SignOff,
  Claim, ClaimKind, Evidence, Review, RunRecord, SandboxConfig, SourceLink, Walkthrough,
} from "./types.js";

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
}

export const sha256File = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

export class WalkthroughCore {
  readonly base: string;
  private readonly redactor: Redactor;
  private readonly now: () => Date;
  readonly registry: Registry;
  private readonly locks = new Map<string, Promise<unknown>>();

  /** Per-id serial lock (promise-chain mutex) around read-modify-write of walkthrough.json. */
  private withLock<T>(id: string, fn: () => T | Promise<T>): Promise<T> {
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
    return this.withLock(id, async () => {
    const w = this.load(id);
    const sb = this.deps.sandboxFactory(w.sandbox, w.id);
    if (action === "exec" && !command) throw new Error("exec requires a command");
    const res = action === "up" ? await sb.up() : action === "down" ? await sb.down() : await sb.exec(command!);
    const rec: RunRecord = {
      id: `run-${w.runs.length + 1}`,
      command: this.redactor.text(action === "exec" ? command! : this.sandboxCommand(w, action)),
      exitCode: res.exitCode,
      output: this.redactor.text(res.output).slice(-20_000),
      createdAt: this.ts(),
    };
    w.runs.push(rec);
    this.save(w);
    return rec;
    });
  }

  captureEvidence(
    id: string, input: { type: "screenshot"; url: string } | { type: "logs"; service: string },
  ): Promise<Evidence> {
    return this.withLock(id, async () => {
    const w = this.load(id);
    const evId = `ev-${w.evidence.length + 1}`;
    let rel: string;
    let source: string;
    if (input.type === "screenshot") {
      rel = `evidence/${evId}.png`;
      source = this.redactor.text(input.url);
      await this.deps.capturer.screenshot(input.url, join(this.dir(id), rel));
    } else {
      rel = `evidence/${evId}.log`;
      source = w.sandbox.backend === "local" ? `local:${input.service}` : `docker:${input.service}`;
      const raw = await this.deps.sandboxFactory(w.sandbox, w.id).logs(input.service);
      writeFileSync(join(this.dir(id), rel), this.redactor.text(raw));
    }
    const ev: Evidence = {
      id: evId, type: input.type, path: rel,
      sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts(), source,
    };
    w.evidence.push(ev);
    this.save(w);
    return ev;
    });
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

  /** Store text (HTTP response, command output, log slice) as hashed evidence. */
  addTextEvidence(id: string, type: "logs" | "response", source: string, text: string): Promise<Evidence> {
    return this.withLock(id, () => {
      const w = this.load(id);
      const evId = `ev-${w.evidence.length + 1}`;
      const rel = `evidence/${evId}.${type === "logs" ? "log" : "txt"}`;
      writeFileSync(join(this.dir(id), rel), this.redactor.text(text));
      const ev: Evidence = { id: evId, type, path: rel, sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts(), source: this.redactor.text(source) };
      w.evidence.push(ev);
      this.save(w);
      return ev;
    });
  }

  /** plan_checks: the agent records the checks it will run for a goal (its own plan, or one from a planner). */
  planChecks(id: string, input: { goal: string; checks: Check[] }): Promise<Check[]> {
    return this.withLock(id, () => {
      const w = this.load(id);
      const ids = new Set<string>();
      for (const c of input.checks) {
        if (!c.id || ids.has(c.id)) throw new Error(`check ids must be unique and non-empty: ${c.id}`);
        if (!hasMachineExpect(c)) throw new Error(`check ${c.id}: expect must be machine-checkable (status, statusRange, bodyIncludes, exitCode or watch.alerts)`);
        if (!c.action || !this.registry.has("action", c.action.type)) throw new Error(`check ${c.id}: no action source "${c.action?.type}"`);
        for (const o of c.observe ?? []) if (!this.registry.has("observer", o.source)) throw new Error(`check ${c.id}: no observe source "${o.source}"`);
        if (c.verify && !this.registry.has("verifier", c.verify.type)) throw new Error(`check ${c.id}: verifier "${c.verify.type}" not available`);
        ids.add(c.id);
      }
      w.goal = input.goal;
      w.checks = input.checks;
      w.checkResults = [];
      this.save(w);
      return w.checks;
    });
  }

  /** run_checks: execute every planned check in the sandbox, capture evidence, auto-judge, and draft findings for failures. */
  async runChecks(id: string, opts: { settleMs?: number } = {}): Promise<CheckResult[]> {
    const w = this.load(id);
    const sb = this.deps.sandboxFactory(w.sandbox, w.id);
    const results: CheckResult[] = [];
    const ctx = { walkthrough: w, sandbox: sb };
    for (const check of w.checks ?? []) {
      const observe: ObserveSpec[] = [...(check.observe ?? []), ...(check.watch?.logs ?? []).map((service) => ({ source: "log" as const, service }))];
      const snaps: unknown[] = [];
      for (const o of observe) snaps.push(await this.registry.observer(o.source).snapshot(o, ctx));
      const out = await this.registry.action(check.action.type).run(check.action, ctx);
      await new Promise((r) => setTimeout(r, opts.settleMs ?? 200));
      const evidenceIds = [(await this.addTextEvidence(id, "response", check.name, out.evidenceText)).id];
      const data = { status: out.status, exitCode: out.exitCode, body: out.body, logs: "" };
      let logEvidenceId: string | undefined;
      for (const [i, o] of observe.entries()) {
        const c = await this.registry.observer(o.source).collect(o, ctx, snaps[i]);
        const ev = await this.addTextEvidence(id, c.evidenceType, `${c.label} (during ${check.id})`, c.text);
        evidenceIds.push(ev.id);
        if (c.evidenceType === "logs") { data.logs += c.text; logEvidenceId ??= ev.id; }
      }
      const a = data;
      const repro = out.repro;
      const reasons = await this.registry.verifier(check.verify?.type ?? "rule").verify(check, data);
      const result: CheckResult = {
        checkId: check.id, status: reasons.length ? "fail" : "pass", reasons,
        actual: { status: a.status, exitCode: a.exitCode }, evidenceIds, at: this.ts(),
      };
      if (reasons.length) {
        const hit = traceStack(a.logs, w.sandbox.cwd, this.deps.root);
        const rootCause: RootCause = { logEvidenceId: hit || a.logs.trim() ? logEvidenceId : undefined };
        if (hit) {
          rootCause.sourceId = (await this.linkSource(id, { file: hit.file, line: hit.line, note: hit.message })).id;
          rootCause.summary = hit.message;
        }
        const finding = await this.recordFinding(id, {
          title: `${check.name} — ${reasons[0]}`,
          severity: severityFor(a, reasons),
          whatHappened: `${check.name} failed: ${reasons.join("; ")}.${hit ? ` Logs show "${hit.message}" at ${hit.file}:${hit.line}.` : ""}`,
          repro: [`Start the sandbox: ${w.sandbox.backend === "local" ? (w.sandbox.local?.up ?? w.sandbox.up) : w.sandbox.up}`, repro],
          rootCause, evidenceIds, kind: "observed", draft: true, checkId: check.id,
        });
        result.findingId = finding.id;
      }
      results.push(result);
    }
    await this.withLock(id, () => {
      const cur = this.load(id);
      cur.checkResults = results;
      this.save(cur);
    });
    return results;
  }

  /** record_finding: observed findings need valid evidence; root-cause references are verified too. */
  recordFinding(id: string, input: {
    title: string; severity: Severity; whatHappened: string; repro?: string[]; rootCause?: RootCause;
    evidenceIds?: string[]; kind: ClaimKind; draft?: boolean; checkId?: string;
  }): Promise<Finding> {
    return this.withLock(id, () => {
      if (!["critical", "high", "medium", "low"].includes(input.severity)) throw new ClaimRejectedError(`invalid severity: ${input.severity}`);
      if (input.kind !== "observed" && input.kind !== "inferred") throw new ClaimRejectedError("kind must be observed or inferred");
      const w = this.load(id);
      const evidenceIds = input.evidenceIds ?? [];
      this.verifyEvidence(w, input.kind, evidenceIds);
      const rc = input.rootCause;
      if (rc?.logEvidenceId) {
        this.verifyEvidence(w, "observed", [rc.logEvidenceId]);
        if (w.evidence.find((e) => e.id === rc.logEvidenceId)?.type !== "logs") throw new ClaimRejectedError(`root cause evidence is not logs: ${rc.logEvidenceId}`);
      }
      if (rc?.sourceId && !w.sources.some((s) => s.id === rc.sourceId)) throw new ClaimRejectedError(`source link not found: ${rc.sourceId}`);
      w.findings ??= [];
      const finding: Finding = {
        id: `finding-${w.findings.length + 1}`, title: input.title, severity: input.severity, whatHappened: input.whatHappened,
        repro: input.repro ?? [], rootCause: rc, evidenceIds, kind: input.kind,
        ...(input.draft ? { draft: true } : {}), ...(input.checkId ? { checkId: input.checkId } : {}),
      };
      w.findings.push(finding);
      this.save(w);
      return finding;
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
    if (signoff && signoff.decision !== "approve" && signoff.decision !== "reject") return Promise.reject(new Error(`invalid sign-off: ${signoff.decision}`));
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
