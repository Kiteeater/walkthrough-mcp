import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import type { Capturer } from "./capture.js";
import { Redactor } from "./redact.js";
import type { Sandbox } from "./sandbox.js";
import { expectProblem } from "./checks.js";
import type { Registry } from "./registry.js";
import { defaultRegistry } from "./sources.js";
import type {
  Check, CheckResult, EvidenceKind, Finding, RootCauseLink, Severity, SignOff,
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

export class WalkthroughCore {
  readonly base: string;
  private readonly redactor: Redactor;
  private readonly now: () => Date;
  readonly registry: Registry;
  private readonly locks = new Map<string, Promise<unknown>>();
  /** Last raw log text seen per walkthrough+service, for `delta` log captures. */
  private readonly logMarks = new Map<string, string>();

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
      if (input.content === undefined && !(binary && input.path)) throw new Error(input.path ? "path is only accepted for screenshot/har; send text as content" : "content is required");
      const ext = input.kind === "screenshot" ? "png" : input.kind === "har" ? "har" : input.kind === "log" ? "log" : "txt";
      const s = input.source;
      ev = {
        id: evId, type: input.kind === "screenshot" ? "screenshot" : input.kind === "log" ? "logs" : "response", kind: input.kind,
        path: `evidence/${evId}.${ext}`, executedBy: "agent",
        source: this.redactor.text(`agent:${s.tool}${s.server ? `@${s.server}` : ""}${s.command ? ` ${s.command}` : ""}`),
      };
      if (input.content !== undefined) writeFileSync(abs(ev.path), input.kind === "screenshot" ? Buffer.from(input.content, "base64") : this.redactor.text(input.content));
      else writeFileSync(abs(ev.path), input.kind === "har" ? this.redactor.text(readFileSync(input.path!, "utf8")) : readFileSync(input.path!));
    }
    const full: Evidence = { ...ev, ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha256File(abs(ev.path)), createdAt: this.ts() };
    w.evidence.push(full);
    this.save(w);
    return full;
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

  /** plan_checks: record the agent's plan. Every check needs a machine-checkable expect; returns next_actions. */
  planChecks(id: string, input: { goal: string; checks: Check[] }): Promise<{ checks: Check[]; next_actions: NextAction[] }> {
    return this.withLock(id, () => {
      const w = this.load(id);
      const ids = new Set<string>();
      for (const c of input.checks) {
        if (!c.id || ids.has(c.id)) throw new Error(`check ids must be unique and non-empty: ${c.id}`);
        const problem = expectProblem(c.expect);
        if (problem) throw new Error(`check ${c.id}: expect is not machine-checkable (${problem})`);
        if (!METHODS.includes(c.method)) throw new Error(`check ${c.id}: method must be one of ${METHODS.join("|")}`);
        if (!c.intent || !c.target) throw new Error(`check ${c.id}: intent and target are required`);
        if (!SEVERITIES.includes(c.severity_if_fail)) throw new Error(`check ${c.id}: severity_if_fail must be one of ${SEVERITIES.join("|")}`);
        if (c.verify && !this.registry.has("verifier", c.verify.type)) throw new Error(`check ${c.id}: verifier "${c.verify.type}" not available`);
        ids.add(c.id);
      }
      w.goal = input.goal;
      w.checks = input.checks;
      w.checkResults = [];
      this.save(w);
      return { checks: w.checks, next_actions: w.checks.map(nextActionFor) };
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
      const texts = evs.filter((ev) => ev.type !== "screenshot").map((ev) => readFileSync(join(this.dir(id), ev.path), "utf8"));
      const j = await this.registry.verifier(check.verify?.type ?? "rule").verify(check, texts);
      const result: CheckResult = { checkId: check.id, status: j.status, reasons: j.reasons, evidenceIds, at: this.ts() };
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
    return this.withLock(id, () => {
      const w = this.load(id);
      w.signoff = { decision: input.decision as SignOff["decision"], ...(input.comment ? { comment: String(input.comment) } : {}) };
      this.save(w);
      return w.signoff;
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
