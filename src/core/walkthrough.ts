import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Capturer } from "./capture.js";
import { Redactor } from "./redact.js";
import type { Sandbox } from "./sandbox.js";
import type {
  Claim, ClaimKind, Evidence, Review, RunRecord, SandboxConfig, SourceLink, Walkthrough,
} from "./types.js";

export class ClaimRejectedError extends Error {
  constructor(message: string) { super(message); this.name = "ClaimRejectedError"; }
}

export interface CoreDeps {
  /** Root directory that holds `.walkthrough/`. */
  root: string;
  sandboxFactory: (cfg: SandboxConfig) => Sandbox;
  capturer: Capturer;
  redactor?: Redactor;
  now?: () => Date;
}

export const sha256File = (p: string) => createHash("sha256").update(readFileSync(p)).digest("hex");

export class WalkthroughCore {
  readonly base: string;
  private readonly redactor: Redactor;
  private readonly now: () => Date;

  constructor(private readonly deps: CoreDeps) {
    this.base = resolve(deps.root, ".walkthrough");
    this.redactor = deps.redactor ?? Redactor.fromEnv();
    this.now = deps.now ?? (() => new Date());
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

  async runInSandbox(id: string, action: "up" | "down" | "exec", command?: string): Promise<RunRecord> {
    const w = this.load(id);
    const sb = this.deps.sandboxFactory(w.sandbox);
    if (action === "exec" && !command) throw new Error("exec requires a command");
    const res = action === "up" ? await sb.up() : action === "down" ? await sb.down() : await sb.exec(command!);
    const rec: RunRecord = {
      id: `run-${w.runs.length + 1}`,
      command: this.redactor.text(action === "exec" ? command! : action === "up" ? w.sandbox.up : w.sandbox.down),
      exitCode: res.exitCode,
      output: this.redactor.text(res.output).slice(-20_000),
      createdAt: this.ts(),
    };
    w.runs.push(rec);
    this.save(w);
    return rec;
  }

  async captureEvidence(
    id: string, input: { type: "screenshot"; url: string } | { type: "logs"; service: string },
  ): Promise<Evidence> {
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
      source = `docker:${input.service}`;
      const raw = await this.deps.sandboxFactory(w.sandbox).logs(input.service);
      writeFileSync(join(this.dir(id), rel), this.redactor.text(raw));
    }
    const ev: Evidence = {
      id: evId, type: input.type, path: rel,
      sha256: sha256File(join(this.dir(id), rel)), createdAt: this.ts(), source,
    };
    w.evidence.push(ev);
    this.save(w);
    return ev;
  }

  linkSource(id: string, input: { file: string; line: number; note?: string }): SourceLink {
    if (!Number.isInteger(input.line) || input.line < 1) throw new Error("line must be a positive integer");
    const w = this.load(id);
    const link: SourceLink = { id: `src-${w.sources.length + 1}`, file: input.file, line: input.line, note: input.note };
    w.sources.push(link);
    this.save(w);
    return link;
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
  }): Claim {
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
  }

  /** Apply a downloaded review.json back into the walkthrough JSON. */
  importReview(review: unknown): { id: string; applied: number } {
    const r = review as { walkthroughId?: string; decisions?: { claimId: string; decision: string; note?: string }[] };
    if (!r || typeof r.walkthroughId !== "string" || !Array.isArray(r.decisions)) throw new Error("invalid review file");
    const w = this.load(r.walkthroughId);
    let applied = 0;
    for (const d of r.decisions) {
      const c = w.claims.find((x) => x.id === d.claimId);
      if (!c) throw new Error(`unknown claim in review: ${d.claimId}`);
      if (d.decision !== "agree" && d.decision !== "flag") throw new Error(`invalid decision: ${d.decision}`);
      c.review = { decision: d.decision, ...(d.note ? { note: String(d.note) } : {}) } as Review;
      applied++;
    }
    this.save(w);
    return { id: w.id, applied };
  }

  readEvidenceText(w: Walkthrough, ev: Evidence): string {
    return this.redactor.text(readFileSync(join(this.dir(w.id), ev.path), "utf8"));
  }

  redact(s: string): string { return this.redactor.text(s); }
}
