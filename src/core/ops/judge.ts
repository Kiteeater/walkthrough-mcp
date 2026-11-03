// Judging ops moved from WalkthroughCore (ops/ split step 9). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { matcherProblem } from "../alerts.js";
import { expectProblem } from "../checks.js";
import { CHECK_METHODS, isOneOf, SEVERITIES } from "../domain/enums.js";
import { ClaimRejectedError } from "../errors.js";
import { sha256File } from "../hash.js";
import type { Registry } from "../registry.js";
import { appendLogEntry } from "../runcli.js";
import type { Check, CheckResult, Claim, ClaimKind, Finding, RootCauseLink, Severity, SourceLink, Walkthrough } from "../types.js";
import type { CoreDeps } from "../walkthrough.js";
import { nextActionFor, type NextAction } from "./next-action.js";

/** Narrow view of WalkthroughCore: only the members the judging ops touch. */
export interface JudgeCore {
  readonly deps: Pick<CoreDeps, "root">;
  readonly registry: Registry;
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  dir(id: string): string;
  ts(): string;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  verifyEvidence(w: Walkthrough, kind: ClaimKind, evidenceIds: string[]): void;
}

const METHODS = CHECK_METHODS;

export function linkSource(core: JudgeCore, id: string, input: { file: string; line: number; note?: string }): Promise<SourceLink> {
  return core.withLock(id, () => {
  if (!Number.isInteger(input.line) || input.line < 1) throw new Error("line must be a positive integer");
  const w = core.load(id);
  const link: SourceLink = { id: `src-${w.sources.length + 1}`, file: input.file, line: input.line, note: input.note };
  w.sources.push(link);
  core.save(w);
  return link;
  });
}

export function verifyEvidence(core: JudgeCore, w: Walkthrough, kind: ClaimKind, evidenceIds: string[]): void {
  if (kind === "observed" && evidenceIds.length === 0) {
    throw new ClaimRejectedError("observed claim must reference at least one evidence id");
  }
  for (const evId of evidenceIds) {
    const ev = w.evidence.find((e) => e.id === evId);
    if (!ev) throw new ClaimRejectedError(`evidence not found: ${evId}`);
    const file = join(core.dir(w.id), ev.path);
    if (!existsSync(file)) throw new ClaimRejectedError(`evidence file missing: ${evId}`);
    if (sha256File(file) !== ev.sha256) throw new ClaimRejectedError(`evidence hash mismatch: ${evId}`);
  }
}

export function recordClaim(core: JudgeCore, id: string, input: {
  question: string; conclusion: string; kind: ClaimKind; evidenceIds?: string[]; sourceIds?: string[];
}): Promise<Claim> {
  return core.withLock(id, () => {
  if (input.kind !== "observed" && input.kind !== "inferred") throw new ClaimRejectedError("kind must be observed or inferred");
  const w = core.load(id);
  const evidenceIds = input.evidenceIds ?? [];
  const sourceIds = input.sourceIds ?? [];
  core.verifyEvidence(w, input.kind, evidenceIds);
  for (const s of sourceIds) if (!w.sources.some((x) => x.id === s)) throw new ClaimRejectedError(`source link not found: ${s}`);
  const claim: Claim = {
    id: `claim-${w.claims.length + 1}`, question: input.question, conclusion: input.conclusion,
    kind: input.kind, evidenceIds, sourceIds,
  };
  w.claims.push(claim);
  core.save(w);
  return claim;
  });
}

export function planChecks(core: JudgeCore, id: string, input: { goal: string; checks: Check[]; append?: boolean; triggeringEvidenceId?: string }): Promise<{ checks: Check[]; next_actions: NextAction[] }> {
  return core.withLock(id, () => {
    const w = core.load(id);
    // append = follow-up checks discovered mid-run (e.g. while tracing a 500). Append-only: existing checks and
    // verdicts can't be changed or removed; each appended check is written to the hash-chained command log.
    const existing = new Map((input.append ? w.checks ?? [] : []).map((c) => [c.id, c]));
    if (input.append) {
      if (!input.triggeringEvidenceId) throw new ClaimRejectedError("append requires triggeringEvidenceId (the evidence that made you add these checks)");
      core.verifyEvidence(w, "observed", [input.triggeringEvidenceId]);
    }
    const ids = new Set<string>(existing.keys());
    for (const c of input.checks) {
      const prev = existing.get(c.id);
      if (prev) throw new ClaimRejectedError(`append-only: check ${c.id} already exists${JSON.stringify(prev.expect) !== JSON.stringify(c.expect) ? " (changing its expect is not allowed)" : ""}`);
      if (!c.id || ids.has(c.id)) throw new Error(`check ids must be unique and non-empty: ${c.id}`);
      const problem = expectProblem(c.expect);
      if (problem) throw new Error(`check ${c.id}: expect is not machine-checkable (${problem})`);
      if (!isOneOf(METHODS, c.method)) throw new Error(`check ${c.id}: method must be one of ${METHODS.join("|")}`);
      if (!c.intent || !c.target) throw new Error(`check ${c.id}: intent and target are required`);
      if (!isOneOf(SEVERITIES, c.severity_if_fail)) throw new Error(`check ${c.id}: severity_if_fail must be one of ${SEVERITIES.join("|")}`);
      if (c.verify && !core.registry.has("verifier", c.verify.type)) throw new Error(`check ${c.id}: verifier "${c.verify.type}" not available`);
      for (const mm of c.alertMatchers ?? []) { const p = matcherProblem(mm); if (p) throw new Error(`check ${c.id}: ${p}`); }
      ids.add(c.id);
    }
    if (!input.append) {
      w.goal = input.goal;
      w.checks = input.checks.map(({ appended: _a, ...c }) => c as Check);
      w.checkResults = [];
      core.save(w);
      return { checks: w.checks, next_actions: w.checks.map(nextActionFor) };
    }
    const added: Check[] = [];
    for (const raw of input.checks) {
      const { appended: _a, ...c } = raw;
      const at = core.ts();
      const log = appendLogEntry(join(core.dir(id), "commands.jsonl"), {
        ts: at, walkthroughId: id, type: "plan_append", checkId: c.id,
        checkSha256: createHash("sha256").update(JSON.stringify(c)).digest("hex"), triggeringEvidenceId: input.triggeringEvidenceId!, executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
      added.push({ ...c, appended: { at, triggeringEvidenceId: input.triggeringEvidenceId!, logSeq: log.seq } });
    }
    w.checks = [...(w.checks ?? []), ...added];
    core.save(w);
    return { checks: w.checks, next_actions: added.map(nextActionFor) };
  });
}

export function evaluateCheck(core: JudgeCore, id: string, input: { checkId: string; evidenceIds: string[] }): Promise<CheckResult> {
  return core.withLock(id, async () => {
    const w = core.load(id);
    const check = (w.checks ?? []).find((c) => c.id === input.checkId);
    if (!check) throw new Error(`unknown check: ${input.checkId}`);
    const evidenceIds = [...new Set(input.evidenceIds ?? [])];
    core.verifyEvidence(w, "inferred", evidenceIds);
    const evs = evidenceIds.map((e) => w.evidence.find((x) => x.id === e)!);
    for (const ev of evs) if (ev.checkId !== check.id) throw new ClaimRejectedError(`evidence ${ev.id} was not captured for ${check.id}`);
    // Screenshots are for humans; blocked-request evidence is a security record, never page content.
    const judged = evs.filter((ev) => ev.type !== "screenshot" && ev.type !== "blocked");
    const texts = judged.map((ev) => readFileSync(join(core.dir(id), ev.path), "utf8"));
    const j = await core.registry.verifier(check.verify?.type ?? "rule").verify(check, texts);
    // Provenance rule: any piece of evidence that fails the expectation → fail, whoever executed it. If everything
    // satisfies it: ≥1 core-executed evidence that passes on its own → pass; agent-reported only → pass_needs_review.
    // (`count` aggregates across evidence, so it is judged on the combined texts only.)
    const per = check.expect.type === "count" || judged.length < 2 ? [] : await Promise.all(judged.map(async (ev, i) => ({ ev, j: await core.registry.verifier(check.verify?.type ?? "rule").verify(check, [texts[i]]) })));
    const failing = per.filter((x) => x.j.status === "fail");
    let status = j.status;
    let reasons = j.reasons;
    if (failing.length) {
      status = "fail";
      reasons = failing.map((x) => `${x.ev.id} (${x.ev.executedBy === "agent" ? "agent 自报" : "walkthrough 执行"}): ${x.j.reasons.join("; ")}`);
    } else if (status === "pass") {
      const coreOk = judged.length < 2 || check.expect.type === "count" ? judged.some((ev) => ev.executedBy !== "agent") : per.some((x) => x.ev.executedBy !== "agent" && x.j.status === "pass");
      if (!coreOk) {
        status = "pass_needs_review";
        reasons = [...j.reasons, "没有 walkthrough 执行的证据满足期望（仅 agent 自报）：需人工复核"];
      }
    }
    const result: CheckResult = { checkId: check.id, status, reasons, evidenceIds, at: core.ts() };
    w.checkResults = [...(w.checkResults ?? []).filter((r) => r.checkId !== check.id), result];
    core.save(w);
    return result;
  });
}

export function recordFinding(core: JudgeCore, id: string, input: {
  title: string; severity: Severity; symptom: string; repro_steps?: string[]; root_cause_chain: RootCauseLink[]; check_id?: string;
  ruled_out?: { claim: string; check_id?: string; evidence_ids: string[] }[];
  inconclusive?: { claim: string; reason: string; check_id?: string; evidence_ids: string[] }[];
}): Promise<Finding> {
  return core.withLock(id, () => {
    if (!isOneOf(SEVERITIES, input.severity)) throw new ClaimRejectedError(`invalid severity: ${input.severity}`);
    if (!input.title || !input.symptom) throw new ClaimRejectedError("title and symptom are required");
    const chain = input.root_cause_chain ?? [];
    if (!chain.length) throw new ClaimRejectedError("root_cause_chain needs at least one step");
    const w = core.load(id);
    if (input.check_id && !(w.checks ?? []).some((c) => c.id === input.check_id)) throw new ClaimRejectedError(`unknown check: ${input.check_id}`);
    for (const [i, l] of chain.entries()) {
      if (!l.claim) throw new ClaimRejectedError(`root_cause_chain[${i}]: claim is required`);
      if (l.kind !== "observed" && l.kind !== "inferred") throw new ClaimRejectedError(`root_cause_chain[${i}]: kind must be observed or inferred`);
      core.verifyEvidence(w, l.kind, l.evidence_ids ?? []);
      if (l.source_ref && !w.sources.some((s) => s.id === l.source_ref)) throw new ClaimRejectedError(`source link not found: ${l.source_ref}`);
    }
    for (const [i, r] of (input.ruled_out ?? []).entries()) {
      if (!r.claim) throw new ClaimRejectedError(`ruled_out[${i}]: claim is required`);
      if (!r.evidence_ids?.length) throw new ClaimRejectedError(`ruled_out[${i}]: needs evidence`);
      core.verifyEvidence(w, "observed", r.evidence_ids);
      // An exclusion is only as good as a passing check (#31): the cited check's latest verdict must be pass and the
      // cited evidence must be what that verdict was judged on. Anything else belongs in `inconclusive`.
      const hint = "put it in inconclusive (未下结论) with a reason instead";
      if (!r.check_id) throw new ClaimRejectedError(`ruled_out[${i}]: check_id is required (an exclusion must cite a passing check); ${hint}`);
      if (!(w.checks ?? []).some((c) => c.id === r.check_id)) throw new ClaimRejectedError(`ruled_out[${i}]: unknown check: ${r.check_id}`);
      const verdict = (w.checkResults ?? []).find((x) => x.checkId === r.check_id);
      if (!verdict) throw new ClaimRejectedError(`ruled_out[${i}]: check ${r.check_id} has not been evaluated; ${hint}`);
      if (verdict.status !== "pass") throw new ClaimRejectedError(`ruled_out[${i}]: check ${r.check_id} latest verdict is ${verdict.status}, not pass; ${hint}`);
      const unused = r.evidence_ids.filter((e) => !verdict.evidenceIds.includes(e));
      if (unused.length) throw new ClaimRejectedError(`ruled_out[${i}]: evidence ${unused.join(", ")} was not used by check ${r.check_id}'s latest verdict; ${hint}`);
    }
    for (const [i, r] of (input.inconclusive ?? []).entries()) {
      if (!r.claim || !r.reason) throw new ClaimRejectedError(`inconclusive[${i}]: claim and reason are required`);
      core.verifyEvidence(w, "observed", r.evidence_ids ?? []);
      if (r.check_id && !(w.checks ?? []).some((c) => c.id === r.check_id)) throw new ClaimRejectedError(`inconclusive[${i}]: unknown check: ${r.check_id}`);
    }
    w.findings ??= [];
    const finding: Finding = {
      id: `finding-${w.findings.length + 1}`, title: input.title, severity: input.severity, symptom: input.symptom,
      repro_steps: input.repro_steps ?? [],
      root_cause_chain: chain.map((l) => ({ claim: l.claim, kind: l.kind, evidence_ids: l.evidence_ids ?? [], ...(l.source_ref ? { source_ref: l.source_ref } : {}) })),
      evidenceIds: [...new Set(chain.flatMap((l) => l.evidence_ids ?? []))],
      kind: chain.every((l) => l.kind === "observed") ? "observed" : "inferred",
      ...(input.check_id ? { checkId: input.check_id } : {}),
      ...(input.inconclusive?.length ? { inconclusive: input.inconclusive.map((r) => ({ claim: r.claim, reason: r.reason, evidence_ids: r.evidence_ids ?? [], ...(r.check_id ? { check_id: r.check_id } : {}) })) } : {}),
      ...(input.ruled_out?.length ? { ruled_out: input.ruled_out.map((r) => ({ claim: r.claim, evidence_ids: r.evidence_ids, ...(r.check_id ? { check_id: r.check_id } : {}) })) } : {}),
    };
    w.findings.push(finding);
    core.save(w);
    return finding;
  });
}

export function sourceLine(core: JudgeCore, file: string, line: number): string | undefined {
  const root = resolve(core.deps.root);
  const p = resolve(root, file);
  if (!p.startsWith(root + sep) || !existsSync(p)) return undefined;
  return readFileSync(p, "utf8").split("\n")[line - 1]?.trim();
}
