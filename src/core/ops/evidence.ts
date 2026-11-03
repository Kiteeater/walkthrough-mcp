// Evidence ops moved from WalkthroughCore (ops/ split step 5). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import type { NavigationGuard, PageCapture } from "../capture.js";
import { isOneOf, SUBMITTABLE_EVIDENCE_KINDS } from "../domain/enums.js";
import { ReplayRejectedError } from "../egress/policy.js";
import { ClaimRejectedError } from "../errors.js";
import { HAR_MAX_BYTES, SCREENSHOT_MAX_BYTES, redactHar, redactUrl, redactUrlsIn } from "../har.js";
import { sha256File } from "../hash.js";
import { MCP_IMPORT_PRESETS, sanitizeParams, scrub } from "../imports.js";
import type { Redactor } from "../redact.js";
import type { Registry } from "../registry.js";
import type { ReplayConfig } from "../replay.js";
import { appendLogEntry } from "../runcli.js";
import type { ClaimKind, Evidence, Walkthrough } from "../types.js";
import type { CoreDeps, ImportMcpInput } from "../walkthrough.js";
import { blockedUrlSecrets, maskAllQuery } from "./capture-urls.js";
import type { SubmittedEvidence } from "./next-action.js";

/** Narrow view of WalkthroughCore: only the members the evidence ops touch. */
export interface EvidenceCore {
  readonly base: string;
  readonly deps: Pick<CoreDeps, "replay" | "sandboxFactory" | "root" | "mcpImports">;
  readonly redactor: Redactor;
  readonly registry: Registry;
  readonly logMarks: Map<string, string>;
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  dir(id: string): string;
  ts(): string;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  guardedPage(cfg: ReplayConfig, url: string, storageState?: NavigationGuard["storageState"]): Promise<PageCapture>;
  verifyEvidence(w: Walkthrough, kind: ClaimKind, evidenceIds: string[]): void;
  captureEvidenceWith(id: string, input: { type: "screenshot"; url: string; checkId?: string } | { type: "logs"; service: string; checkId?: string; delta?: boolean } | SubmittedEvidence, policy?: ReplayConfig): Promise<Evidence>;
  agentFile(p: string, kind: "har" | "screenshot"): string;
}

const KINDS = SUBMITTABLE_EVIDENCE_KINDS;

export function captureEvidence(
  core: EvidenceCore,
  id: string,
  input: { type: "screenshot"; url: string; checkId?: string } | { type: "logs"; service: string; checkId?: string; delta?: boolean } | SubmittedEvidence,
): Promise<Evidence> {
  return core.captureEvidenceWith(id, input);
}

export function captureEvidenceWith(
  core: EvidenceCore,
  id: string,
  input: { type: "screenshot"; url: string; checkId?: string } | { type: "logs"; service: string; checkId?: string; delta?: boolean } | SubmittedEvidence,
  policy?: ReplayConfig,
): Promise<Evidence> {
  return core.withLock(id, async () => {
  const w = core.load(id);
  if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
  const evId = `ev-${w.evidence.length + 1}`;
  const abs = (rel: string) => join(core.dir(id), rel);
  let ev: Omit<Evidence, "sha256" | "createdAt">;
  if (input.type === "screenshot") {
    ev = { id: evId, type: "screenshot", kind: "screenshot", path: `evidence/${evId}.png`, source: core.redactor.text(input.url), executedBy: "core" };
    // B1: same guarded browser path as capture_page (core blocklist, allowHosts + IP rules, pinned DNS, every redirect
    // hop re-checked, read-only methods); only the screenshot is kept. No login state is loaded for this path.
    const cfg = policy ?? core.deps.replay;
    if (!cfg || !cfg.allowHosts?.length) throw new ReplayRejectedError("screenshot capture needs replay.allowHosts (same policy as capture_page)");
    const p = await core.guardedPage(cfg, input.url);
    writeFileSync(abs(ev.path), p.screenshot);
    // Always logged like capture_page (blocked requests included, redacted). If the log write fails, the PNG is
    // removed again so no unregistered evidence file is left behind.
    try {
      const blocked = p.blocked ?? [];
      const r = core.redactor.with(blockedUrlSecrets(blocked.map((b) => b.url)));
      const log = appendLogEntry(join(core.dir(id), "commands.jsonl"), {
        ts: core.ts(), walkthroughId: id, type: "capture_screenshot", ...(input.checkId ? { checkId: input.checkId } : {}), evidenceIds: [evId],
        navigations: p.navigations.map((n) => ({ ...n, url: maskAllQuery(redactUrl(n.url, r)) })),
        blocked: blocked.slice(0, 500).map((b) => ({ url: maskAllQuery(redactUrl(b.url, r)), method: b.method, type: b.type, reason: r.text(redactUrlsIn(b.reason, r)) })),
        blockedCount: blocked.length, executedBy: "core",
      });
      w.commandLogHead = { seq: log.seq, hash: log.hash };
    } catch (e) {
      // Keep the original log error even if cleanup fails too: both are reported, the log error first (and as cause).
      try { rmSync(abs(ev.path), { force: true }); } catch (rmErr) {
        throw new AggregateError([e, rmErr], `command log write failed and the screenshot ${ev.path} could not be removed`, { cause: e });
      }
      throw e;
    }
  } else if (input.type === "logs") {
    ev = { id: evId, type: "logs", kind: "log", path: `evidence/${evId}.log`, source: `${w.sandbox.backend === "local" ? "local" : "docker"}:${input.service}`, executedBy: "core" };
    const raw = await core.deps.sandboxFactory(w.sandbox, w.id).logs(input.service);
    const key = `${id}\0${input.service}`;
    // Keep a compact cursor in the manifest as well as the process-local full mark. A
    // restart must still produce a true delta, without copying the entire (possibly
    // secret-bearing) log into walkthrough.json.
    type LogCursor = { length: number; prefixSha256: string };
    const persisted = w as Walkthrough & { logCursors?: Record<string, LogCursor | string> };
    const memoryPrev = core.logMarks.get(key);
    const cursor = persisted.logCursors?.[input.service];
    const cursorLength = typeof cursor === "string" ? cursor.length : cursor?.length;
    const cursorHash = typeof cursor === "string" ? createHash("sha256").update(cursor).digest("hex") : cursor?.prefixSha256;
    const hasPersistedPrefix = input.delta && cursorLength !== undefined && cursorHash !== undefined && raw.length >= cursorLength &&
      createHash("sha256").update(raw.slice(0, cursorLength)).digest("hex") === cursorHash;
    core.logMarks.set(key, raw);
    persisted.logCursors ??= {};
    persisted.logCursors[input.service] = { length: raw.length, prefixSha256: createHash("sha256").update(raw).digest("hex") };
    // Stack traces carry absolute host paths; under the walkthrough root they are written repo-relative.
    const rootPrefix = resolve(core.deps.root) + sep;
    const delta = input.delta
      ? memoryPrev !== undefined && raw.startsWith(memoryPrev) ? raw.slice(memoryPrev.length)
        : hasPersistedPrefix ? raw.slice(cursorLength!) : raw
      : raw;
    writeFileSync(abs(ev.path), core.redactor.text(delta).split(rootPrefix).join(""));
  } else {
    if (!isOneOf(KINDS, input.kind)) throw new Error(`invalid evidence kind: ${input.kind}`);
    if (!input.source?.tool) throw new Error("source.tool is required");
    const binary = input.kind === "screenshot" || input.kind === "har";
    if (binary && input.path && input.content === undefined) input = { ...input, path: core.agentFile(input.path, input.kind as "har" | "screenshot") };
    if (input.content === undefined && !(binary && input.path)) throw new Error(input.path ? "path is only accepted for screenshot/har; send text as content" : "content is required");
    const ext = input.kind === "screenshot" ? "png" : input.kind === "har" ? "har" : input.kind === "log" ? "log" : "txt";
    const s = input.source;
    ev = {
      id: evId, type: input.kind === "screenshot" ? "screenshot" : input.kind === "log" ? "logs" : "response", kind: input.kind,
      path: `evidence/${evId}.${ext}`, executedBy: "agent",
      source: core.redactor.text(`agent:${s.tool}${s.server ? `@${s.server}` : ""}${s.command ? ` ${s.command}` : ""}`),
    };
    if (input.kind === "har") ev.type = "har";
    const cap = input.kind === "screenshot" ? SCREENSHOT_MAX_BYTES : HAR_MAX_BYTES;
    const raw: Buffer = input.content !== undefined ? (input.kind === "screenshot" ? Buffer.from(input.content, "base64") : Buffer.from(input.content, "utf8")) : readFileSync(input.path!);
    if (raw.length > cap) throw new ClaimRejectedError(`${input.kind} too large: ${raw.length} bytes > ${cap}`);
    writeFileSync(abs(ev.path), input.kind === "screenshot" ? raw : input.kind === "har" ? redactHar(raw.toString("utf8"), core.redactor) : core.redactor.text(raw.toString("utf8")));
  }
  const full: Evidence = { ...ev, ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha256File(abs(ev.path)), createdAt: core.ts() };
  w.evidence.push(full);
  core.save(w);
  return full;
  });
}

/**
 * A screenshot/HAR file the agent hands over by path must live under `.walkthrough/` (after realpath, so a symlink
 * can't point outside) and stay under the size cap. Returns the resolved path.
 */
export function agentFile(core: EvidenceCore, p: string, kind: "har" | "screenshot"): string {
  let real: string;
  try { real = realpathSync(resolve(core.deps.root, p)); } catch { throw new ClaimRejectedError(`${kind} file not found: ${p}`); }
  const base = existsSync(core.base) ? realpathSync(core.base) : core.base;
  if (!real.startsWith(base + sep)) throw new ClaimRejectedError(`${kind} path must be inside ${core.base} (resolved to ${real})`);
  const st = statSync(real);
  if (!st.isFile()) throw new ClaimRejectedError(`${kind} path is not a regular file: ${p}`);
  const cap = kind === "har" ? HAR_MAX_BYTES : SCREENSHOT_MAX_BYTES;
  if (st.size > cap) throw new ClaimRejectedError(`${kind} too large: ${st.size} bytes > ${cap}`);
  return real;
}

export function importMcpResult(core: EvidenceCore, id: string, input: ImportMcpInput): Promise<Evidence> {
  return core.withLock(id, async () => {
    const w = core.load(id);
    const c = (core.deps.mcpImports ?? MCP_IMPORT_PRESETS).find((x) => x.name === input.connector);
    if (!c) throw new ClaimRejectedError(`unknown MCP connector: ${input.connector}`);
    if (!c.tools.includes(input.tool)) throw new ClaimRejectedError(`tool ${input.connector}.${input.tool} is not in the read-only import list`);
    if (input.checkId !== undefined && !(w.checks ?? []).some((x) => x.id === input.checkId)) throw new ClaimRejectedError(`unknown check: ${input.checkId}`);
    if (input.result === undefined) throw new ClaimRejectedError("result is required");
    const links = input.links ?? [];
    if (!links.length) throw new ClaimRejectedError("imported evidence must link to earlier evidence (links: [{evidenceId, key}])");
    const raw = typeof input.result === "string" ? input.result : JSON.stringify(input.result, null, 2);
    core.verifyEvidence(w, "observed", links.map((l) => l.evidenceId));
    for (const l of links) {
      if (!l.key || String(l.key).length < 1) throw new ClaimRejectedError("link key is required");
      const ev = w.evidence.find((e) => e.id === l.evidenceId)!;
      if (!readFileSync(join(core.dir(id), ev.path), "utf8").includes(String(l.key))) throw new ClaimRejectedError(`unlinked: key "${l.key}" not found in ${l.evidenceId}`);
      if (!raw.includes(String(l.key))) throw new ClaimRejectedError(`unlinked: key "${l.key}" not found in the imported result`);
    }
    const params = sanitizeParams(input.params ?? {}, core.redactor);
    const out = await core.registry.action(`connector:${c.name}`).run({ type: `connector:${c.name}`, tool: input.tool, params, result: input.result } as never, { walkthrough: w, sandbox: undefined as never, replay: core.deps.replay });
    const evId = `ev-${w.evidence.length + 1}`;
    const rel = `evidence/${evId}.json.txt`;
    writeFileSync(join(core.dir(id), rel), scrub(out.evidenceText, core.redactor));
    const ev: Evidence = {
      id: evId, type: "response", kind: "mcp_result", path: rel, executedBy: "agent",
      source: `connector:${c.name}`, mcpCall: { connector: c.name, server: c.server, tool: input.tool, params },
      links: links.map((l) => ({ evidenceId: l.evidenceId, key: scrub(String(l.key), core.redactor) })),
      ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha256File(join(core.dir(id), rel)), createdAt: core.ts(),
    };
    w.evidence.push(ev);
    core.save(w);
    return ev;
  });
}

export function readEvidenceText(core: EvidenceCore, w: Walkthrough, ev: Evidence): string {
  return core.redactor.text(readFileSync(join(core.dir(w.id), ev.path), "utf8"));
}
