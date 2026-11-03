// External CLI ops moved from WalkthroughCore (ops/ split step 8). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
// State (`versions` cache) stays an instance field on WalkthroughCore; this module holds no state.
// `verifyCommandLogOp` is named so it does not shadow runcli's `verifyCommandLog`, which its body calls.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { assertNoCoreBlockedTargets, pinNamesrvArgv } from "../egress/targets.js";
import { sha256File } from "../hash.js";
import type { Redactor } from "../redact.js";
import {
  appendCommandLog, assertArgvHostsAllowed, CLI_ENV_DENY, cliArgv, CliRejectedError, collectMessageBodies, mongoArgv, PRESET_CONNECTORS, requestedMsgIds, verifyCommandLog,
  type CommandLogEntry, type ConnectorConfig, type MongoTemplate,
} from "../runcli.js";
import { allowlistEnv, run } from "../sandbox.js";
import type { Check, Evidence, Walkthrough } from "../types.js";
import type { CoreDeps, RunCliInput } from "../walkthrough.js";

/** Narrow view of WalkthroughCore: only the members the CLI ops touch. */
export interface CliCore {
  readonly deps: Pick<CoreDeps, "connectors" | "resolver">;
  readonly redactor: Redactor;
  readonly versions: Map<string, string>;
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  dir(id: string): string;
  ts(): string;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  cliVersion(c: ConnectorConfig, env: NodeJS.ProcessEnv, cwd: string): Promise<string>;
}

export async function cliVersion(core: CliCore, c: ConnectorConfig, env: NodeJS.ProcessEnv, cwd: string): Promise<string> {
  const key = `${c.name}\0${c.binary}`;
  if (!core.versions.has(key)) {
    const r = await run(c.binary, c.versionArgs ?? ["--version"], { cwd, env, timeoutMs: 5_000, maxBytes: 4096 });
    core.versions.set(key, r.exitCode === 0 ? core.redactor.text(r.output.trim().split("\n")[0] ?? "").slice(0, 120) || "unknown" : "unknown");
  }
  return core.versions.get(key)!;
}

export function runCli(core: CliCore, id: string, input: RunCliInput): Promise<{ evidence: Evidence; log: CommandLogEntry; exitCode: number }> {
  return core.withLock(id, async () => {
    const w = core.load(id);
    if (input.checkId !== undefined && !(w.checks ?? []).some((c) => c.id === input.checkId)) throw new Error(`unknown check: ${input.checkId}`);
    if ((input as { env?: unknown }).env !== undefined) throw new CliRejectedError("run_cli does not accept env from the caller");
    const c = (core.deps.connectors ?? PRESET_CONNECTORS).find((x) => x.name === input.connector);
    if (!c) throw new CliRejectedError(`unknown connector: ${input.connector}`);
    let argv: string[];
    if (c.kind === "mongo") {
      if (input.argv?.length) throw new CliRejectedError("mongosh accepts only a query template (find|aggregate|countDocuments), not argv");
      argv = mongoArgv(c, input.template as MongoTemplate);
    } else {
      if (input.template) throw new CliRejectedError(`${c.name} takes argv, not a template`);
      argv = cliArgv(c, input.argv ?? []);
    }
    // Core blocklist: no argv value / connector target (URI, name server, endpoint…) may name or resolve to it.
    // Each name is resolved ONCE; failure/timeout/no address refuses the call (the CLI connects by itself, so this is
    // the only check). Lockable targets (`-n` host:port name servers) are rewritten to the checked IP so the CLI
    // never resolves them again. HTTPS endpoints (aliyun) cannot be pinned without breaking TLS/SNI: there the agent
    // may not name any host outside the connector's allowHosts, and --endpoint is on no allowlist.
    if (c.kind !== "mongo") assertArgvHostsAllowed(c, input.argv ?? []);
    const resolveAll = core.deps.resolver ? async (h: string) => [await core.deps.resolver!(h)] : undefined;
    try {
      const checked = await assertNoCoreBlockedTargets([...argv, ...(c.uri ? [c.uri] : []), ...(c.namesrvs ?? [])], resolveAll);
      if (c.namesrvs) argv = await pinNamesrvArgv(argv, checked, resolveAll);
    } catch (e) { throw new CliRejectedError((e as Error).message); }
    const root = resolve(w.sandbox.cwd);
    const cwd = resolve(root, input.cwd ?? ".");
    if (cwd !== root && !cwd.startsWith(root + sep)) throw new CliRejectedError(`cwd outside the walkthrough root: ${input.cwd}`);
    const env = allowlistEnv([...(w.sandbox.local?.passEnv ?? []), ...(c.passEnv ?? [])].filter((n) => !CLI_ENV_DENY.test(n)));
    for (const n of Object.keys(env)) if (CLI_ENV_DENY.test(n)) delete env[n];
    const version = await core.cliVersion(c, env, cwd);
    const timeoutMs = Math.min(Math.max(1, input.timeoutS ?? 60), 600) * 1000;
    const startedMs = Date.now();
    const res = await run(c.binary, argv, { cwd, env, timeoutMs });
    if (c.messageBody?.subcommands.includes(argv[0])) {
      res.output = collectMessageBodies(res.output, { dir: c.messageBody.dir, maxChars: c.messageBody.maxChars, sinceMs: startedMs, ids: requestedMsgIds(argv) }, (t) => core.redactor.text(t));
    }
    const shown = argv.map((a) => core.redactor.text(a));
    const evId = `ev-${w.evidence.length + 1}`;
    const rel = `evidence/${evId}.txt`;
    writeFileSync(join(core.dir(id), rel), core.redactor.text(`$ ${c.name} ${JSON.stringify(shown)}\nexit ${res.exitCode}\n\n${res.output}`));
    const sha = sha256File(join(core.dir(id), rel));
    const evidence: Evidence = {
      id: evId, type: "response", kind: "cli_output", path: rel, executedBy: "core",
      source: `run_cli:${c.name} ${shown.join(" ")}`.slice(0, 500), ...(input.checkId ? { checkId: input.checkId } : {}), sha256: sha, createdAt: core.ts(),
    };
    const log = appendCommandLog(join(core.dir(id), "commands.jsonl"), {
      ts: evidence.createdAt, walkthroughId: id, ...(input.checkId ? { checkId: input.checkId } : {}), connector: c.name,
      cli: { name: c.binary.split("/").pop()!, version, ...(c.profile ? { profile: c.profile } : {}) },
      argv: shown, cwd: input.cwd ?? ".", exitCode: res.exitCode, outputSha256: sha, evidenceId: evId, executedBy: "core",
    });
    w.evidence.push(evidence);
    w.commandLogHead = { seq: log.seq, hash: log.hash };
    core.save(w);
    return { evidence, log, exitCode: res.exitCode };
  });
}

export function verifyCommandLogOp(core: CliCore, id: string): { ok: boolean; entries: number; error?: string } {
  const w = core.load(id);
  const file = join(core.dir(id), "commands.jsonl");
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
        if (!ev2 || !existsSync(join(core.dir(id), ev2.path)) || sha256File(join(core.dir(id), ev2.path)) !== ev2.sha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: evidence ${x} missing or modified` };
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
    const p = ev && join(core.dir(id), ev.path);
    if (!ev || ev.sha256 !== e.outputSha256 || !existsSync(p!) || sha256File(p!) !== e.outputSha256) return { ok: false, entries: r.entries, error: `seq ${e.seq}: evidence ${e.evidenceId} missing or modified` };
  }
  return r;
}
