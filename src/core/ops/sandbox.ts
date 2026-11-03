// Sandbox ops moved from WalkthroughCore (ops/ split step 4). Bodies are verbatim except `this.` -> `core.`.
// The class keeps one-line forwarders `return xxx(this, ...)`, so `core` is always the WalkthroughCore instance.
import { createHash } from "node:crypto";
import { join } from "node:path";
import { execDecision } from "../execpolicy.js";
import { appendLogEntry, CliRejectedError, PRESET_CONNECTORS, type CommandLogEntry } from "../runcli.js";
import type { Redactor } from "../redact.js";
import type { Evidence, RunRecord, Walkthrough } from "../types.js";
import { SignedOffError } from "../errors.js";
import type { CoreDeps, RunCliInput } from "../walkthrough.js";

/** Narrow view of WalkthroughCore: only the members the sandbox ops touch. */
export interface SandboxCore {
  readonly deps: Pick<CoreDeps, "sandboxFactory" | "connectors">;
  readonly redactor: Redactor;
  load(id: string): Walkthrough;
  save(w: Walkthrough): void;
  dir(id: string): string;
  ts(): string;
  withLock<T>(id: string, fn0: () => T | Promise<T>, opts?: { allowSigned?: boolean }): Promise<T>;
  runCli(id: string, input: RunCliInput): Promise<{ evidence: Evidence; log: CommandLogEntry; exitCode: number }>;
  sandboxExec(id: string, command?: string): Promise<RunRecord>;
  sandboxCommand(w: Walkthrough, action: "up" | "down"): string;
}

export function runInSandbox(core: SandboxCore, id: string, action: "up" | "down" | "exec", command?: string): Promise<RunRecord> {
  if (action === "exec") return core.sandboxExec(id, command);
  return core.withLock(id, async () => {
  const w = core.load(id);
  const sb = core.deps.sandboxFactory(w.sandbox, w.id);
  const res = action === "up" ? await sb.up() : await sb.down();
  const rec: RunRecord = {
    id: `run-${w.runs.length + 1}`,
    command: core.redactor.text(core.sandboxCommand(w, action)),
    exitCode: res.exitCode,
    output: core.redactor.text(res.output).slice(-20_000),
    createdAt: core.ts(),
  };
  w.runs.push(rec);
  core.save(w);
  return rec;
  });
}

/**
 * run_in_sandbox exec (issue #8). Off unless sandbox.allowExec: true. A command naming a known credentialed CLI
 * (aliyun, mqadmin, mongosh, …, by any path/case) never runs here: connector CLIs are routed through run_cli's
 * allowlist, the rest are rejected; shells/wrappers are rejected. Spawned as file + args, never via a shell.
 * Every exec is recorded (run record + hash-chained `sandbox_exec` log entry) and flagged red on the report.
 */
export async function sandboxExec(core: SandboxCore, id: string, command?: string): Promise<RunRecord> {
  if (!command) throw new Error("exec requires a command");
  const w0 = core.load(id);
  if (w0.signoff) throw new SignedOffError(`walkthrough ${id} is signed off; it is read-only now`); // re-checked under the lock
  if (w0.sandbox.allowExec !== true) throw new CliRejectedError("run_in_sandbox exec is disabled (set sandbox.allowExec: true in the walkthrough config to enable arbitrary commands); use run_cli for CLIs");
  const d = execDecision(command, process.env, core.deps.connectors ?? PRESET_CONNECTORS);
  if (d.kind === "route") {
    const r = await core.runCli(id, { connector: d.connector.name, argv: d.argv });
    return core.withLock(id, () => {
      const w = core.load(id);
      const rec: RunRecord = { id: `run-${w.runs.length + 1}`, command: core.redactor.text(command), exitCode: r.exitCode, output: `routed to run_cli (${d.connector.name}), evidence ${r.evidence.id}`, createdAt: core.ts(), via: "run_cli" };
      w.runs.push(rec);
      core.save(w);
      return rec;
    });
  }
  return core.withLock(id, async () => {
    const w = core.load(id);
    const sb = core.deps.sandboxFactory(w.sandbox, w.id);
    const res = await sb.exec([d.file, ...d.args]);
    const rec: RunRecord = { id: `run-${w.runs.length + 1}`, command: core.redactor.text(command), exitCode: res.exitCode, output: core.redactor.text(res.output).slice(-20_000), createdAt: core.ts(), via: "exec" };
    w.runs.push(rec);
    const l = appendLogEntry(join(core.dir(id), "commands.jsonl"), { ts: rec.createdAt, walkthroughId: id, type: "sandbox_exec", runId: rec.id, command: rec.command, exitCode: rec.exitCode,
      outputSha256: createHash("sha256").update(rec.output).digest("hex"), executedBy: "core" });
    w.commandLogHead = { seq: l.seq, hash: l.hash };
    core.save(w);
    return rec;
  });
}

export function sandboxCommand(core: SandboxCore, w: Walkthrough, action: "up" | "down"): string {
  if (w.sandbox.backend === "local") return action === "up" ? (w.sandbox.local?.up ?? w.sandbox.up) : "kill local process group";
  return action === "up" ? w.sandbox.up : w.sandbox.down;
}
