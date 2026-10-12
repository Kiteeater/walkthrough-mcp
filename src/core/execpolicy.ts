// Policy for run_in_sandbox exec (issue #8). exec is arbitrary code, so it is OFF unless the walkthrough config sets
// sandbox.allowExec: true. Even then, anything that resolves to a known credentialed CLI is never run here: it goes
// through run_cli's allowlist, or is rejected. Commands are always spawned as file + args (no shell).
import { basename } from "node:path";
import { parseCommand, UnsafeCommandError } from "./argv.js";
import { CliRejectedError, PRESET_CONNECTORS, type ConnectorConfig } from "./runcli.js";

/** CLIs that carry local credentials but have no connector: never runnable via exec. */
export const CREDENTIALED_CLIS = ["aliyun", "aliyuncli", "mongosh", "mongo", "mongodump", "mongoexport", "mongoimport", "mongorestore", "mongofiles",
  "mqadmin", "ossutil", "ossutil64", "kubectl", "ssh", "scp", "curl", "wget"];
/** Wrappers that would hide the real program (or need a shell): rejected outright. */
export const WRAPPERS = ["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "env", "sudo", "su", "doas", "xargs", "nohup", "timeout", "nice", "ionice",
  "stdbuf", "busybox", "command", "script", "setsid", "chroot", "strace", "time", "watch", "flock", "unbuffer", "runuser", "exec", "eval", "source"];

/** Normalised program name: basename, lower-case, without .exe/.cmd/.bat/.sh. */
export const progName = (file: string) => basename(file.replace(/\\/g, "/")).toLowerCase().replace(/\.(exe|cmd|bat|sh|ps1)$/, "");

export type ExecDecision = { kind: "run"; file: string; args: string[] } | { kind: "route"; connector: ConnectorConfig; argv: string[] };

export function execDecision(command: string, env: NodeJS.ProcessEnv, connectors: ConnectorConfig[] = PRESET_CONNECTORS): ExecDecision {
  let p;
  try { p = parseCommand(command, env); } catch (e) {
    if (e instanceof UnsafeCommandError) throw new CliRejectedError(`run_in_sandbox exec: ${e.message}`);
    throw e;
  }
  if (!p.file) throw new CliRejectedError("run_in_sandbox exec: empty command");
  const name = progName(p.file);
  if (WRAPPERS.includes(name)) throw new CliRejectedError(`run_in_sandbox exec: ${name} is a shell/wrapper and is not allowed; run the program directly`);
  const known = (n: string) => connectors.find((c) => c.name.toLowerCase() === n || progName(c.binary) === n);
  const conn = known(name);
  if (conn || CREDENTIALED_CLIS.includes(name)) {
    if (!conn) throw new CliRejectedError(`run_in_sandbox exec: ${name} carries local credentials and has no run_cli connector; not allowed`);
    if (Object.keys(p.env).length) throw new CliRejectedError(`run_in_sandbox exec: env assignments are not allowed for ${name}; use run_cli`);
    if (p.file !== conn.binary && p.file !== name) throw new CliRejectedError(`run_in_sandbox exec: ${p.file} looks like ${name}; call it by name through run_cli`);
    if (conn.kind === "mongo") throw new CliRejectedError(`run_in_sandbox exec: ${name} only runs through run_cli with a query template`);
    return { kind: "route", connector: conn, argv: p.args };
  }
  // A credentialed CLI anywhere in the argv (e.g. `node wrapper.js aliyun …`, `python3 x /usr/bin/aliyun`) is refused too.
  for (const a of p.args) {
    const n = progName(a);
    if (known(n) || CREDENTIALED_CLIS.includes(n) || WRAPPERS.includes(n) && /\//.test(a)) throw new CliRejectedError(`run_in_sandbox exec: argument ${JSON.stringify(a)} names a credentialed CLI or wrapper; use run_cli`);
  }
  // VAR=value prefixes are not supported for exec (PATH/LD_PRELOAD/credential-env tricks); set env in the sandbox config.
  if (Object.keys(p.env).length) throw new CliRejectedError(`run_in_sandbox exec: env assignments (${Object.keys(p.env).join(", ")}) are not allowed; configure env in the sandbox`);
  return { kind: "run", file: p.file, args: p.args };
}
