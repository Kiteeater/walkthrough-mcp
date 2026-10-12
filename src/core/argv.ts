/**
 * Shell-free command lines. Config strings like `docker compose up -d` or `PORT=$P exec node server.js` are split into
 * argv here and run with spawn(file, args) — never `bash -c`, never `shell: true`. Anything that would need a shell
 * (`;`, `|`, `&`, `` ` ``, `$(`, redirects, globs, unknown `$VAR`) is rejected instead of being interpreted.
 */
export class UnsafeCommandError extends Error {
  constructor(message: string) { super(message); this.name = "UnsafeCommandError"; }
}

export interface ParsedCommand { file: string; args: string[]; env: Record<string, string> }

const META = /[;&|`<>(){}*?!\n\r\\]/;
const ASSIGN = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

/** Split on whitespace honouring '…' and "…" quotes. Unquoted shell metacharacters are an error. */
export function tokenize(line: string): string[] {
  const out: string[] = [];
  let cur = "", has = false, q: "'" | '"' | null = null;
  for (const ch of line) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (has) out.push(cur); cur = ""; has = false; continue; }
    if (META.test(ch)) throw new UnsafeCommandError(`shell metacharacter ${JSON.stringify(ch)} is not allowed: ${line}`);
    cur += ch; has = true;
  }
  if (q) throw new UnsafeCommandError(`unterminated quote: ${line}`);
  if (has) out.push(cur);
  return out;
}

/**
 * Parse a config command into file/args/env. Leading `NAME=value` become env entries; a whole-value `$NAME` is taken
 * from `env` (the already-allowlisted child env) or rejected. A leading `exec` is dropped (spawn already replaces).
 */
export function parseCommand(input: string | string[], env: NodeJS.ProcessEnv = {}): ParsedCommand {
  const toks = Array.isArray(input) ? [...input] : tokenize(input);
  const extra: Record<string, string> = {};
  if (!Array.isArray(input)) {
    while (toks.length && ASSIGN.test(toks[0])) {
      const [, k, v] = ASSIGN.exec(toks.shift()!)!;
      extra[k] = expandWhole(v, env);
    }
    if (toks[0] === "exec") toks.shift();
    for (const t of toks) if (t.includes("$")) throw new UnsafeCommandError(`variable expansion is not supported in arguments: ${t}`);
  }
  if (!toks.length || !toks[0]) throw new UnsafeCommandError("empty command");
  return { file: toks[0], args: toks.slice(1), env: extra };
}

function expandWhole(v: string, env: NodeJS.ProcessEnv): string {
  if (!v.includes("$")) return v;
  const m = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(v);
  if (!m) throw new UnsafeCommandError(`only a whole-value $NAME is supported: ${v}`);
  const val = env[m[1]];
  if (val === undefined) throw new UnsafeCommandError(`$${m[1]} is not in the allowed env`);
  return val;
}
