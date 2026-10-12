import { existsSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Check, Severity } from "./types.js";

/** Default alert patterns an agent can watch for in logs. */
export const DEFAULT_ALERTS = ["Error:", "Unhandled", "FATAL"];

/** True if the expectation is machine-checkable (at least one concrete criterion). */
export function hasMachineExpect(c: Check): boolean {
  const e = c.expect ?? {};
  return e.status !== undefined || e.statusRange !== undefined || e.bodyIncludes !== undefined || e.exitCode !== undefined || (c.watch?.alerts?.length ?? 0) > 0;
}

export interface Actual { status?: number; exitCode?: number; body: string; logs: string }


/** Judge a check against its expectation. Returns failure reasons (empty = pass). */
export function judge(check: Check, a: Actual): string[] {
  const reasons: string[] = [];
  const e = check.expect;
  if (e.status !== undefined && a.status !== e.status) reasons.push(`status ${a.status ?? "none"}, expected ${e.status}`);
  if (e.statusRange && (a.status === undefined || a.status < e.statusRange[0] || a.status > e.statusRange[1])) {
    reasons.push(`status ${a.status ?? "none"}, expected ${e.statusRange[0]}-${e.statusRange[1]}`);
  }
  if (e.exitCode !== undefined && a.exitCode !== e.exitCode) reasons.push(`exit code ${a.exitCode}, expected ${e.exitCode}`);
  if (e.bodyIncludes !== undefined && !a.body.includes(e.bodyIncludes)) reasons.push(`body missing ${JSON.stringify(e.bodyIncludes)}`);
  for (const p of check.watch?.alerts ?? []) if (a.logs.includes(p)) reasons.push(`alert ${JSON.stringify(p)} in logs`);
  return reasons;
}

export function severityFor(a: Actual, reasons: string[]): Severity {
  if (a.status !== undefined && a.status >= 500) return "high";
  if (reasons.some((r) => r.startsWith("alert"))) return "high";
  if (a.status === undefined && a.exitCode === undefined) return "critical";
  return "medium";
}

export interface StackHit { message: string; file: string; line: number; column: number }

/**
 * Grep logs for an error and its stack trace, and map the first in-project frame to a file under `projectDir`,
 * returned relative to `root`. Handles host paths and container paths (e.g. /app/server.js) by suffix matching.
 */
export function traceStack(logs: string, projectDir: string, root: string): StackHit | undefined {
  const lines = logs.split("\n");
  const start = lines.findIndex((l) => /\b\w*Error\b[:\s]/.test(l));
  if (start < 0) return undefined;
  const message = lines[start].replace(/^.*?\|\s*/, "").trim();
  const frame = /\(?((?:file:\/\/)?[^\s()]+?\.(?:[cm]?[jt]s)):(\d+):(\d+)\)?/;
  for (const l of lines.slice(start, start + 30)) {
    const m = frame.exec(l);
    if (!m || m[1].startsWith("node:") || m[1].includes("node_modules")) continue;
    const file = resolveInProject(m[1].replace(/^file:\/\//, ""), projectDir);
    if (!file) continue;
    return { message, file: relative(root, file).split(sep).join("/"), line: Number(m[2]), column: Number(m[3]) };
  }
  return undefined;
}

function resolveInProject(p: string, projectDir: string): string | undefined {
  const dir = resolve(projectDir);
  if (isAbsolute(p) && p.startsWith(dir + sep) && existsSync(p)) return p;
  const parts = p.split(/[\\/]+/).filter(Boolean);
  for (let i = 0; i < parts.length; i++) {
    const cand = join(dir, ...parts.slice(i));
    if (cand.startsWith(dir + sep) && existsSync(cand)) return cand;
  }
  return undefined;
}
