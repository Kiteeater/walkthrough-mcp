import { existsSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Expect, Verdict } from "./types.js";
import { judgeUi, uiExpectProblem, type UiExpect } from "./har.js";

/** Default alert patterns an agent can watch for in logs. */
export const DEFAULT_ALERTS = ["Error:", "Unhandled", "FATAL"];

const num = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function compiles(p: unknown): p is string {
  if (typeof p !== "string" || !p || p.length > 500) return false; // length cap on agent-supplied patterns
  try { new RegExp(p, "m"); return true; } catch { return false; }
}

/** Why an expectation is NOT machine-checkable, or undefined if it is. plan_checks rejects the check otherwise. */
export function expectProblem(e: Expect | undefined): string | undefined {
  if (!e || typeof e !== "object") return "missing expect";
  const v = e.value;
  switch (e.type) {
    case "status":
      return num(v) || (Array.isArray(v) && v.length === 2 && v.every(num)) ? undefined : "status value must be a number or [min, max]";
    case "count":
      if (num(v)) return undefined;
      if (!obj(v) || ![v.eq, v.min, v.max].some(num)) return "count value must be a number or {pattern?, eq|min|max}";
      return v.pattern === undefined || compiles(v.pattern) ? undefined : "count pattern is not a valid regex";
    case "regex":
    case "absent":
      return compiles(v) ? undefined : `${e.type} value must be a valid, non-empty regex`;
    case "threshold":
      if (!obj(v) || !compiles(v.pattern) || ![v.min, v.max].some(num)) return "threshold value must be {pattern, min|max}";
      return new RegExp(v.pattern as string).source.includes("(") ? undefined : "threshold pattern needs a capture group";
    case "ui":
      return uiExpectProblem(v);
    default:
      return `unknown expect type ${JSON.stringify((e as { type?: unknown }).type)}`;
  }
}

export interface Judgement { status: Verdict; reasons: string[] }

function readStatus(text: string): number | undefined {
  const m = /^HTTP\/?[\d.]*\s+(\d{3})\b/m.exec(text) ?? /"status"\s*:\s*(\d{3})\b/.exec(text);
  return m ? Number(m[1]) : undefined;
}

function countOf(text: string, pattern?: string): number {
  if (pattern) return [...text.matchAll(new RegExp(pattern, "gm"))].length;
  try { const j = JSON.parse(text); if (Array.isArray(j)) return j.length; if (obj(j) && num(j.count)) return j.count; } catch { /* not JSON */ }
  return text.split("\n").filter((l) => l.trim()).length;
}

/** Judge an expectation over raw evidence texts. No evidence or no readable value → inconclusive. */
export function evaluateExpect(e: Expect, texts: string[]): Judgement {
  if (!texts.length) return { status: "inconclusive", reasons: ["no evidence submitted for this check"] };
  const all = texts.join("\n");
  type Spec = { pattern?: string; eq?: number; min?: number; max?: number };
  const v = e.value as Spec & number & string & [number, number];
  if (e.type === "ui") return judgeUi(e.value as UiExpect, texts);
  switch (e.type) {
    case "status": {
      const got = texts.map(readStatus).find((x) => x !== undefined);
      if (got === undefined) return { status: "inconclusive", reasons: ["no HTTP status found in evidence"] };
      const [lo, hi] = Array.isArray(v) ? v : [v, v];
      return got >= lo && got <= hi ? { status: "pass", reasons: [] } : { status: "fail", reasons: [`status ${got}, expected ${lo === hi ? lo : `${lo}-${hi}`}`] };
    }
    case "count": {
      const spec: Spec = num(v) ? { eq: v } : v;
      const n = countOf(all, spec.pattern);
      const r: string[] = [];
      if (num(spec.eq) && n !== spec.eq) r.push(`count ${n}, expected ${spec.eq}`);
      if (num(spec.min) && n < spec.min) r.push(`count ${n}, expected >= ${spec.min}`);
      if (num(spec.max) && n > spec.max) r.push(`count ${n}, expected <= ${spec.max}`);
      return { status: r.length ? "fail" : "pass", reasons: r };
    }
    case "regex":
      return new RegExp(v, "m").test(all) ? { status: "pass", reasons: [] } : { status: "fail", reasons: [`no match for /${v}/`] };
    case "absent": {
      const m = new RegExp(v, "m").exec(all);
      return m ? { status: "fail", reasons: [`found /${v}/: ${JSON.stringify(m[0].slice(0, 120))}`] } : { status: "pass", reasons: [] };
    }
    case "threshold": {
      const t = e.value as Spec;
      const m = new RegExp(t.pattern!, "m").exec(all);
      const x = m ? Number(m[1]) : NaN;
      if (!Number.isFinite(x)) return { status: "inconclusive", reasons: [`no number for /${t.pattern}/ in evidence`] };
      const r: string[] = [];
      if (num(t.min) && x < t.min) r.push(`${x} < min ${t.min}`);
      if (num(t.max) && x > t.max) r.push(`${x} > max ${t.max}`);
      return { status: r.length ? "fail" : "pass", reasons: r };
    }
  }
  return { status: "inconclusive", reasons: ["unknown expect type"] };
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
