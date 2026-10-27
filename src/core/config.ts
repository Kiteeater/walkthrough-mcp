// Strict schemas for every config file the core reads: <root>/walkthrough.config.json (replay block) and flow configs
// (`walkthrough run --config`, the demo agents). Unknown fields, wrong types and missing required fields are a
// ConfigError naming the file and the field path, never ignored: a typo in a guard setting (e.g. "allowHost") must
// not silently fall back to a default.
import { z } from "zod";
import type { FlowConfig } from "./flow.js";
import type { ReplayConfig } from "./replay.js";

export class ConfigError extends Error {
  override name = "ConfigError";
}

const str = z.string().min(1);
const strs = z.array(str);
const posInt = z.number().int().positive();

export const replaySchema = z.object({
  allowHosts: strs,
  allowCidrs: strs.optional(),
  auth: z.object({ header: str, valueEnv: str, origins: strs.optional() }).strict().optional(),
  capture: z.object({
    storageStatePath: str.optional(),
    allowWebSocketHosts: strs.optional(),
    webSocketOutbound: z.record(z.string(), z.array(z.string())).optional(),
  }).strict().optional(),
  maxRedirects: z.number().int().nonnegative().optional(),
  timeoutMs: posInt.optional(),
  maxBodyBytes: posInt.optional(),
}).strict();

/** <root>/walkthrough.config.json (or WALKTHROUGH_CONFIG). */
export const rootConfigSchema = z.object({ replay: replaySchema.optional() }).strict();

const sandboxSchema = z.object({
  backend: z.enum(["compose", "local"]).optional(),
  local: z.object({ up: str, down: str.optional(), passEnv: strs.optional(), killTimeoutMs: posInt.optional() }).strict().optional(),
  allowExec: z.boolean().optional(),
  cwd: str.optional(), // resolved against the config file's directory by loadFlowConfig (default ".")
  // Required like SandboxConfig; may be "" only when backend is "local" (local.up is what runs then).
  up: z.string(),
  down: z.string(),
  logs: str.optional(),
}).strict().superRefine((sb, ctx) => {
  if (sb.backend === "local") return;
  for (const k of ["up", "down"] as const) if (sb[k] === "") ctx.addIssue({ code: z.ZodIssueCode.custom, path: [k], message: `must not be empty unless backend is "local"` });
});

export const flowSchema = z.object({
  title: str,
  sandbox: sandboxSchema,
  waitFor: z.object({
    url: str, timeoutMs: posInt.optional(), attemptTimeoutMs: posInt.optional(),
    header: z.object({ name: str, value: str }).strict().optional(),
  }).strict().optional(),
  exec: strs.optional(),
  captures: z.array(z.discriminatedUnion("type", [
    z.object({ as: str, type: z.literal("screenshot"), url: str }).strict(),
    z.object({ as: str, type: z.literal("logs"), service: str }).strict(),
  ])),
  sources: z.array(z.object({ as: str, file: str, line: posInt, note: z.string().optional() }).strict()).optional(),
  claims: z.array(z.object({
    question: str, conclusion: str, kind: z.enum(["observed", "inferred"]), evidence: strs.optional(), sources: strs.optional(),
  }).strict()),
  keepRunning: z.boolean().optional(),
  /** Read by the demo agents (src/demo-agent), ignored by `walkthrough run`. */
  agent: z.object({ goal: str, baseUrl: str, service: str.optional(), orders: strs.optional() }).strict().optional(),
}).strict();

function issues(e: z.ZodError): string {
  return e.issues.map((i) => {
    const path = i.path.length ? i.path.join(".") : "(root)";
    if (i.code === "unrecognized_keys") return `${path}: unknown field(s) ${i.keys.join(", ")}`;
    // Keep the public config error wording stable across Zod 3 and Zod 4.
    const x = i as z.ZodIssue & { expected?: string; received?: string; minimum?: number; inclusive?: boolean };
    if (i.code === "invalid_type" && x.expected) {
      const received = x.received ?? /received ([^ ]+)/.exec(i.message)?.[1] ?? "unknown";
      return `${path}: ${received === "undefined" ? "Required" : `Expected ${x.expected}, received ${received}`}`;
    }
    if (i.code === "too_small" && typeof x.minimum === "number" && x.expected === undefined) return `${path}: Number must be ${x.inclusive === false ? "greater than" : "greater than or equal to"} ${x.minimum}`;
    if (i.code === "invalid_value") return `${path}: Invalid enum value`;
    return `${path}: ${i.message}`;
  }).join("; ");
}

function parse<T>(schema: z.ZodTypeAny, value: unknown, where: string): T {
  const r = schema.safeParse(value);
  if (!r.success) throw new ConfigError(`invalid config ${where}: ${issues(r.error)}`);
  return r.data as T;
}

export const parseRootConfig = (v: unknown, where: string) => parse<{ replay?: ReplayConfig }>(rootConfigSchema, v, where);
export const parseReplayConfig = (v: unknown, where: string) => parse<ReplayConfig>(replaySchema, v, where);
export const parseFlowConfig = (v: unknown, where: string) => parse<FlowConfig>(flowSchema, v, where);

/** JSON.parse with the file named in the error. */
export function parseJsonConfig(text: string, where: string): unknown {
  try { return JSON.parse(text); } catch (e) { throw new ConfigError(`invalid config ${where}: not valid JSON (${(e as Error).message})`); }
}
