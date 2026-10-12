import { z } from "zod";

/** Zod shapes for the MCP tools, kept in core so the MCP shell stays thin. */
export const checkSchema = z.object({
  id: z.string(),
  name: z.string(),
  action: z.discriminatedUnion("type", [
    z.object({ type: z.literal("http"), method: z.string().optional(), url: z.string(), body: z.string().optional(), headers: z.record(z.string()).optional() }),
    z.object({ type: z.literal("command"), command: z.string() }),
  ]).or(z.object({ type: z.string().regex(/^connector:/) }).passthrough()),
  observe: z.array(z.object({ source: z.string() }).passthrough()).optional(),
  verify: z.object({ type: z.string() }).passthrough().optional(),
  watch: z.object({ logs: z.array(z.string()).optional(), alerts: z.array(z.string()).optional() }).optional(),
  expect: z.object({
    status: z.number().int().optional(), statusRange: z.tuple([z.number(), z.number()]).optional(),
    bodyIncludes: z.string().optional(), exitCode: z.number().int().optional(),
  }),
});

export const planChecksShape = {
  id: z.string(),
  goal: z.string(),
  checks: z.array(checkSchema).describe("your plan; every check needs a machine-checkable expect"),
};

export const recordFindingShape = {
  id: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  whatHappened: z.string(),
  repro: z.array(z.string()).optional(),
  rootCause: z.object({ sourceId: z.string().optional(), logEvidenceId: z.string().optional(), summary: z.string().optional() }).optional(),
  evidenceIds: z.array(z.string()).optional(),
  kind: z.enum(["observed", "inferred"]),
};
