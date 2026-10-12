#!/usr/bin/env node
// Thin stdio MCP shell. All behaviour lives in src/core.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createCore, planChecksShape, recordFindingShape, renderWalkthrough } from "../core/index.js";

const core = createCore(process.env.WALKTHROUGH_ROOT ?? process.cwd());
const server = new McpServer({ name: "walkthrough-mcp", version: "0.1.0" });

const wrap = (fn: () => unknown) => async () => {
  try {
    return { content: [{ type: "text" as const, text: JSON.stringify(await fn(), null, 2) }] };
  } catch (e) {
    return { isError: true, content: [{ type: "text" as const, text: core.redact(String((e as Error).message)) }] };
  }
};
const id = z.string().describe("walkthrough id");

server.tool("start_walkthrough", "Start a walkthrough with a Docker Compose sandbox config.", {
  title: z.string(), cwd: z.string(), up: z.string(), down: z.string(), logs: z.string().optional(),
  sandbox: z.enum(["compose", "local"]).optional().describe("local = host child processes, NOT isolated"),
}, (a) => wrap(() => core.startWalkthrough({ title: a.title, sandbox: { backend: a.sandbox, cwd: a.cwd, up: a.up, down: a.down, logs: a.logs } }))());

server.tool("run_in_sandbox", "Bring the sandbox up/down or exec a command in its cwd.", {
  id, action: z.enum(["up", "down", "exec"]), command: z.string().optional(),
}, (a) => wrap(() => core.runInSandbox(a.id, a.action, a.command))());

server.tool("capture_evidence", "Capture a screenshot (url) or docker logs (service) as hashed evidence.", {
  id, type: z.enum(["screenshot", "logs"]), url: z.string().optional(), service: z.string().optional(),
}, (a) => wrap(() => core.captureEvidence(a.id, a.type === "screenshot" ? { type: "screenshot", url: a.url ?? "" } : { type: "logs", service: a.service ?? "" }))());

server.tool("link_source", "Link a source file and line.", {
  id, file: z.string(), line: z.number().int(), note: z.string().optional(),
}, (a) => wrap(() => core.linkSource(a.id, a))());

server.tool("record_claim", "Record a claim. observed claims must cite existing, unmodified evidence ids.", {
  id, question: z.string(), conclusion: z.string(), kind: z.enum(["observed", "inferred"]),
  evidenceIds: z.array(z.string()).optional(), sourceIds: z.array(z.string()).optional(),
}, (a) => wrap(() => core.recordClaim(a.id, a))());

server.tool("plan_checks", "Record the checks you will run for a goal. Each needs a machine-checkable expect.", planChecksShape,
  (a) => wrap(() => core.planChecks(a.id, { goal: a.goal, checks: a.checks as never }))());

server.tool("run_checks", "Run all planned checks in the sandbox, capture evidence, auto-judge pass/fail, draft findings.", { id },
  (a) => wrap(() => core.runChecks(a.id))());

server.tool("record_finding", "Record a finding. observed findings must cite existing, unmodified evidence ids.", recordFindingShape,
  (a) => wrap(() => core.recordFinding(a.id, a))());

server.tool("render_walkthrough", "Render the walkthrough to static HTML.", { id },
  (a) => wrap(() => ({ html: renderWalkthrough(core, a.id) }))());

await server.connect(new StdioServerTransport());
