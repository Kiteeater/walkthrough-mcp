#!/usr/bin/env node
// Thin stdio MCP shell. All behaviour lives in src/core.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  captureEvidenceShape, captureInput, QUERY_METRICS_DESC, queryMetricsShape, START_WATCH_DESC, startWatchShape, COLLECT_WATCH_DESC, collectWatchShape, watchInput, importInput, importMcpResultShape, createCore, evaluateCheckShape, planChecksShape, recordFindingShape, renderWalkthrough,
} from "../core/index.js";

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

server.tool("run_in_sandbox", "Bring the sandbox up/down, or exec a command (disabled unless sandbox.allowExec: true; known CLIs go through run_cli's allowlist; no shell).", {
  id, action: z.enum(["up", "down", "exec"]), command: z.string().optional(),
}, (a) => wrap(() => core.runInSandbox(a.id, a.action, a.command))());

server.tool("capture_evidence", "Submit raw output you obtained yourself (type=submit, check_id, kind, source, content), or have walkthrough capture a screenshot/logs. Stored redacted with sha256.",
  captureEvidenceShape, (a) => wrap(() => core.captureEvidence(a.id, captureInput(a)))());

server.tool("import_mcp_result", "Import a result you got from another READ-ONLY MCP server (mongodb / langfuse / aliyun). Stored as agent-reported evidence (lower trust), hashed and redacted; must link to earlier evidence by a shared key.",
  importMcpResultShape, (a) => wrap(() => core.importMcpResult(a.id, importInput(a as never)))());

server.tool("capture_page", "method: ui fallback when you have no computer use: walkthrough loads the page with Playwright and stores screenshot + HAR + DOM text (executed by walkthrough).", {
  id, check_id: z.string(), url: z.string(),
}, (a) => wrap(() => core.capturePage(a.id, { checkId: a.check_id, url: a.url }))());

server.tool("replay_request", "walkthrough re-sends ONE GET/HEAD request from a HAR evidence item itself (executed by walkthrough): host must be in replay.allowHosts, private/metadata IPs denied, HAR cookies/auth never sent, redirects re-checked.", {
  id, check_id: z.string(), evidence_id: z.string().describe("HAR evidence to take the request from"),
  url_match: z.string().optional().describe("regex picking the HAR entry"), method: z.enum(["GET", "HEAD"]).optional(),
}, (a) => wrap(() => core.replayHar(a.id, { checkId: a.check_id, evidenceId: a.evidence_id, urlMatch: a.url_match, method: a.method }))());

server.tool("query_metrics", QUERY_METRICS_DESC, queryMetricsShape, (a) => wrap(() => core.queryMetrics(a.id, { query: a.query, checkId: a.check_id, time: a.time }))());
server.tool("start_watch", START_WATCH_DESC, startWatchShape, (a) => wrap(() => core.startWatch(a.id, { ...watchInput(a), background: "in-process" }))()); server.tool("collect_watch", COLLECT_WATCH_DESC, collectWatchShape, (a) => wrap(() => core.collectWatch(a.watch_id))());
server.tool("link_source", "Link a source file and line.", {
  id, file: z.string(), line: z.number().int(), note: z.string().optional(),
}, (a) => wrap(() => core.linkSource(a.id, a))());

server.tool("record_claim", "Record a claim. observed claims must cite existing, unmodified evidence ids.", {
  id, question: z.string(), conclusion: z.string(), kind: z.enum(["observed", "inferred"]),
  evidenceIds: z.array(z.string()).optional(), sourceIds: z.array(z.string()).optional(),
}, (a) => wrap(() => core.recordClaim(a.id, a))());

server.tool("run_cli", "walkthrough runs a whitelisted READ-ONLY CLI for you (argv only, no shell) and stores the output as evidence. mongosh takes only template {name: find|aggregate|countDocuments, db, collection, filter|pipeline}.", {
  id, check_id: z.string().optional(), connector: z.string(), argv: z.array(z.string()).optional(),
  template: z.record(z.unknown()).optional(), timeout_s: z.number().optional(),
}, (a) => wrap(() => core.runCli(a.id, { checkId: a.check_id, connector: a.connector, argv: a.argv, template: a.template as never, timeoutS: a.timeout_s }))());

server.tool("verify_command_log", "Verify the hash-chained run_cli command log.", { id }, (a) => wrap(() => core.verifyCommandLog(a.id))());

server.tool("plan_checks", "Record your check plan. Every check needs a machine-checkable expect. Returns next_actions.", planChecksShape,
  (a) => wrap(() => core.planChecks(a.id, { goal: a.goal, checks: a.checks as never, append: a.append, triggeringEvidenceId: a.triggering_evidence_id }))());

server.tool("evaluate_check", "walkthrough judges a check pass/pass_needs_review/fail/inconclusive from its evidence (agent-reported evidence alone is at most pass_needs_review). You cannot set or override the verdict.", evaluateCheckShape,
  (a) => wrap(() => core.evaluateCheck(a.id, { checkId: a.check_id, evidenceIds: a.evidence_ids }))());

server.tool("record_finding", "Record a finding with symptom, repro_steps and root_cause_chain. Observed steps must cite verified evidence.", recordFindingShape,
  (a) => wrap(() => core.recordFinding(a.id, a))());

// sign_off is deliberately NOT an MCP tool: the report-level decision is a human act (CLI `walkthrough sign-off`).

server.tool("render_walkthrough", "Render the walkthrough to static HTML.", { id },
  (a) => wrap(() => ({ html: renderWalkthrough(core, a.id) }))());

await server.connect(new StdioServerTransport());
