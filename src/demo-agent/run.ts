#!/usr/bin/env node
// Demo entry: bring the sandbox up, let the demo agent plan/execute/submit, render the audit report.
// usage: node dist/demo-agent/run.js <flow.json> <routes.json> [--sandbox local|compose] [--root <dir>]
// Uses an explicit main() (no top-level await) so a stalled promise can never end the process silently with exit 13.
import { parseArgs } from "node:util";
import { createCore, loadFlowConfig, Redactor, runFlow, readJsonFile } from "../core/index.js";
import { runDemoAgent } from "./agent.js";
import { loadRoutes } from "./planner.js";

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { sandbox: { type: "string" }, root: { type: "string" } } });
  const [flowFile, routesFile] = positionals;
  if (!flowFile || !routesFile) throw new Error("usage: run.js <flow.json> <routes.json> [--sandbox local|compose] [--root <dir>]");
  const core = createCore(values.root ?? process.cwd());
  const cfg = loadFlowConfig(flowFile, { backend: values.sandbox as "local" | undefined });
  const agentCfg = ((readJsonFile(flowFile) as { agent?: { goal?: string; baseUrl?: string; service?: string } }).agent) ?? {};
  const routes = loadRoutes(routesFile);
  const r = await runFlow(core, cfg, {
    agent: async (id) => { await runDemoAgent(core, id, routes, { goal: agentCfg.goal ?? "every declared route works", baseUrl: agentCfg.baseUrl ?? "http://localhost:3000", service: agentCfg.service }); },
  });
  console.log(JSON.stringify(r));
}

main().catch((e: Error) => { console.error(Redactor.fromEnv().text(String(e.message))); process.exitCode = 1; });
