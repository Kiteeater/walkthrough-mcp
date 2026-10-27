#!/usr/bin/env node
// Demo entry: bring the sandbox up, let the demo agent plan/execute/submit, render the audit report.
// usage: node dist/demo-agent/run.js <flow.json> <routes.json> [--sandbox local|compose] [--root <dir>]
// Uses an explicit main() (no top-level await) so a stalled promise can never end the process silently with exit 13.
import { parseArgs } from "node:util";
import { createCore, loadFlowConfig, Redactor, runFlow } from "../core/index.js";
import { runDemoAgent } from "./agent.js";
import { loopbackCidrs } from "./allowlist.js";
import { loadRoutes } from "./planner.js";

const DEFAULT_BASE_URL = "http://localhost:3000";

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { sandbox: { type: "string" }, root: { type: "string" } } });
  const [flowFile, routesFile] = positionals;
  if (!flowFile || !routesFile) throw new Error("usage: run.js <flow.json> <routes.json> [--sandbox local|compose] [--root <dir>]");
  const cfg = loadFlowConfig(flowFile, { backend: values.sandbox as "local" | undefined });
  const agentCfg = ((cfg as unknown as { agent?: { goal?: string; baseUrl?: string; service?: string } }).agent) ?? {}; // env-expanded
  // Allowlist: the service under test (same host the flow's waitFor / screenshots use). Local demo → loopback only.
  const svc = new URL(agentCfg.baseUrl ?? DEFAULT_BASE_URL);
  const core = createCore(values.root ?? process.cwd(), undefined, { allowHosts: [svc.host], allowCidrs: loopbackCidrs([svc]) });
  const routes = loadRoutes(routesFile);
  const r = await runFlow(core, cfg, {
    agent: async (id) => { await runDemoAgent(core, id, routes, { goal: agentCfg.goal ?? "every declared route works", baseUrl: agentCfg.baseUrl ?? DEFAULT_BASE_URL, service: agentCfg.service }); },
  });
  console.log(JSON.stringify(r));
}

main().catch((e: Error) => { console.error(Redactor.fromEnv().text(String(e.message))); process.exitCode = 1; });
