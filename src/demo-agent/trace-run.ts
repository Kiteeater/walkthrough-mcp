#!/usr/bin/env node
// PR #7 demo entry: local sandbox runs the service; the agent traces a 500 through Langfuse and MongoDB.
// usage: node dist/demo-agent/trace-run.js <flow.json> [--root <dir>]
// env: MONGO_URL, LANGFUSE_URL, LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY (the agent's OWN access; never given to walkthrough).
import { parseArgs } from "node:util";
import { createCore, loadFlowConfig, PRESET_CONNECTORS, readJsonFile, Redactor, runFlow, type ConnectorConfig } from "../core/index.js";
import { runTraceAgent, type McpClients } from "./trace.js";

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { root: { type: "string" } } });
  const [flowFile] = positionals;
  if (!flowFile) throw new Error("usage: trace-run.js <flow.json> [--root <dir>]");
  const env = (k: string) => { const v = process.env[k]; if (!v) throw new Error(`${k} is required`); return v; };
  const { MongoClient } = await import("mongodb");
  const mongo = new MongoClient(env("MONGO_URL"));
  const auth = "Basic " + Buffer.from(`${env("LANGFUSE_PUBLIC_KEY")}:${env("LANGFUSE_SECRET_KEY")}`).toString("base64");
  const mcp: McpClients = {
    async getTrace(traceId) {
      const r = await fetch(`${env("LANGFUSE_URL")}/api/public/traces/${encodeURIComponent(traceId)}`, { headers: { authorization: auth }, signal: AbortSignal.timeout(10_000) });
      if (!r.ok) throw new Error(`langfuse get_trace ${r.status}`);
      return r.json();
    },
    find: (db, coll, filter) => mongo.db(db).collection(coll).find(filter as never).limit(10).toArray(),
  };
  // Prometheus (read-only) is optional: when configured, its host is the only replay/metrics allowlist entry.
  const prom = process.env.WALKTHROUGH_PROMETHEUS_URL ? new URL(process.env.WALKTHROUGH_PROMETHEUS_URL) : undefined;
  const cfg = loadFlowConfig(flowFile);
  const a = ((readJsonFile(flowFile) as { agent?: { goal: string; baseUrl: string; service?: string; orders: string[] } }).agent)!;
  // Allowlist: the service under test (for replay_request) + Prometheus when configured. Local demo → loopback only.
  const svc = new URL(a.baseUrl);
  const hosts = [svc.host, ...(prom ? [prom.host] : [])];
  // RocketMQ (read-only, optional): the demo points the real mqadmin preset at a mock binary and fixes the name server.
  // Cloud logs (read-only, optional): the real aliyun preset (sls get-logs allowlist) pointed at a mock binary.
  const mqBin = process.env.WALKTHROUGH_DEMO_MQADMIN, mqNs = process.env.WALKTHROUGH_DEMO_NAMESRV, slsBin = process.env.WALKTHROUGH_DEMO_ALIYUN;
  const useMq = !!(mqBin && mqNs), useSls = !!slsBin;
  const connectors: ConnectorConfig[] | undefined = useMq || useSls
    ? PRESET_CONNECTORS.map((c) => (useMq && c.name === "mqadmin" ? { ...c, binary: mqBin!, namesrvs: [mqNs!], profile: "demo-readonly" }
      : useSls && c.name === "aliyun" ? { ...c, binary: slsBin!, profile: "demo-readonly" } : c))
    : undefined;
  const core = createCore(values.root ?? process.cwd(), undefined, { allowHosts: hosts, allowCidrs: [svc, ...(prom ? [prom] : [])].some((u) => u.hostname === "127.0.0.1") ? ["127.0.0.1/32"] : [] }, connectors);
  try {
    const r = await runFlow(core, cfg, { agent: (id) => runTraceAgent(core, id, mcp, { ...a, metrics: !!prom, replay: true, ...(useMq ? { mq: { group: "order-pricing-consumer", topic: "ORDER_CREATED" } } : {}),
      ...(useSls ? { sls: { project: "demo-prod-logs", logstore: "infra" } } : {}) }) });
    console.log(JSON.stringify(r));
  } finally { await mongo.close(); }
}

main().catch((e: Error) => { console.error(Redactor.fromEnv().text(String(e.message))); process.exitCode = 1; });
