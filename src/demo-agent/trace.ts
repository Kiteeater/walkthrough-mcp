// Demo agent for PR #7: traces a 500 across sources. It plays the host agent that has the official Langfuse and
// MongoDB MCP servers mounted: the "MCP calls" below are what those read-only tools would return, made by the agent,
// and handed to walkthrough via import_mcp_result (agent-reported). walkthrough itself only captures the service logs.
import { DEFAULT_ALERTS, traceStack, type Check, type RootCauseLink, type WalkthroughCore } from "../core/index.js";

export interface McpClients {
  /** Stand-in for langfuse.get_trace({traceId}). */
  getTrace(traceId: string): Promise<unknown>;
  /** Stand-in for mongodb.find({database, collection, filter}). */
  find(database: string, collection: string, filter: Record<string, unknown>): Promise<unknown[]>;
}
export interface TraceOptions { goal: string; baseUrl: string; orders: string[]; service?: string; settleMs?: number; /** Corroborate with Prometheus (core query_metrics). */ metrics?: boolean; /** Let walkthrough replay the failing request itself (core replay_request). */ replay?: boolean }

/** 5xx ratio of the orders total route over 5m (one series). */
export const FIVE_XX_RATIO = 'sum(rate(http_requests_total{route="/api/orders/:id/total",status=~"5.."}[5m])) / sum(rate(http_requests_total{route="/api/orders/:id/total"}[5m]))';

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function planTraceChecks(o: TraceOptions): Check[] {
  const base = o.baseUrl.replace(/\/$/, "");
  return o.orders.flatMap((ord, i): Check[] => [
    { id: `chk-${i + 1}`, intent: `GET /api/orders/${ord}/total 返回 2xx`, method: "http", target: `GET ${base}/api/orders/${ord}/total`, expect: { type: "status", value: [200, 299] }, severity_if_fail: "high",
      ...(o.metrics ? { alertMatchers: [{ route: "/api/orders/:id/total" }] } : {}) },
    { id: `chk-${i + 1}-logs`, intent: `${o.service ?? "app"} 日志中 ${ord} 没有报错`, method: "cli", target: `logs:${o.service ?? "app"}`, expect: { type: "absent", value: DEFAULT_ALERTS.map(esc).join("|") }, severity_if_fail: "high" },
  ]);
}

export async function runTraceAgent(core: WalkthroughCore, id: string, mcp: McpClients, o: TraceOptions): Promise<void> {
  const service = o.service ?? "app";
  const plan = planTraceChecks(o);
  await core.planChecks(id, { goal: o.goal, checks: plan });
  await core.captureEvidence(id, { type: "logs", service, delta: true });
  // Alerts: start a background watch BEFORE acting (it does not lock the walkthrough), wait for a baseline poll,
  // then act; collect at the end. A firing alert whose labels match a check's alertMatchers is attached to that
  // check's finding (the traced 500); unrelated firing alerts are listed separately.
  const watch = o.metrics ? await core.startWatch(id, { windowS: 60, intervalS: 1 }) : undefined;
  if (watch) await until(() => core.readWatch(watch.id).polls.length >= 1, 5000);
  const actedAt = new Date().toISOString();
  for (const main of plan.filter((c) => /^chk-\d+$/.test(c.id))) {
    const [method, url] = main.target.split(" ");
    const out = await core.registry.action("http").run({ type: "http", method, url }, { walkthrough: core.load(id), sandbox: undefined as never });
    await new Promise((r) => setTimeout(r, o.settleMs ?? 300));
    const httpEv = await core.captureEvidence(id, { type: "submit", checkId: main.id, kind: "http", source: { tool: "fetch", command: out.repro }, content: out.evidenceText });
    const logEv = await core.captureEvidence(id, { type: "logs", service, delta: true, checkId: `${main.id}-logs` });
    // walkthrough re-sends the request itself (method + URL only, SSRF policy, hash-chained) so the symptom is core-executed.
    let replayEv: { id: string } | undefined;
    if (o.replay && (out.status ?? 0) >= 500) {
      const har = { log: { version: "1.2", creator: { name: "trace-agent", version: "1" }, entries: [{ startedDateTime: new Date().toISOString(), request: { method, url, headers: [], cookies: [], queryString: [] }, response: { status: out.status, headers: [], cookies: [], content: { mimeType: "application/json", text: out.body } } }] } };
      const harEv = await core.captureEvidence(id, { type: "submit", checkId: main.id, kind: "har", source: { tool: "fetch", command: out.repro }, content: JSON.stringify(har) });
      replayEv = await core.replayHar(id, { checkId: main.id, evidenceId: harEv.id, method: "GET" });
    }
    const r = await core.evaluateCheck(id, { checkId: main.id, evidenceIds: replayEv ? [httpEv.id, replayEv.id] : [httpEv.id] });
    await core.evaluateCheck(id, { checkId: `${main.id}-logs`, evidenceIds: [logEv.id] });
    if (r.status !== "fail") continue;

    // Follow the 500: trace id from the response → Langfuse trace → the Mongo doc it names → stack frame.
    const traceId = /"traceId"\s*:\s*"([\w-]+)"/.exec(out.body)?.[1];
    const chain: RootCauseLink[] = [{ claim: replayEv ? `${main.target.replace(/https?:\/\/[^/]+/, "")} 返回 ${out.status}，walkthrough 自己重放同一请求确认（${r.reasons.join("；")}）` : `${main.target.replace(/https?:\/\/[^/]+/, "")} 返回 ${out.status}（${r.reasons.join("；")}）`, kind: "observed", evidence_ids: replayEv ? [replayEv.id, httpEv.id] : [httpEv.id] }];
    let more: Check[] = [];
    if (o.metrics) {
      // Corroborate the single failing request with production-style metrics, queried by walkthrough itself.
      const mId = `${main.id}-5xx`;
      await core.planChecks(id, { goal: o.goal, append: true, triggeringEvidenceId: httpEv.id, checks: [
        { id: mId, intent: "指标佐证：/api/orders/:id/total 近 5 分钟 5xx 比例 > 0", method: "script", target: `prometheus ${FIVE_XX_RATIO}`, expect: { type: "metric", value: { op: ">", value: 0, query: FIVE_XX_RATIO } }, severity_if_fail: "medium" },
      ] });
      const mEv = await core.queryMetrics(id, { query: FIVE_XX_RATIO, checkId: mId });
      const mRes = await core.evaluateCheck(id, { checkId: mId, evidenceIds: [mEv.id] });
      chain.push({ claim: `Prometheus：/api/orders/:id/total 近 5 分钟 5xx 比例 — ${mRes.reasons.join("；")}（${mRes.status}），不是偶发`, kind: "observed", evidence_ids: [mEv.id] });
    }
    if (traceId) {
      const trace = await mcp.getTrace(traceId) as { metadata?: { db?: string; collection?: string; orderId?: string }; observations?: { name: string; level: string; statusMessage?: string }[] };
      const n = main.id;
      more = [
        { id: `${n}-trace`, intent: `Langfuse trace ${traceId} 没有 ERROR 级 observation`, method: "mcp", target: `langfuse.get_trace(${traceId})`, expect: { type: "absent", value: '"level": "ERROR"' }, severity_if_fail: "high" },
      ];
      const meta = trace.metadata ?? {};
      if (meta.orderId && meta.collection) {
        more.push({ id: `${n}-doc`, intent: `${meta.db}.${meta.collection} ${meta.orderId} 有商品明细（items）`, method: "mcp", target: `mongodb.find(${meta.collection}, {_id: ${meta.orderId}})`, expect: { type: "regex", value: '"items"\\s*:' }, severity_if_fail: "high" });
      }
      await core.planChecks(id, { goal: o.goal, checks: more, append: true, triggeringEvidenceId: httpEv.id });
      const tEv = await core.importMcpResult(id, { checkId: `${n}-trace`, connector: "langfuse", tool: "get_trace", params: { traceId }, result: trace, links: [{ evidenceId: httpEv.id, key: traceId }] });
      const tRes = await core.evaluateCheck(id, { checkId: `${n}-trace`, evidenceIds: [tEv.id] });
      const err = trace.observations?.find((x) => x.level === "ERROR");
      chain.push({ claim: `Langfuse trace ${traceId}：observation "${err?.name}" 为 ERROR（${err?.statusMessage}），对应 ${meta.collection} ${meta.orderId} — ${tRes.status}`, kind: "observed", evidence_ids: [tEv.id] });
      if (meta.orderId && meta.collection) {
        const filter = { _id: meta.orderId };
        const docs = await mcp.find(meta.db ?? "test", meta.collection, filter);
        const dEv = await core.importMcpResult(id, { checkId: `${n}-doc`, connector: "mongodb", tool: "find", params: { database: meta.db, collection: meta.collection, filter }, result: docs, links: [{ evidenceId: tEv.id, key: meta.orderId }] });
        const dRes = await core.evaluateCheck(id, { checkId: `${n}-doc`, evidenceIds: [dEv.id] });
        const fields = Object.keys((docs[0] ?? {}) as object).join(", ");
        chain.push({ claim: `MongoDB ${meta.db}.${meta.collection} {_id: "${meta.orderId}"} 只有字段 [${fields}]，没有 "items" — ${dRes.status}`, kind: "observed", evidence_ids: [dEv.id] });
      }
    }
    const w = core.load(id);
    const hit = traceStack(core.readEvidenceText(w, w.evidence.find((e) => e.id === logEv.id)!), w.sandbox.cwd, core.root);
    if (hit) {
      const src = await core.linkSource(id, { file: hit.file, line: hit.line, note: hit.message });
      chain.push({ claim: `服务的堆栈指向 ${hit.file}:${hit.line}（${hit.message}）：代码假设每个订单都有 items`, kind: "observed", evidence_ids: [logEv.id], source_ref: src.id });
    }
    await core.recordFinding(id, {
      title: `${main.target.replace(/https?:\/\/[^/]+/, "")} 返回 500：订单文档缺少商品明细`, severity: "high", check_id: main.id,
      symptom: `${main.target} 返回 ${out.status}${traceId ? `（trace ${traceId}）` : ""}`,
      repro_steps: [out.repro, ...(traceId ? [`langfuse.get_trace({traceId: "${traceId}"})`] : []), ...more.slice(1).map((c) => c.target)],
      root_cause_chain: chain,
    });
  }
  if (watch) {
    await until(() => core.readWatch(watch.id).polls.some((p) => p.at > actedAt && p.firing.length > 0), 5000);
    await core.collectWatch(watch.id);
  }
}

async function until(cond: () => boolean, ms: number): Promise<void> {
  for (const end = Date.now() + ms; Date.now() < end && !cond();) await new Promise((r) => setTimeout(r, 100));
}
