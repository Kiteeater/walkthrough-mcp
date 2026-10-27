import { z } from "zod";

/** Zod shapes for the MCP tools, kept in core so the MCP shell stays thin. Field names follow walkthrough-design.md. */
export const checkSchema = z.object({
  id: z.string(),
  intent: z.string().describe("what this check proves"),
  method: z.enum(["cli", "mcp", "ui", "http", "script"]).describe("how YOU will execute it; the MCP never executes it"),
  target: z.string().describe("URL / command / MCP tool / page to act on"),
  expect: z.object({
    type: z.enum(["status", "count", "regex", "threshold", "absent", "ui", "metric", "sls_empty"]),
    value: z.unknown().describe("status: number|[min,max]; count: number|{pattern?,eq|min|max}; regex/absent: pattern; threshold: {pattern with one capture group, min|max}; ui: {har:{urlMatch,status,bodyMatch?,method?}} or {text:{contains}} (screenshots are never judged); metric: {op: >|>=|<|<=|==|!=, value, query?} over query_metrics evidence (one finite series, else inconclusive)"),
  }),
  severity_if_fail: z.enum(["critical", "high", "medium", "low"]),
  verify: z.object({ type: z.string() }).passthrough().optional(),
  alertMatchers: z.array(z.record(z.string())).optional().describe("Prometheus alert label matchers relating alerts to this check, e.g. [{alertname: 'HighOrders5xx'}, {route: '~/api/orders.*'}]"),
});

export const planChecksShape = {
  id: z.string(),
  goal: z.string(),
  checks: z.array(checkSchema).describe("your plan; a check without a machine-checkable expect is rejected"),
  append: z.boolean().optional().describe("append-only follow-up checks (existing checks can't be changed); logged in the command log"),
  triggering_evidence_id: z.string().optional().describe("required with append: the evidence that made you add these checks"),
};

export const captureEvidenceShape = {
  id: z.string(),
  type: z.enum(["submit", "screenshot", "logs"]).default("submit").describe("submit = raw output you obtained yourself; screenshot/logs = captured by walkthrough"),
  check_id: z.string().optional(),
  kind: z.enum(["cli_output", "mcp_result", "http", "screenshot", "har", "log"]).optional(),
  source: z.object({ tool: z.string(), server: z.string().optional(), command: z.string().optional() }).optional(),
  content: z.string().optional().describe("raw, unedited output (base64 for a screenshot; HAR JSON for har). Screenshots are never judged; use har (network) or DOM text"),
  path: z.string().optional().describe("screenshot/har file path; must be inside .walkthrough/ (symlinks resolved), HAR <= 5 MB, PNG <= 10 MB"),
  url: z.string().optional(), service: z.string().optional(), delta: z.boolean().optional(),
};

export const evaluateCheckShape = {
  id: z.string(), check_id: z.string(), evidence_ids: z.array(z.string()).describe("evidence captured for this check"),
};

export const recordFindingShape = {
  id: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  symptom: z.string(),
  repro_steps: z.array(z.string()).optional(),
  root_cause_chain: z.array(z.object({
    claim: z.string(), kind: z.enum(["observed", "inferred"]), evidence_ids: z.array(z.string()), source_ref: z.string().optional(),
  })).min(1).describe("symptom → … → cause; observed steps must cite evidence"),
  check_id: z.string().optional(),
};


type Cap = { [K in keyof typeof captureEvidenceShape]?: unknown };
/** Map capture_evidence tool args to the core input. */
export function captureInput(a: Cap) {
  const s = a as { type?: string; check_id?: string; url?: string; service?: string; delta?: boolean; kind?: never; source?: never; content?: string; path?: string };
  if (s.type === "screenshot") return { type: "screenshot" as const, url: s.url ?? "", checkId: s.check_id };
  if (s.type === "logs") return { type: "logs" as const, service: s.service ?? "", checkId: s.check_id, delta: s.delta };
  if (!s.check_id) throw new Error("check_id is required when submitting evidence");
  return { type: "submit" as const, checkId: s.check_id, kind: s.kind as never, source: s.source as never, content: s.content, path: s.path };
}

export const importMcpResultShape = {
  id: z.string(),
  check_id: z.string().optional(),
  connector: z.string().describe("connector name: mongodb | langfuse | aliyun (read-only presets)"),
  tool: z.string().describe("the MCP tool YOU called on that server, e.g. find / get_trace / sls_GetLogs"),
  params: z.unknown().optional().describe("the call parameters; credential fields are dropped, never send secrets"),
  result: z.unknown().describe("the raw, unedited tool result"),
  links: z.array(z.object({ evidence_id: z.string(), key: z.string() })).min(1)
    .describe("earlier evidence this result follows from, and the key (trace id, doc id…) present in both"),
};
type Imp = { check_id?: string; connector: string; tool: string; params?: unknown; result: unknown; links: { evidence_id: string; key: string }[] };
export const importInput = (a: Imp) => ({
  checkId: a.check_id, connector: a.connector, tool: a.tool, params: a.params, result: a.result,
  links: (a.links ?? []).map((l) => ({ evidenceId: l.evidence_id, key: l.key })),
});

export const QUERY_METRICS_DESC = "walkthrough runs ONE read-only Prometheus instant query itself (GET /api/v1/query only; endpoint from WALKTHROUGH_PROMETHEUS_URL, host must be in replay.allowHosts) and stores the result as evidence executed by walkthrough. Judge it with expect {type: metric, value: {op, value, query?}}.";
export const queryMetricsShape = {
  id: z.string(), query: z.string().max(2000).describe("PromQL; aggregate to ONE series, e.g. sum(rate(...))"),
  check_id: z.string().optional(), time: z.string().optional().describe("unix seconds or RFC3339; default now"),
};

export const ALERT_WATCH_DEFAULT_WINDOW_S = 60;
export const START_WATCH_DESC = "Start watching Prometheus alerts (GET /api/v1/alerts only, same endpoint rules as query_metrics) in the BACKGROUND over a bounded window; returns a watch id at once, other tools stay usable. Trigger your action, then call collect_watch.";
export const startWatchShape = {
  id: z.string(),
  window_s: z.number().int().min(1).max(900).optional().describe("watch window in seconds (default 60, max 900)"),
  interval_s: z.number().int().min(1).max(60).optional().describe("poll interval in seconds (1-60, default 15)"),
  matchers: z.array(z.object({ check_id: z.string(), labels: z.record(z.string()) })).optional().describe("extra matchers mapping alerts to checks"),
};
export const COLLECT_WATCH_DESC = "Stop a watch and turn what it saw into evidence/findings: firing alerts matching a check's alertMatchers are attached to that check's finding (or become one); unmatched ones are listed separately; a quiet window is recorded with start/end; a dead poller is reported as interrupted.";
export const collectWatchShape = { watch_id: z.string().regex(/^w_[0-9a-f]{16}$/).describe("id returned by start_watch") };
type Watch = { window_s?: number; interval_s?: number; matchers?: { check_id: string; labels: Record<string, string> }[] };
export const watchInput = (a: Watch) => ({ windowS: a.window_s ?? ALERT_WATCH_DEFAULT_WINDOW_S, intervalS: a.interval_s, matchers: a.matchers?.map((m) => ({ checkId: m.check_id, labels: m.labels })) });
