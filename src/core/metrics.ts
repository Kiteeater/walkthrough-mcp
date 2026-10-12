// Read-only Prometheus adapter: instant queries only (GET /api/v1/query). The endpoint goes through the same host
// allowlist + IP policy as replay (pinned IP, every redirect hop re-checked, token bound to the endpoint's origin).
import { replayRequest, ReplayRejectedError, type ReplayConfig, type Resolver } from "./replay.js";

export interface MetricsSample { metric: Record<string, string>; value: number; at: string }

export interface MetricsAdapter {
  readonly kind: string;
  /** Run an instant query. Must not mutate the backend. */
  query(expr: string, at?: Date): Promise<MetricsSample[]>;
}

export class NotImplementedMetricsAdapter implements MetricsAdapter {
  readonly kind = "none";
  async query(): Promise<MetricsSample[]> {
    throw new Error("metrics adapter not configured (set WALKTHROUGH_PROMETHEUS_URL and replay.allowHosts)");
  }
}

export interface PrometheusConfig {
  /** Base URL, e.g. https://prom.internal:9090 or https://host/prometheus. Must not itself point at an /api/ path. */
  url: string;
  /** Env var holding a bearer token (default WALKTHROUGH_PROMETHEUS_TOKEN). The value is never stored. */
  tokenEnv?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export const MAX_QUERY_LEN = 2000;
export const PROM_QUERY_PATH = "/api/v1/query";
export class MetricsError extends Error { constructor(m: string) { super(m); this.name = "MetricsError"; } }

/** Prometheus config from env: WALKTHROUGH_PROMETHEUS_URL (+ WALKTHROUGH_PROMETHEUS_TOKEN). */
export function prometheusFromEnv(env: NodeJS.ProcessEnv = process.env): PrometheusConfig | undefined {
  const url = env.WALKTHROUGH_PROMETHEUS_URL;
  return url ? { url, tokenEnv: env.WALKTHROUGH_PROMETHEUS_TOKEN_ENV || "WALKTHROUGH_PROMETHEUS_TOKEN" } : undefined;
}

/** The only URL we ever request: <base>/api/v1/query?query=…[&time=…]. Throws for anything else. */
/** Validate the configured base URL (no API path, query, fragment or credentials). */
function promBase(base: string): URL {
  let u: URL;
  try { u = new URL(base); } catch { throw new MetricsError(`invalid Prometheus URL`); }
  if (u.search || u.hash || u.username || u.password) throw new MetricsError("Prometheus URL must not carry query, fragment or credentials");
  if (/\/api(\/|$)/i.test(u.pathname)) throw new MetricsError(`Prometheus URL must be the base URL, not an API path (${u.pathname})`);
  return u;
}

/** The read-only Prometheus API paths walkthrough may call. Nothing else is ever requested. */
export const PROM_ALERTS_PATH = "/api/v1/alerts";
export type PromPath = typeof PROM_QUERY_PATH | typeof PROM_ALERTS_PATH;

/** <base><path>[?params]; throws for an invalid base. */
export function promUrl(base: string, path: PromPath, params: Record<string, string> = {}): URL {
  const u = promBase(base);
  u.pathname = u.pathname.replace(/\/+$/, "") + path;
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u;
}

/** The only URL we ever request for queries: <base>/api/v1/query?query=…[&time=…]. Throws for anything else. */
export function promQueryUrl(base: string, query: string, time?: string): URL {
  if (typeof query !== "string" || !query.trim()) throw new MetricsError("query is required");
  if (query.length > MAX_QUERY_LEN) throw new MetricsError(`query longer than ${MAX_QUERY_LEN} chars`);
  if (time !== undefined && !/^\d{9,11}(\.\d+)?$/.test(time) && Number.isNaN(Date.parse(time))) throw new MetricsError("time must be a unix timestamp or RFC3339");
  return promUrl(base, PROM_QUERY_PATH, time === undefined ? { query } : { query, time });
}

export interface PromQueryResult {
  url: string; status: number; body: string; hops: { url: string; ip: string; status: number }[]; sentSecrets: string[];
  /** Parsed Prometheus envelope (status success|error, data…). */
  json: { status?: string; errorType?: string; error?: string; data?: { resultType?: string; result?: unknown; alerts?: unknown } };
}

/**
 * GET one read-only Prometheus API URL under the replay policy: allowlist + IP rules, pinned IP, every redirect hop
 * re-checked and required to stay on the same API path, bearer token bound to the endpoint's origin, size/time limits.
 */
export async function promGet(
  cfg: PrometheusConfig, policy: ReplayConfig, url: URL, path: PromPath,
  opts: { resolver?: Resolver; env?: NodeJS.ProcessEnv } = {},
): Promise<PromQueryResult> {
  const env = opts.env ?? process.env;
  const token = env[cfg.tokenEnv ?? "WALKTHROUGH_PROMETHEUS_TOKEN"];
  const AUTH = "__WALKTHROUGH_PROM_AUTH";
  const p: ReplayConfig = {
    ...policy, timeoutMs: cfg.timeoutMs ?? 10_000, maxBodyBytes: cfg.maxResponseBytes ?? 1024 * 1024, maxRedirects: 2,
    // Token bound to the endpoint's origin only; any redirect to another origin drops it.
    auth: token ? { header: "Authorization", valueEnv: AUTH, origins: [url.origin] } : undefined,
  };
  const r = await replayRequest(p, { method: "GET", url: url.toString() }, {
    resolver: opts.resolver, env: { [AUTH]: token ? `Bearer ${token}` : undefined },
    // Every hop (including redirects) must still be the same read-only API: no admin / write / remote_write paths.
    hopCheck: (h) => { if (!h.pathname.endsWith(path)) throw new ReplayRejectedError(`only ${path} is allowed, not ${h.pathname}`); },
  });
  if (r.truncated) throw new MetricsError(`Prometheus response larger than ${p.maxBodyBytes} bytes`);
  let json: PromQueryResult["json"];
  try { json = JSON.parse(r.body); } catch { throw new MetricsError(`Prometheus answered HTTP ${r.status} with a non-JSON body`); }
  return { url: url.toString(), status: r.status, body: r.body, hops: r.hops, sentSecrets: [...r.sentSecrets, ...(token ? [token] : [])], json };
}

/** Run one instant query (GET /api/v1/query). */
export function promInstantQuery(
  cfg: PrometheusConfig, policy: ReplayConfig, query: string,
  opts: { time?: string; resolver?: Resolver; env?: NodeJS.ProcessEnv } = {},
): Promise<PromQueryResult> {
  return promGet(cfg, policy, promQueryUrl(cfg.url, query, opts.time), PROM_QUERY_PATH, opts);
}

export type MetricOp = ">" | ">=" | "<" | "<=" | "==" | "!=";
export const METRIC_OPS: MetricOp[] = [">", ">=", "<", "<=", "==", "!="];
export interface MetricExpect { op: MetricOp; value: number; query?: string }

export function metricExpectProblem(v: unknown): string | undefined {
  const o = v as MetricExpect;
  if (!o || typeof o !== "object") return "metric value must be {op, value, query?}";
  if (!METRIC_OPS.includes(o.op)) return `metric op must be one of ${METRIC_OPS.join(" ")}`;
  if (typeof o.value !== "number" || !Number.isFinite(o.value)) return "metric value.value must be a finite number";
  if (o.query !== undefined && (typeof o.query !== "string" || !o.query || o.query.length > MAX_QUERY_LEN)) return "metric query must be a non-empty string";
  return undefined;
}

/** Marker so the judge only reads evidence written by queryMetrics. */
export const METRIC_EVIDENCE = "walkthrough.metric/v1";

/**
 * Judge a metric expectation over stored metric evidence. Exactly one series with one finite value is required:
 * empty result, NaN/±Inf, multiple series, non-success status → inconclusive (never treated as 0).
 */
export function judgeMetric(v: MetricExpect, texts: string[]): { status: "pass" | "fail" | "inconclusive"; reasons: string[] } {
  const evs = texts.map((t) => { try { const j = JSON.parse(t); return j?.format === METRIC_EVIDENCE ? j : undefined; } catch { return undefined; } })
    .filter((j) => j && (!v.query || j.query === v.query));
  if (!evs.length) return { status: "inconclusive", reasons: [v.query ? `no metric evidence for query ${v.query}` : "no metric evidence"] };
  const out: { status: "pass" | "fail" | "inconclusive"; reasons: string[] }[] = evs.map((j) => {
    if (j.response?.status !== "success") return { status: "inconclusive", reasons: [`Prometheus status ${j.response?.status ?? "?"} (HTTP ${j.httpStatus}) ${j.response?.errorType ?? ""} ${j.response?.error ?? ""}`.trim()] };
    const d = j.response.data ?? {};
    let raw: unknown;
    if (d.resultType === "scalar") raw = (d.result as unknown[])?.[1];
    else if (d.resultType === "vector") {
      const r = (d.result ?? []) as { metric: unknown; value: [number, string] }[];
      if (r.length === 0) return { status: "inconclusive", reasons: [`empty result for ${j.query} (not treated as 0)`] };
      if (r.length > 1) return { status: "inconclusive", reasons: [`${r.length} series for ${j.query}; aggregate to one series (e.g. sum(...))`] };
      raw = r[0].value?.[1];
    } else return { status: "inconclusive", reasons: [`unsupported resultType ${d.resultType}`] };
    const x = Number(raw);
    if (typeof raw !== "string" || !Number.isFinite(x)) return { status: "inconclusive", reasons: [`non-finite value ${String(raw)} for ${j.query}`] };
    const ok = { ">": x > v.value, ">=": x >= v.value, "<": x < v.value, "<=": x <= v.value, "==": x === v.value, "!=": x !== v.value }[v.op];
    return ok ? { status: "pass", reasons: [`${j.query} = ${x} ${v.op} ${v.value}`] } : { status: "fail", reasons: [`${j.query} = ${x}, expected ${v.op} ${v.value}`] };
  });
  if (out.some((o) => o.status === "fail")) return { status: "fail", reasons: out.filter((o) => o.status === "fail").flatMap((o) => o.reasons) };
  if (out.some((o) => o.status === "inconclusive")) return { status: "inconclusive", reasons: out.filter((o) => o.status === "inconclusive").flatMap((o) => o.reasons) };
  return { status: "pass", reasons: out.flatMap((o) => o.reasons) };
}

/** One-line value summary of a metric evidence text (for the audit view), or undefined. */
export function metricSummary(text: string): { query: string; value?: string; ok: boolean } | undefined {
  try {
    const j = JSON.parse(text);
    if (j?.format !== METRIC_EVIDENCE) return undefined;
    const r = j.response?.data?.result;
    const v = j.response?.data?.resultType === "scalar" ? r?.[1] : Array.isArray(r) && r.length === 1 ? r[0].value?.[1] : undefined;
    return { query: j.query, value: v, ok: j.response?.status === "success" };
  } catch { return undefined; }
}
