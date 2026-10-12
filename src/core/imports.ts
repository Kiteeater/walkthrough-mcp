// Importing results from OTHER MCP servers (official MongoDB, Aliyun, Langfuse) as agent-reported evidence.
// The host agent calls those servers itself (with its own read-only login); we never connect, never see credentials.
import type { ActionSource } from "./registry.js";
import type { ConnectorAction } from "./types.js";
import { MASK, type Redactor } from "./redact.js";

/** A connector the agent may import results from. `tools` = read-only tool names we accept; anything else is rejected. */
export interface McpImportConnector { name: string; server: string; tools: string[] }

/** Read-only presets matching the recommended server configs in README (mongo --readOnly, aliyun --services, Langfuse allowlist). */
export const MCP_IMPORT_PRESETS: McpImportConnector[] = [
  { name: "mongodb", server: "mongodb-mcp-server", tools: ["find", "aggregate", "count", "list-databases", "list-collections", "collection-schema", "collection-indexes", "explain", "db-stats"] },
  { name: "langfuse", server: "langfuse", tools: ["get_trace", "list_traces", "get_observation", "list_observations", "get_session", "list_sessions"] },
  { name: "aliyun", server: "alibaba-cloud-ops-mcp-server", tools: ["sls_GetLogs", "sls_GetHistograms", "cms_DescribeAlertLogList", "cms_DescribeMetricList", "ecs_DescribeInstances"] },
];

/** Call parameters as stored: credential-looking keys dropped to MASK, URI userinfo stripped, then env-secret redaction. */
const CRED_KEY = /(pass(word|wd)?|secret|token|api[-_]?key|auth(orization)?|credential|cookie|session[-_]?key|private[-_]?key|^sk$|^pk$|access[-_]?key)/i;
export function sanitizeParams(params: unknown, redactor: Redactor): unknown {
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return redactor.text(stripUserinfo(v));
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) if (x !== undefined) out[redactor.text(k)] = CRED_KEY.test(k) ? MASK : walk(x);
      return out;
    }
    return v;
  };
  return walk(params);
}
/** `mongodb://user:pw@host` → `mongodb://[REDACTED]@host` (anywhere in a string). */
export const stripUserinfo = (s: string) => s.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s@:]+(:[^/\s@]*)?@/gi, `$1${MASK}@`);

export interface McpImportAction extends ConnectorAction { tool: string; params: unknown; result: unknown }

/** The `connector:<name>` source seam: normalises an agent-reported MCP result into evidence text. It executes nothing. */
export function mcpImportSource(c: McpImportConnector): ActionSource<McpImportAction> {
  return {
    type: `connector:${c.name}`,
    async run(a) {
      const body = typeof a.result === "string" ? a.result : JSON.stringify(a.result, null, 2);
      const call = `${c.server}.${a.tool}(${JSON.stringify(a.params ?? {})})`;
      return { body, repro: `call MCP tool ${call}`, evidenceText: `# reported by agent: ${call}\n\n${body}` };
    },
  };
}
