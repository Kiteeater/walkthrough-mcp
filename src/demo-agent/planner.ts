// Demo agent: NOT part of the MCP core. A host agent normally plans checks itself; this deterministic,
// rule-based planner stands in for it in the example so the demo needs no LLM.
import { readFileSync } from "node:fs";
import { DEFAULT_ALERTS, type Check } from "../core/index.js";

/** A route declared by the service under test. Carries no knowledge of which route is buggy. */
export interface RouteSpec { method?: string; path: string; expectStatus?: number; expectIncludes?: string }

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Every declared route gets the same generic checks (design-doc schema):
 * - `chk-N`: request it, expect a 2xx (or the declared status)
 * - `chk-N-logs`: the service logs during that request contain no error alerts
 * - `chk-N-body` (only if declared): the body contains the declared text
 */
export function planFromRoutes(routes: RouteSpec[], opts: { baseUrl: string; service?: string; alerts?: string[] }): Check[] {
  const base = opts.baseUrl.replace(/\/$/, "");
  const alerts = (opts.alerts ?? DEFAULT_ALERTS).map(escapeRe).join("|");
  return routes.flatMap((r, i): Check[] => {
    const method = (r.method ?? "GET").toUpperCase();
    const id = `chk-${i + 1}`;
    const target = `${method} ${base}${r.path}`;
    return [
      { id, intent: `${method} ${r.path} answers ${r.expectStatus ?? "2xx"}`, method: "http", target,
        expect: { type: "status", value: r.expectStatus ?? [200, 299] }, severity_if_fail: "high" },
      { id: `${id}-logs`, intent: `no error alerts in ${opts.service ?? "app"} logs during ${method} ${r.path}`, method: "cli",
        target: `logs:${opts.service ?? "app"} (delta during ${id})`, expect: { type: "absent", value: alerts }, severity_if_fail: "high" },
      ...(r.expectIncludes ? [{ id: `${id}-body`, intent: `${method} ${r.path} body includes the declared text`, method: "http" as const, target,
        expect: { type: "regex" as const, value: escapeRe(r.expectIncludes) }, severity_if_fail: "medium" as const }] : []),
    ];
  });
}

export function loadRoutes(file: string): RouteSpec[] {
  const data = JSON.parse(readFileSync(file, "utf8")) as { routes?: RouteSpec[] } | RouteSpec[];
  return Array.isArray(data) ? data : data.routes ?? [];
}
