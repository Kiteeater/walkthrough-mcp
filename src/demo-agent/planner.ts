// Demo agent: NOT part of the MCP core. A host agent normally plans checks itself; this deterministic,
// rule-based planner stands in for it in the example so the demo needs no LLM.
import { readFileSync } from "node:fs";
import { DEFAULT_ALERTS, type Check } from "../core/index.js";

/** A route declared by the service under test. Carries no knowledge of which route is buggy. */
export interface RouteSpec { method?: string; path: string; expectStatus?: number; expectIncludes?: string }


/**
 * Deterministic rule-based planner (no LLM): every declared route gets the same generic check —
 * request it, expect a 2xx (or the declared status), and watch the service logs for error alerts.
 */
export function planFromRoutes(routes: RouteSpec[], opts: { baseUrl: string; service?: string; alerts?: string[] }): Check[] {
  return routes.map((r, i) => {
    const method = (r.method ?? "GET").toUpperCase();
    return {
      id: `chk-${i + 1}`,
      name: `${method} ${r.path}`,
      action: { type: "http", method, url: opts.baseUrl.replace(/\/$/, "") + r.path },
      watch: { logs: [opts.service ?? "app"], alerts: opts.alerts ?? DEFAULT_ALERTS },
      expect: {
        ...(r.expectStatus ? { status: r.expectStatus } : { statusRange: [200, 299] as [number, number] }),
        ...(r.expectIncludes ? { bodyIncludes: r.expectIncludes } : {}),
      },
    };
  });
}

export function loadRoutes(file: string): RouteSpec[] {
  const data = JSON.parse(readFileSync(file, "utf8")) as { routes?: RouteSpec[] } | RouteSpec[];
  return Array.isArray(data) ? data : data.routes ?? [];
}


// CLI: node dist/demo-agent/planner.js <flow-template.json> <routes.json> <out.json>
// Writes a flow config whose plan.checks were derived from the routes (the agent's "plan").
if (process.argv[1]?.endsWith("planner.js") && process.argv.length >= 5) {
  const [tpl, routesFile, out] = process.argv.slice(2);
  const { writeFileSync } = await import("node:fs");
  const { dirname, resolve, relative } = await import("node:path");
  const cfg = JSON.parse(readFileSync(tpl, "utf8"));
  const { baseUrl = "http://localhost:3000", service = "app", goal } = cfg.agent ?? {};
  cfg.plan = { goal, checks: planFromRoutes(loadRoutes(routesFile), { baseUrl, service }) };
  delete cfg.agent;
  cfg.sandbox.cwd = relative(dirname(resolve(out)), resolve(dirname(tpl), cfg.sandbox.cwd));
  writeFileSync(out, JSON.stringify(cfg, null, 2));
  console.log(`planned ${cfg.plan.checks.length} checks -> ${out}`);
}
