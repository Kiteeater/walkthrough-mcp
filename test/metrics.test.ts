import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { judgeMetric, promQueryUrl, Redactor, renderWalkthrough, WalkthroughCore, type Check, type PrometheusConfig, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

// Token in an env var whose NAME does not look secret: only explicit per-run redaction can hide it.
const TOKEN = "promLOGINvalue98765";
const vec = (series: { metric: Record<string, string>; value: [number, string] }[]) => ({ status: "success", data: { resultType: "vector", result: series } });

let srv: http.Server, other: http.Server, port = 0, oport = 0;
const seen: { method?: string; url?: string; headers: http.IncomingHttpHeaders }[] = [];
const otherSeen: http.IncomingHttpHeaders[] = [];
beforeAll(async () => {
  srv = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, headers: req.headers });
    const u = new URL(req.url!, "http://x");
    const q = u.searchParams.get("query") ?? "";
    const auth = String(req.headers.authorization ?? "");
    const send = (code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json", "x-debug-echo": auth }); res.end(JSON.stringify(body)); };
    if (u.pathname !== "/api/v1/query") return send(404, { status: "error", error: "only query here" });
    if (q === "empty") return send(200, vec([]));
    if (q === "nan") return send(200, vec([{ metric: {}, value: [1, "NaN"] }]));
    if (q === "inf") return send(200, vec([{ metric: {}, value: [1, "+Inf"] }]));
    if (q === "multi") return send(200, vec([{ metric: { a: "1" }, value: [1, "1"] }, { metric: { a: "2" }, value: [1, "2"] }]));
    if (q === "err") return send(400, { status: "error", errorType: "bad_data", error: "parse error" });
    if (q === "big") { res.writeHead(200); return res.end("x".repeat(2 * 1024 * 1024)); }
    if (q === "slow") { setTimeout(() => send(200, vec([])), 3000); return; }
    if (q === "redir-admin") { res.writeHead(302, { location: "/api/v1/admin/tsdb/delete_series?match[]=up" }); return res.end(); }
    if (q === "redir-other") { res.writeHead(302, { location: `http://other.local:${oport}/api/v1/query?query=x` }); return res.end(); }
    // Default: one series; debug endpoint echoes the Authorization header in a header AND the body.
    return send(200, { ...vec([{ metric: { route: "/api/orders", debug: `auth was ${auth}` }, value: [1700000000, "0.5"] }]) });
  });
  other = http.createServer((req, res) => { otherSeen.push(req.headers); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(vec([{ metric: {}, value: [1, "1"] }]))); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port; oport = (other.address() as AddressInfo).port;
});
afterAll(() => { srv.close(); other.close(); });

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const metricCheck = (value: unknown, id = "m"): Check => ({ id, intent: "5xx ratio of /api/orders over 5m", method: "script", target: "prometheus", expect: { type: "metric", value } as never, severity_if_fail: "high" });
function mk(o: { prom?: Partial<PrometheusConfig>; replay?: ReplayConfig | null; resolver?: (h: string) => Promise<string> } = {}) {
  const root = mkdtempSync(join(tmpdir(), "wt-prom-"));
  const replay = o.replay === null ? undefined : o.replay ?? { allowHosts: [`prom.local:${port}`, `other.local:${oport}`], allowCidrs: ["127.0.0.1/32"] };
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, out) => writeFileSync(out, "png") },
    redactor: Redactor.fromEnv(process.env), replay, resolver: o.resolver ?? (async () => "127.0.0.1"),
    env: { PROM_LOGIN: TOKEN }, prometheus: { url: `http://prom.local:${port}`, tokenEnv: "PROM_LOGIN", timeoutMs: 1000, ...o.prom },
  });
  return { core, root };
}
async function planned(core: WalkthroughCore, checks: Check[] = [metricCheck({ op: ">", value: 0 })]) {
  const w = core.startWalkthrough({ title: "metrics", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks });
  return w.id;
}
const allFiles = (dir: string) => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((d) => d.isFile())
  .map((d) => readFileSync(join(d.parentPath ?? (d as never as { path: string }).path, d.name), "utf8")).join("\n");

describe("query_metrics (read-only Prometheus, core-executed)", () => {
  it("success: GET /api/v1/query, stored as core-executed metric evidence, hash-chained log, normal pass (not needs_review)", async () => {
    const { core } = mk();
    const id = await planned(core);
    seen.length = 0;
    const ev = await core.queryMetrics(id, { query: 'sum(rate(http_requests_total{status=~"5.."}[5m]))', checkId: "m" });
    expect(ev).toMatchObject({ kind: "metric", executedBy: "core", checkId: "m" });
    expect(ev.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(seen).toHaveLength(1);
    expect(seen[0].method).toBe("GET");
    expect(seen[0].url).toMatch(/^\/api\/v1\/query\?query=/);
    expect(seen[0].headers.authorization).toBe(`Bearer ${TOKEN}`);
    const r = await core.evaluateCheck(id, { checkId: "m", evidenceIds: [ev.id] });
    expect(r.status).toBe("pass");
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8");
    expect(log).toMatch(/"type":"metrics_query".*"executedBy":"core"/);
    expect(core.verifyCommandLog(id).ok).toBe(true);
  });
  it("threshold fail is judged automatically", async () => {
    const { core } = mk();
    const id = await planned(core, [metricCheck({ op: "<=", value: 0.01 })]);
    const ev = await core.queryMetrics(id, { query: "ratio", checkId: "m" });
    const r = await core.evaluateCheck(id, { checkId: "m", evidenceIds: [ev.id] });
    expect(r.status).toBe("fail");
    expect(r.reasons.join()).toMatch(/= 0.5, expected <= 0.01/);
  });
  it("token echoed by the server (header + body) never reaches any artifact or the HTML", async () => {
    const { core, root } = mk();
    const id = await planned(core);
    const ev = await core.queryMetrics(id, { query: "q", checkId: "m" });
    await core.evaluateCheck(id, { checkId: "m", evidenceIds: [ev.id] });
    await core.recordFinding(id, { title: "t", severity: "high", symptom: "s", root_cause_chain: [{ claim: "5xx spike", kind: "observed", evidence_ids: [ev.id] }], check_id: "m" });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toContain("metric-confirm");
    expect(readFileSync(join(core.dir(id), ev.path), "utf8")).toMatch(/auth was (Bearer )?\[REDACTED\]/); // echo present, masked
    expect(html).not.toContain(TOKEN);
    expect(allFiles(join(root, ".walkthrough"))).not.toContain(TOKEN);
  });
  it("non-success Prometheus status → inconclusive (stored, never treated as 0)", async () => {
    const { core } = mk();
    const id = await planned(core);
    const ev = await core.queryMetrics(id, { query: "err", checkId: "m" });
    const r = await core.evaluateCheck(id, { checkId: "m", evidenceIds: [ev.id] });
    expect(r.status).toBe("inconclusive");
    expect(r.reasons.join()).toMatch(/status error \(HTTP 400\) bad_data/);
  });
  it.each([["empty", /empty result/], ["nan", /non-finite value NaN/], ["inf", /non-finite value \+Inf/], ["multi", /2 series/]])("%s → inconclusive", async (q, why) => {
    const { core } = mk();
    const id = await planned(core, [metricCheck({ op: "==", value: 0 })]);
    const ev = await core.queryMetrics(id, { query: q, checkId: "m" });
    const r = await core.evaluateCheck(id, { checkId: "m", evidenceIds: [ev.id] });
    expect(r.status).toBe("inconclusive");
    expect(r.reasons.join()).toMatch(why);
  });
  it("endpoint not in the allowlist is rejected; no request sent", async () => {
    const { core } = mk({ prom: { url: "http://evil.example:9090" } });
    const id = await planned(core);
    seen.length = 0;
    await expect(core.queryMetrics(id, { query: "up" })).rejects.toThrow(/not in the replay allowlist/);
    expect(seen).toHaveLength(0);
  });
  it("needs replay allowlist and a configured endpoint", async () => {
    const a = mk({ replay: null });
    await expect(a.core.queryMetrics(await planned(a.core), { query: "up" })).rejects.toThrow(/allowHosts/);
  });
  it("metadata IP rejected (literal and via DNS), private IP rejected unless listed", async () => {
    const lit = mk({ prom: { url: "http://169.254.169.254" }, replay: { allowHosts: ["169.254.169.254"], allowCidrs: ["169.254.0.0/16"] } });
    await expect(lit.core.queryMetrics(await planned(lit.core), { query: "up" })).rejects.toThrow(/metadata/);
    const dns = mk({ resolver: async () => "169.254.169.254" });
    await expect(dns.core.queryMetrics(await planned(dns.core), { query: "up" })).rejects.toThrow(/metadata/);
    const priv = mk({ resolver: async () => "10.0.0.5", replay: { allowHosts: [`prom.local:${port}`] } });
    await expect(priv.core.queryMetrics(await planned(priv.core), { query: "up" })).rejects.toThrow(/denied/);
  });
  it("only /api/v1/query: admin / write / remote_write / other API base URLs and redirects to them are rejected", async () => {
    for (const bad of ["http://p:9090/api/v1/admin/tsdb/delete_series", "http://p:9090/api/v1/write", "http://p:9090/api/v1/remote_write", "http://p:9090/api/v1/query_range", "http://p:9090/api/v2/alerts", "http://p:9090/?x=1"])
      expect(() => promQueryUrl(bad, "up"), bad).toThrow();
    expect(promQueryUrl("https://h/prometheus/", "up").pathname).toBe("/prometheus/api/v1/query");
    const { core } = mk();
    const id = await planned(core);
    await expect(core.queryMetrics(id, { query: "redir-admin" })).rejects.toThrow(/only \/api\/v1\/query is allowed/);
  });
  it("redirect to another (allowlisted) origin drops the token", async () => {
    const { core } = mk();
    const id = await planned(core);
    otherSeen.length = 0;
    await core.queryMetrics(id, { query: "redir-other" });
    expect(otherSeen).toHaveLength(1);
    expect(otherSeen[0].authorization).toBeUndefined();
  });
  it("limits: query length, response size, timeout", async () => {
    const { core } = mk();
    const id = await planned(core);
    await expect(core.queryMetrics(id, { query: "x".repeat(2001) })).rejects.toThrow(/longer than 2000/);
    const big = mk({ prom: { maxResponseBytes: 64 * 1024 } });
    await expect(big.core.queryMetrics(await planned(big.core), { query: "big" })).rejects.toThrow(/larger than 65536 bytes/);
    const t0 = Date.now();
    await expect(core.queryMetrics(id, { query: "slow" })).rejects.toThrow(/timed out/);
    expect(Date.now() - t0).toBeLessThan(2500);
  });
  it("plan_checks rejects malformed metric expectations; judge ignores non-metric evidence", async () => {
    const { core } = mk();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    for (const v of [{}, { op: "~", value: 1 }, { op: ">", value: "1" }, { op: ">", value: Infinity }]) await expect(core.planChecks(w.id, { goal: "g", checks: [metricCheck(v)] })).rejects.toThrow();
    expect(judgeMetric({ op: ">", value: 0 }, ['{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"5"]}]}}']).status).toBe("inconclusive");
  });
});
