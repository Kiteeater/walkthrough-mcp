import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, WalkthroughCore, type Check, type PrometheusConfig, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const TOKEN = "promWATCHlogin4242";
const S = { labelKey: "LABELapikeySECRET1", annotUrl: "ANNOTqueryTOKEN2", annotBearer: "ANNOTbearerVALUE3", labelLf: "sk-lf-LABELlangfuse4", labelUrl: "LABELurlSIG5" };
const alert = (name: string, state: string, labels: Record<string, string> = {}, annotations: Record<string, string> = {}) =>
  ({ labels: { alertname: name, ...labels }, annotations, state, activeAt: "2026-10-12T20:00:00Z", value: "1" });
let mode: "firing" | "quiet" | "pending" | "secrets" | "redir-admin" | "error" = "firing";
let srv: http.Server, port = 0;
const seen: { url?: string; method?: string }[] = [];
beforeAll(async () => {
  srv = http.createServer((req, res) => {
    seen.push({ url: req.url, method: req.method });
    const auth = String(req.headers.authorization ?? "");
    const send = (code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json", "x-debug-echo": auth }); res.end(JSON.stringify(body)); };
    if (req.url !== "/api/v1/alerts") return send(404, { status: "error" });
    if (mode === "redir-admin") { res.writeHead(302, { location: "/api/v1/admin/tsdb/delete_series" }); return res.end(); }
    if (mode === "error") return send(503, { status: "error", error: "unavailable" });
    const alerts = mode === "quiet" ? [] : mode === "pending" ? [alert("HighOrders5xx", "pending", { route: "/api/orders" })]
      : mode === "secrets" ? [alert("HighOrders5xx", "firing", { route: "/api/orders", api_key: S.labelKey, lf: S.labelLf, dash: `https://grafana.example/d?sig=${S.labelUrl}&org=1`, debug_auth: auth },
          { summary: `5xx on /api/orders (${auth})`, runbook_url: `https://runbook.example/orders?token=${S.annotUrl}&page=1`, description: `curl -H "Authorization: Bearer ${S.annotBearer}"` })]
      : [alert("HighOrders5xx", "firing", { route: "/api/orders", severity: "critical" }, { summary: "5xx ratio on /api/orders above 10%" }),
         alert("DiskAlmostFull", "firing", { instance: "db-1", severity: "warning" }), alert("SlowCheckout", "pending", { route: "/api/checkout" })];
    send(200, { status: "success", data: { alerts } });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const orders: Check = { id: "orders", intent: "GET /api/orders 2xx", method: "http", target: "GET /api/orders", expect: { type: "status", value: 200 }, severity_if_fail: "high", alertMatchers: [{ alertname: "HighOrders5xx" }, { route: "~/api/orders.*" }] };
const other: Check = { id: "health", intent: "health", method: "http", target: "GET /health", expect: { type: "status", value: 200 }, severity_if_fail: "low" };
function mk(o: { prom?: Partial<PrometheusConfig>; replay?: ReplayConfig } = {}) {
  const root = mkdtempSync(join(tmpdir(), "wt-alerts-"));
  const sleeps: number[] = [];
  let t = Date.parse("2026-10-12T20:00:00Z");
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, out) => writeFileSync(out, "png") },
    redactor: Redactor.fromEnv(process.env), replay: o.replay ?? { allowHosts: [`prom.local:${port}`], allowCidrs: ["127.0.0.1/32"] },
    resolver: async () => "127.0.0.1", env: { PROM_LOGIN: TOKEN }, prometheus: { url: `http://prom.local:${port}`, tokenEnv: "PROM_LOGIN", timeoutMs: 2000, ...o.prom },
    now: () => new Date(t), sleep: async (ms) => { sleeps.push(ms); t += ms; },
  });
  return { core, root, sleeps };
}
async function planned(core: WalkthroughCore, checks: Check[] = [orders, other]) {
  const w = core.startWalkthrough({ title: "alerts", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks });
  return w.id;
}
const allFiles = (dir: string) => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((d) => d.isFile())
  .map((d) => readFileSync(join(d.parentPath ?? (d as never as { path: string }).path, d.name), "utf8")).join("\n");

describe("watch_alerts (read-only GET /api/v1/alerts, core-executed)", () => {
  it("firing alert matching a check → finding; unmatched firing listed separately; pending ignored; hash-chained log", async () => {
    mode = "firing";
    const { core } = mk();
    const id = await planned(core);
    seen.length = 0;
    const r = await core.watchAlerts(id, { windowS: 60, intervalS: 15 });
    expect(seen.every((s) => s.method === "GET" && s.url === "/api/v1/alerts")).toBe(true);
    expect(r.evidence).toMatchObject({ kind: "alert", executedBy: "core" });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ title: "Alert HighOrders5xx firing", severity: "critical", checkId: "orders", kind: "observed" });
    expect(r.watch.unmatched.map((u) => u.alertname)).toEqual(["DiskAlmostFull"]);
    expect(r.watch.matched).toEqual([{ alertname: "HighOrders5xx", checkIds: ["orders"], findingId: r.findings[0].id, attached: false }]);
    expect(r.watch.pendingSeen).toBe(1);
    const w = core.load(id);
    expect(w.findings).toHaveLength(1); // DiskAlmostFull NOT force-attached
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8");
    expect(log).toMatch(/"type":"alerts_poll"/); expect(log).toMatch(/"type":"alerts_watch"/);
    expect(core.verifyCommandLog(id).error).toBeUndefined();
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toMatch(/class="alert-confirm" data-alert="HighOrders5xx"/);
    expect(html).toMatch(/class="unmatched-alerts" data-unmatched="1"/);
    expect(html).toContain("DiskAlmostFull");
  });
  it("attaches to the existing finding of a matched check instead of creating a new one", async () => {
    mode = "firing";
    const { core } = mk();
    const id = await planned(core);
    const ev = await core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    const f = await core.recordFinding(id, { title: "500", severity: "high", symptom: "s", check_id: "orders", root_cause_chain: [{ claim: "500", kind: "observed", evidence_ids: [ev.id] }, { claim: "bug", kind: "inferred", evidence_ids: [] }] });
    const r = await core.watchAlerts(id, { windowS: 10, intervalS: 5 });
    expect(r.findings).toHaveLength(0);
    expect(r.watch.matched[0]).toMatchObject({ findingId: f.id, attached: true });
    const after = core.load(id).findings![0];
    expect(after.root_cause_chain[1].evidence_ids).toEqual([r.evidence.id]);
    expect(after.root_cause_chain[1].claim).toMatch(/alert HighOrders5xx firing/);
  });
  it("quiet window → core-executed 'no alerts in window' evidence with start/end; polls bounded by window/interval", async () => {
    mode = "quiet";
    const { core, sleeps } = mk();
    const id = await planned(core);
    const r = await core.watchAlerts(id, { windowS: 30, intervalS: 10 });
    expect(r.findings).toHaveLength(0);
    expect(r.watch.polls).toBe(4);
    expect(sleeps).toEqual([10000, 10000, 10000]);
    const doc = JSON.parse(readFileSync(join(core.dir(id), r.evidence.path), "utf8"));
    expect(doc.note).toBe("no alerts in window");
    expect(doc.window).toMatchObject({ start: "2026-10-12T20:00:00.000Z", end: "2026-10-12T20:00:30.000Z" });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toContain("no alerts in window");
  });
  it("pending (not firing) alerts are not counted", async () => {
    mode = "pending";
    const { core } = mk();
    const r = await core.watchAlerts(await planned(core), { windowS: 2, intervalS: 1 });
    expect(r.findings).toHaveLength(0);
    expect(r.watch.unmatched).toHaveLength(0);
    expect(r.watch.pendingSeen).toBe(1);
  });
  it("window / interval caps", async () => {
    mode = "quiet";
    const { core } = mk();
    const id = await planned(core);
    await expect(core.watchAlerts(id, { windowS: 901 })).rejects.toThrow(/window_s must be 1-900/);
    await expect(core.watchAlerts(id, { windowS: 0 })).rejects.toThrow(/window_s/);
    await expect(core.watchAlerts(id, { windowS: 60, intervalS: 0 })).rejects.toThrow(/interval_s must be 1-60/);
    await expect(core.watchAlerts(id, { windowS: 60, intervalS: 61 })).rejects.toThrow(/interval_s/);
    const r = await core.watchAlerts(id, { windowS: 900, intervalS: 1 });
    expect(r.watch.polls).toBe(120); // hard cap on polls
  });
  it("non-allowlisted endpoint rejected; no request sent", async () => {
    const { core } = mk({ prom: { url: "http://evil.example:9090" } });
    seen.length = 0;
    await expect(core.watchAlerts(await planned(core), { windowS: 5, intervalS: 5 })).rejects.toThrow(/not in the replay allowlist/);
    expect(seen).toHaveLength(0);
  });
  it("write/admin endpoints rejected (base URL and redirect hop); bad matchers rejected", async () => {
    for (const bad of ["/api/v1/admin/tsdb/delete_series", "/api/v1/write", "/api/v1/alerts"]) {
      const { core } = mk({ prom: { url: `http://prom.local:${port}${bad}` } });
      await expect(core.watchAlerts(await planned(core), { windowS: 5, intervalS: 5 })).rejects.toThrow(/not an API path/);
    }
    mode = "redir-admin";
    const { core } = mk();
    const id = await planned(core);
    await expect(core.watchAlerts(id, { windowS: 5, intervalS: 5 })).rejects.toThrow(/only \/api\/v1\/alerts is allowed/);
    await expect(core.watchAlerts(id, { windowS: 5, intervalS: 5, matchers: [{ checkId: "orders", labels: { route: "~(a+)+" } }] })).rejects.toThrow(/ReDoS/);
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await expect(core.planChecks(w.id, { goal: "g", checks: [{ ...orders, alertMatchers: [{}] }] })).rejects.toThrow(/matcher/);
  });
  it("non-success alerts response is an error, not 'no alerts'", async () => {
    mode = "error";
    const { core } = mk();
    await expect(core.watchAlerts(await planned(core), { windowS: 5, intervalS: 5 })).rejects.toThrow(/status error \(HTTP 503\)/);
  });
  it("labels/annotations redacted (secret keys, URL query tokens, bearer, generic keys) + echoed token: absent from all artifacts and HTML", async () => {
    mode = "secrets";
    const { core, root } = mk();
    const id = await planned(core);
    const r = await core.watchAlerts(id, { windowS: 5, intervalS: 5 });
    expect(r.findings).toHaveLength(1);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    const all = allFiles(join(root, ".walkthrough"));
    for (const [k, v] of Object.entries({ ...S, TOKEN })) { expect(html, k).not.toContain(v); expect(all, k).not.toContain(v); }
    expect(all).toContain("page=1"); expect(all).toContain("org=1"); // non-secret params survive
    expect(all).toContain("HighOrders5xx");
  });
});
