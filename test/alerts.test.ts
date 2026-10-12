import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, MAX_ACTIVE_WATCHES, WalkthroughCore, type Check, type PrometheusConfig, type ReplayConfig, type Sandbox } from "../src/core/index.js";
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
function mk(o: { prom?: Partial<PrometheusConfig>; replay?: ReplayConfig; realTime?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "wt-alerts-"));
  const sleeps: number[] = [];
  let t = Date.parse("2026-10-12T20:00:00Z");
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, out) => writeFileSync(out, "png") },
    redactor: Redactor.fromEnv(process.env), replay: o.replay ?? { allowHosts: [`prom.local:${port}`], allowCidrs: ["127.0.0.1/32"] },
    resolver: async () => "127.0.0.1", env: { PROM_LOGIN: TOKEN }, prometheus: { url: `http://prom.local:${port}`, tokenEnv: "PROM_LOGIN", timeoutMs: 2000, ...o.prom },
    ...(o.realTime ? {} : { now: () => new Date(t), sleep: async (ms: number) => { sleeps.push(ms); t += ms; } }),
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
    expect(r.watch.matched).toEqual([expect.objectContaining({ alertname: "HighOrders5xx", checkIds: ["orders"], findingId: r.findings[0].id, attached: false })]);
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
    expect(after.root_cause_chain).toEqual(f.root_cause_chain); // chain unchanged by the alert
    expect(after.corroborating).toEqual([expect.objectContaining({ kind: "alert", alertname: "HighOrders5xx", evidence_ids: [r.evidence.id], alsoMatched: [] })]);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toMatch(/class="corroborating" data-corroborating="1"><b>同时观测到的信号/);
  });
  it("an alert matching several checks shows 'also matched X, Y'", async () => {
    mode = "firing";
    const { core } = mk();
    const c2 = { ...other, id: "orders-list", alertMatchers: [{ alertname: "HighOrders5xx" }] };
    const c3 = { ...other, id: "orders-admin", alertMatchers: [{ route: "/api/orders" }] };
    const id = await planned(core, [orders, c2, c3]);
    const ev = await core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    await core.recordFinding(id, { title: "500", severity: "high", symptom: "s", check_id: "orders", root_cause_chain: [{ claim: "500", kind: "observed", evidence_ids: [ev.id] }] });
    await core.watchAlerts(id, { windowS: 1, intervalS: 1 });
    expect(core.load(id).findings![0].corroborating![0].alsoMatched).toEqual(["orders-list", "orders-admin"]);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toContain('<span class="also-matched" data-also="orders-list,orders-admin">also matched orders-list, orders-admin</span>');
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
    const rr = await core.watchAlerts(id, { windowS: 5, intervalS: 5 }); // poll errors are recorded, never a quiet window
    expect(rr.watch.errors?.[0]).toMatch(/only \/api\/v1\/alerts is allowed/);
    expect(JSON.parse(readFileSync(join(core.dir(id), rr.evidence.path), "utf8")).note).toMatch(/no successful poll.*NOT a quiet window/);
    await expect(core.watchAlerts(id, { windowS: 5, intervalS: 5, matchers: [{ checkId: "orders", labels: { route: "~(a+)+" } }] })).rejects.toThrow(/ReDoS/);
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await expect(core.planChecks(w.id, { goal: "g", checks: [{ ...orders, alertMatchers: [{}] }] })).rejects.toThrow(/matcher/);
  });
  it("non-success alerts response is an error, not 'no alerts'", async () => {
    mode = "error";
    const { core } = mk();
    const id = await planned(core);
    const r = await core.watchAlerts(id, { windowS: 5, intervalS: 5 });
    expect(r.watch.errors?.join()).toMatch(/error|503/);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).not.toContain("no alerts in window · 窗口内无告警");
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

describe("start_watch / collect_watch: background polling, no long lock", () => {
  it("evaluate_check during an active watch is not blocked; concurrent log writes keep the hash chain valid", async () => {
    mode = "firing";
    const { core } = mk({ realTime: true });
    const id = await planned(core);
    const s = await core.startWatch(id, { windowS: 6, intervalS: 1 });
    expect(s.id).toMatch(/^w_[0-9a-f]{16}$/);
    const t0 = Date.now();
    const ev = await core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    const r = await core.evaluateCheck(id, { checkId: "orders", evidenceIds: [ev.id] });
    expect(r.status).toBe("fail");
    // more log writers while the poller runs: append-only plan entries
    await core.planChecks(id, { goal: "g", append: true, triggeringEvidenceId: ev.id, checks: [{ ...other, id: "extra-1", alertMatchers: undefined }] });
    await new Promise((res) => setTimeout(res, 1200));
    await core.planChecks(id, { goal: "g", append: true, triggeringEvidenceId: ev.id, checks: [{ ...other, id: "extra-2", alertMatchers: undefined }] });
    expect(Date.now() - t0).toBeLessThan(3000); // well before the 6 s window ends
    expect(core.readWatch(s.id).polls.length).toBeGreaterThanOrEqual(1);
    const out = await core.collectWatch(s.id);
    expect(out.watch.outcome).toBe("stopped_early");
    expect(out.watch.polls).toBeGreaterThanOrEqual(2);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(core.verifyCommandLog(id).error).toBeUndefined();
    await expect(core.collectWatch(s.id)).rejects.toThrow(/already collected/);
  }, 15_000);
  it("records poll timestamps, activeAt and first-seen time", async () => {
    mode = "firing";
    const { core } = mk();
    const id = await planned(core);
    const r = await core.watchAlerts(id, { windowS: 2, intervalS: 1 });
    expect(r.watch.matched[0]).toMatchObject({ activeAt: "2026-10-12T20:00:00Z", firstSeenAt: "2026-10-12T20:00:00.000Z" });
    const doc = JSON.parse(readFileSync(join(core.dir(id), r.evidence.path), "utf8"));
    expect(doc.polls.map((p: { at: string }) => p.at)).toEqual(["2026-10-12T20:00:00.000Z", "2026-10-12T20:00:01.000Z", "2026-10-12T20:00:02.000Z"]);
  });
  it("dead poller → 'interrupted' with partial polls, never 'no alerts in window'; marked in the report", async () => {
    mode = "quiet";
    const { core, root } = mk();
    const id = await planned(core);
    const s = await core.startWatch(id, { windowS: 60, intervalS: 5, background: "none" }); // no poller runs
    const f = join(root, ".walkthrough", "watches", `${s.id}.json`);
    const st = JSON.parse(readFileSync(f, "utf8"));
    st.polls.push({ at: "2026-10-12T20:00:00.000Z", httpStatus: 200, firing: [], pending: 0 });
    st.pid = 2 ** 22 + 12345; // a pid that is not alive
    writeFileSync(f, JSON.stringify(st));
    const r = await core.collectWatch(s.id);
    expect(r.watch.outcome).toBe("interrupted");
    const doc = JSON.parse(readFileSync(join(core.dir(id), r.evidence.path), "utf8"));
    expect(doc.note).toMatch(/^interrupted: poller stopped after 1 poll/);
    expect(doc.note).not.toMatch(/no alerts in window/);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toMatch(/class="alert-window interrupted" data-outcome="interrupted"/);
    expect(html).not.toContain("no alerts in window · 窗口内无告警");
  });
  it("sign_off auto-finalizes open watches; interrupted ones are visible on the sign-off panel", async () => {
    mode = "firing";
    const { core, root } = mk({ realTime: true });
    const id = await planned(core);
    const live = await core.startWatch(id, { windowS: 30, intervalS: 1 });
    const dead = await core.startWatch(id, { windowS: 30, intervalS: 1, background: "none" });
    const f = join(root, ".walkthrough", "watches", `${dead.id}.json`);
    const st = JSON.parse(readFileSync(f, "utf8")); st.pid = 2 ** 22 + 54321; writeFileSync(f, JSON.stringify(st));
    await new Promise((res) => setTimeout(res, 300));
    const so = await core.signOff(id, { decision: "reject", comment: "c" });
    expect(so.autoFinalizedWatches).toEqual(expect.arrayContaining([{ watchId: live.id, outcome: "stopped_early" }, { watchId: dead.id, outcome: "interrupted" }]));
    expect(core.readWatch(live.id).status).toBe("finalized");
    expect(core.readWatch(dead.id).status).toBe("finalized");
    const w = core.load(id);
    expect(w.alertWatches!.map((a) => a.finalizedBy)).toEqual(["sign_off", "sign_off"]);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    const panel = html.slice(html.indexOf('class="signoff"'), html.indexOf("</section>", html.indexOf('class="signoff"')));
    expect(panel).toMatch(/class="auto-finalized" data-auto-finalized="2"/);
    expect(panel).toMatch(new RegExp(`class="aw interrupted" data-outcome="interrupted">${dead.id} \\(<b>interrupted</b>`));
    expect(core.verifyCommandLog(id).error).toBeUndefined();
  }, 15_000);
  it("watch ids are core-generated and strictly validated (no path traversal)", async () => {
    const { core } = mk();
    for (const bad of ["../../etc/passwd", "/etc/passwd", "w_../x", "w_0123456789abcdeg", "W_0123456789abcdef", "w_0123456789abcdef/../x", ""])
      await expect(core.collectWatch(bad), bad).rejects.toThrow(/invalid watch id/);
    await expect(core.collectWatch("w_0123456789abcdef")).rejects.toThrow(/watch not found/);
  });
  it(`at most ${MAX_ACTIVE_WATCHES} active watches`, async () => {
    mode = "quiet";
    const { core } = mk();
    const id = await planned(core);
    const ids = [];
    for (let i = 0; i < MAX_ACTIVE_WATCHES; i++) ids.push((await core.startWatch(id, { windowS: 60, intervalS: 5, background: "none" })).id);
    await expect(core.startWatch(id, { windowS: 60, intervalS: 5, background: "none" })).rejects.toThrow(/too many active watches \(4\/4\)/);
  });
});
