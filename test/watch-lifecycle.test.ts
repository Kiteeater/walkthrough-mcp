import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, WalkthroughCore, type Check, type Sandbox } from "../src/core/index.js";
import { acquireFileLock } from "../src/core/lockfile.js";
import { SB } from "./helpers.js";

let srv: http.Server, port = 0;
beforeAll(async () => {
  srv = http.createServer((req, res) => {
    res.writeHead(req.url === "/api/v1/alerts" ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "success", data: { alerts: [{ labels: { alertname: "HighOrders5xx", route: "/api/orders" }, annotations: {}, state: "firing", activeAt: "2026-10-12T20:00:00Z" }] } }));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const orders: Check = { id: "orders", intent: "GET /api/orders 2xx", method: "http", target: "GET /api/orders", expect: { type: "status", value: 200 }, severity_if_fail: "high", alertMatchers: [{ alertname: "HighOrders5xx" }] };
function mk(root = mkdtempSync(join(tmpdir(), "wt-life-"))) {
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, out) => writeFileSync(out, "png") }, redactor: Redactor.fromEnv(process.env),
    replay: { allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] }, prometheus: { url: `http://127.0.0.1:${port}`, timeoutMs: 2000 }, env: {},
  });
  return { core, root };
}
const sha = (f: string) => createHash("sha256").update(readFileSync(f)).digest("hex");
const tail = (core: WalkthroughCore, id: string) => { const f = join(core.dir(id), "commands.jsonl"); return existsSync(f) ? readFileSync(f, "utf8") : ""; };

describe("after sign_off the walkthrough is read-only", () => {
  it("every write path is rejected; report, walkthrough.json and command-log tail unchanged; a late poller writes nothing", async () => {
    const { core } = mk();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    const id = w.id;
    await core.planChecks(id, { goal: "g", checks: [orders] });
    const ev = await core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    const watch = await core.startWatch(id, { windowS: 30, intervalS: 1, background: "none" });
    await core.signOff(id, { decision: "reject" });
    expect(core.readWatch(watch.id).status).toBe("finalized"); // finalized BEFORE signing
    const report = renderWalkthrough(core, id);
    const before = { report: sha(report), wt: sha(join(core.dir(id), "walkthrough.json")), log: tail(core, id), watch: readFileSync(join(core.root, ".walkthrough", "watches", `${watch.id}.json`), "utf8") };
    const attempts: [string, () => Promise<unknown>][] = [
      ["capture_evidence", () => core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: "x" })],
      ["plan_checks append", () => core.planChecks(id, { goal: "g", append: true, triggeringEvidenceId: ev.id, checks: [{ ...orders, id: "o2" }] })],
      ["evaluate_check", () => core.evaluateCheck(id, { checkId: "orders", evidenceIds: [ev.id] })],
      ["record_finding", () => core.recordFinding(id, { title: "x", severity: "high", symptom: "s", check_id: "orders", root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: [ev.id] }] })],
      ["record_claim", () => core.recordClaim(id, { claim: "c", kind: "inferred", evidence_ids: [] } as never)],
      ["link_source", () => core.linkSource(id, { file: "x.js", line: 1 })],
      ["start_watch", () => core.startWatch(id, { windowS: 5, intervalS: 1 })],
      ["import_mcp_result", () => core.importMcpResult(id, { checkId: "orders", connector: "c", tool: "t", params: {}, result: {} } as never)],
      ["replay_request", () => core.replayHar(id, { checkId: "orders", evidenceId: ev.id })],
      ["query_metrics", () => core.queryMetrics(id, { query: "up" })],
      ["capture_page", () => core.capturePage(id, { url: `http://127.0.0.1:${port}/`, checkId: "orders" })],
      ["run_cli", () => core.runCli(id, { argv: ["kubectl", "get", "pods"] } as never)],
      ["run_in_sandbox", () => core.runInSandbox(id, "exec", "true")],
      ["sign_off again", () => core.signOff(id, { decision: "accept" })],
    ];
    for (const [name, f] of attempts) await expect(f(), name).rejects.toThrow(/signed off; it is read-only/);
    await expect(core.collectWatch(watch.id)).rejects.toThrow(/already collected|signed off/);
    await core.runPoller(watch.id); // a poller waking up after sign-off
    expect(readFileSync(join(core.root, ".walkthrough", "watches", `${watch.id}.json`), "utf8")).toBe(before.watch);
    expect(sha(renderWalkthrough(core, id))).toBe(before.report);
    expect(sha(join(core.dir(id), "walkthrough.json"))).toBe(before.wt);
    expect(tail(core, id)).toBe(before.log);
    expect(core.verifyCommandLog(id).error).toBeUndefined();
  });

  it("sign_off racing background writes (separate core instance = separate lock holder): nothing lands after the signature", async () => {
    for (let iter = 0; iter < 15; iter++) {
      const a = mk(); const b = mk(a.root); // two writers sharing only the filesystem lock
      const id = a.core.startWalkthrough({ title: "race", sandbox: SB }).id;
      await a.core.planChecks(id, { goal: "g", checks: [orders] });
      let stop = false;
      const writer = (async () => {
        let n = 0;
        while (!stop) {
          try { const e = await b.core.captureEvidence(id, { type: "submit", checkId: "orders", kind: "http", source: { tool: "t" }, content: `HTTP/1.1 500 #${n++}` });
                await b.core.evaluateCheck(id, { checkId: "orders", evidenceIds: [e.id] }); }
          catch (e) { if (!/signed off/.test(String(e))) throw e; }
          await new Promise((r) => setImmediate(r));
        }
      })();
      await new Promise((r) => setTimeout(r, 5 + (iter % 5) * 3));
      await a.core.signOff(id, { decision: "reject" });
      const snap = { wt: sha(join(a.core.dir(id), "walkthrough.json")), log: tail(a.core, id), report: sha(renderWalkthrough(a.core, id)) };
      await new Promise((r) => setTimeout(r, 30));
      stop = true; await writer;
      expect(sha(join(a.core.dir(id), "walkthrough.json"))).toBe(snap.wt);
      expect(tail(a.core, id)).toBe(snap.log);
      expect(sha(renderWalkthrough(a.core, id))).toBe(snap.report);
      expect(a.core.verifyCommandLog(id).error).toBeUndefined();
      expect(a.core.load(id).signoff?.decision).toBe("reject");
    }
  }, 30_000);
});

describe("cross-process lockfile", () => {
  it("lock content is {pid, host, ts}; a crashed owner's lock (dead pid) is reclaimed promptly", async () => {
    const f = join(mkdtempSync(join(tmpdir(), "wt-lock-")), "x.lock");
    writeFileSync(f, JSON.stringify({ pid: 2 ** 22 + 777, host: hostname(), ts: Date.now() }));
    const t0 = Date.now();
    const release = await acquireFileLock(f, { timeoutMs: 2000 });
    expect(Date.now() - t0).toBeLessThan(500);
    expect(JSON.parse(readFileSync(f, "utf8"))).toMatchObject({ pid: process.pid, host: hostname() });
    release();
    expect(existsSync(f)).toBe(false);
  });
  it("a fresh lock held by a live pid is respected (bounded wait, clear error); an old one is reclaimed", async () => {
    const f = join(mkdtempSync(join(tmpdir(), "wt-lock-")), "x.lock");
    writeFileSync(f, JSON.stringify({ pid: process.ppid, host: hostname(), ts: Date.now() }));
    await expect(acquireFileLock(f, { timeoutMs: 200 })).rejects.toThrow(new RegExp(`timed out after 200 ms .*held by pid ${process.ppid} on ${hostname()}`));
    writeFileSync(f, JSON.stringify({ pid: process.ppid, host: "other-host", ts: Date.now() - 11 * 60_000 }));
    (await acquireFileLock(f, { timeoutMs: 500 }))();
  });
  it("many concurrent waiters on a stale lock: exactly one holds it at a time", async () => {
    const f = join(mkdtempSync(join(tmpdir(), "wt-lock-")), "x.lock");
    writeFileSync(f, JSON.stringify({ pid: 2 ** 22 + 778, host: hostname(), ts: Date.now() }));
    let inside = 0, max = 0;
    await Promise.all(Array.from({ length: 8 }, async () => {
      const rel = await acquireFileLock(f, { timeoutMs: 5000 });
      inside++; max = Math.max(max, inside); await new Promise((r) => setTimeout(r, 5)); inside--; rel();
    }));
    expect(max).toBe(1);
  });
});

describe("CLI smoke: watch start / collect share the core", () => {
  const CLI = resolve("dist/cli/index.js");
  it("start prints a watch id and a detached poller polls; collect turns it into evidence", async () => {
    const { core, root } = mk();
    writeFileSync(join(root, "walkthrough.config.json"), JSON.stringify({ replay: { allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] } }));
    const id = core.startWalkthrough({ title: "cli", sandbox: SB }).id;
    await core.planChecks(id, { goal: "g", checks: [orders] });
    const env = { ...process.env, WALKTHROUGH_PROMETHEUS_URL: `http://127.0.0.1:${port}` };
    const s = spawnSync(process.execPath, [CLI, "watch", "start", id, "--window", "20", "--interval", "1", "--root", root], { encoding: "utf8", env, timeout: 20_000 });
    expect(s.status, s.stderr).toBe(0);
    const { watchId } = JSON.parse(s.stdout);
    expect(watchId).toMatch(/^w_[0-9a-f]{16}$/);
    for (let i = 0; i < 50 && core.readWatch(watchId).polls.length < 2; i++) await new Promise((r) => setTimeout(r, 200));
    if (core.readWatch(watchId).polls.length < 2) throw new Error(`detached poller: expected >= 2 polls within 10 s, got ${core.readWatch(watchId).polls.length}`);
    expect(core.readWatch(watchId).polls.length).toBeGreaterThanOrEqual(2);
    const c = spawnSync(process.execPath, [CLI, "watch", "collect", watchId, "--root", root], { encoding: "utf8", env, timeout: 30_000 });
    expect(c.status, c.stderr).toBe(0);
    const out = JSON.parse(c.stdout);
    expect(out.watch).toMatchObject({ watchId, outcome: "stopped_early", finalizedBy: "collect" });
    expect(out.findings[0].title).toBe("Alert HighOrders5xx firing");
    expect(core.verifyCommandLog(id).error).toBeUndefined();
    const bad = spawnSync(process.execPath, [CLI, "watch", "collect", "../../etc/passwd", "--root", root], { encoding: "utf8", env });
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/invalid watch id/);
  }, 40_000);
});
