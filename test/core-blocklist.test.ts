// Core blocklist (34.142.135.39): refused on every outbound path even when allowlisted, incl. via DNS.
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
const require_ = createRequire(import.meta.url);
import { CliRejectedError, Redactor, ReplayRejectedError, WalkthroughCore, type ConnectorConfig, type Sandbox } from "../src/core/index.js";
import { guardedGet, guardedRequest, replayRequest } from "../src/core/egress/fetch.js";
import { addTestCoreBlocked, checkHop, CORE_BLOCKED_IPS, ipProblem } from "../src/core/egress/policy.js";
import { assertNoCoreBlockedTargets, hostCandidates } from "../src/core/egress/targets.js";
import { guardedWebSocket } from "../src/core/egress/ws.js";
import { waitForUrl } from "../src/core/flow.js";
import { promInstantQuery } from "../src/core/metrics.js";
import { httpSource } from "../src/core/sources.js";
import { SB } from "./helpers.js";

const BAD = "34.142.135.39";
const toBad = async () => BAD;
// Allowlisted on purpose (host, IP literal, CIDR, even 0.0.0.0/0): the core blocklist must still win.
const cfg = { allowHosts: [BAD, `${BAD}:8080`, "evil.test", "evil.test:8080", "ok.test"], allowCidrs: [`${BAD}/32`, "0.0.0.0/0"] };
const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };

describe("core blocklist: IP policy", () => {
  it("is not configurable and contains the address", () => {
    expect(CORE_BLOCKED_IPS).toEqual([BAD]);
    expect(Object.isFrozen(CORE_BLOCKED_IPS)).toBe(true);
  });
  it("ipProblem refuses it even with allowCidrs covering it, in IPv4-mapped / NAT64 / 6to4 forms too", () => {
    for (const ip of [BAD, `::ffff:${BAD}`, "::ffff:228e:8727", "64:ff9b::228e:8727", "2002:228e:8727::1"]) expect(ipProblem(ip, cfg.allowCidrs), ip).toMatch(/core blocklist/);
    expect(ipProblem("34.142.135.40", cfg.allowCidrs)).toBeUndefined();
  });
  it("checkHop: literal URL and a hostname whose DNS answer is the address", async () => {
    await expect(checkHop(cfg, new URL(`http://${BAD}/`), toBad)).rejects.toThrow(/core blocklist/);
    await expect(checkHop(cfg, new URL("https://evil.test/"), toBad)).rejects.toThrow(/core blocklist/);
  });
});

describe("core blocklist: HTTP / WebSocket / replay / metrics / capture_page", () => {
  it("HTTP (guardedGet, guardedRequest, replayRequest) refused before any connection", async () => {
    await expect(guardedGet(cfg, `http://${BAD}/`, { resolver: toBad })).rejects.toBeInstanceOf(ReplayRejectedError);
    await expect(guardedRequest(cfg, "http://evil.test:8080/x", { resolver: toBad })).rejects.toThrow(/core blocklist/);
    await expect(replayRequest(cfg, { method: "GET", url: "http://evil.test/" }, { resolver: toBad })).rejects.toThrow(/core blocklist/);
  });
  it("a redirect hop that resolves to it is refused", async () => {
    // first hop fine (ok.test → 127.0.0.1 server), second hop evil.test → BAD
    const http = await import("node:http");
    const srv = http.createServer((_q, r) => { r.writeHead(302, { location: "http://evil.test/next" }); r.end(); });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    try {
      const c = { allowHosts: [`ok.test:${port}`, "evil.test"], allowCidrs: ["127.0.0.1/32", `${BAD}/32`] };
      await expect(replayRequest(c, { method: "GET", url: `http://ok.test:${port}/` }, { resolver: async (h) => (h === "evil.test" ? BAD : "127.0.0.1") })).rejects.toThrow(/core blocklist/);
    } finally { srv.close(); }
  });
  it("WebSocket (ws/wss, literal and via DNS)", async () => {
    await expect(guardedWebSocket(cfg, `ws://${BAD}/`, { resolver: toBad })).rejects.toThrow(/core blocklist/);
    await expect(guardedWebSocket(cfg, "wss://evil.test/", { resolver: toBad })).rejects.toThrow(/core blocklist/);
  });
  it("query_metrics endpoint resolving to it", async () => {
    await expect(promInstantQuery({ url: "http://evil.test:8080" }, cfg, "up", { resolver: toBad })).rejects.toThrow(/core blocklist/);
  });
  it("capture_page: refused before the browser starts (literal and via DNS)", async () => {
    let called = 0;
    const root = mkdtempSync(join(tmpdir(), "wt-cb-"));
    const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, redactor: new Redactor([]), resolver: toBad, replay: cfg,
      capturer: { screenshot: async () => undefined, page: async () => { called++; throw new Error("must not run"); } } });
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.planChecks(w.id, { goal: "g", checks: [{ id: "p", intent: "p", method: "ui", target: "x", expect: { type: "ui", value: { text: { contains: "x" } } }, severity_if_fail: "high" }] });
    for (const url of [`http://${BAD}/`, "http://evil.test/"]) await expect(core.capturePage(w.id, { checkId: "p", url })).rejects.toThrow(/core blocklist/);
    expect(called).toBe(0);
  });
});

describe("core blocklist: run_cli targets and mongo", () => {
  function fake(dir: string): string {
    const p = join(dir, "fakecli");
    writeFileSync(p, `#!/usr/bin/env node\nif(process.argv[2]==="--version"){console.log("1");process.exit(0)}\nrequire("fs").writeFileSync(require("path").join(__dirname,"RAN"),"1");console.log("ran")\n`);
    chmodSync(p, 0o755);
    return p;
  }
  function mk(connectors: ConnectorConfig[], resolver = async (h: string) => (h.endsWith("evil.test") ? BAD : "127.0.0.1")) {
    const root = mkdtempSync(join(tmpdir(), "wt-cbcli-"));
    const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async () => undefined }, redactor: new Redactor([]), resolver, connectors });
    return { core, start: () => core.startWalkthrough({ title: "t", sandbox: { cwd: root, up: "true", down: "true" } }).id };
  }
  it("argv value naming it (literal, host:port, URL, glued) or a host resolving to it → refused, binary never runs", async () => {
    const bin = mkdtempSync(join(tmpdir(), "wt-cbbin-"));
    const c: ConnectorConfig = { name: "tool", binary: fake(bin), allow: [["get"]], args: { get: ["--host", "--url"] } };
    const { core, start } = mk([c]);
    const id = start();
    for (const argv of [["get", "--host", BAD], ["get", "--host", `${BAD}:9876`], ["get", "--url", `http://${BAD}/x`], ["get", "--host=x${BAD}"], ["get", "--host", "api.evil.test"], ["get", "--url", "https://api.evil.test:443/v1"]])
      await expect(core.runCli(id, { connector: "tool", argv }), argv.join(" ")).rejects.toThrow(CliRejectedError);
    expect(existsSync(join(bin, "RAN"))).toBe(false);
    await core.runCli(id, { connector: "tool", argv: ["get", "--host", "ok.test"] }); // control: allowed target runs
    expect(existsSync(join(bin, "RAN"))).toBe(true);
  });
  it("connector name server / mongo URI naming it or resolving to it → refused", async () => {
    const bin = mkdtempSync(join(tmpdir(), "wt-cbbin-"));
    for (const c of [
      { name: "mq", binary: fake(bin), allow: [["topicList"]], args: { topicList: ["-n"] }, namesrvs: [`${BAD}:9876`] },
      { name: "mongosh", binary: fake(bin), kind: "mongo" as const, uri: `mongodb://${BAD}:27017/app` },
      { name: "mongosh", binary: fake(bin), kind: "mongo" as const, uri: "mongodb://db1.ok.test:27017,db2.evil.test:27017/app?replicaSet=rs0" },
      { name: "mongosh", binary: fake(bin), kind: "mongo" as const, uri: "mongodb+srv://cluster.evil.test/app" },
    ]) {
      const { core, start } = mk([c]);
      const id = start();
      const input = c.kind === "mongo" ? { connector: c.name, template: { name: "countDocuments", db: "app", collection: "orders", filter: {} } } : { connector: c.name, argv: ["topicList"] };
      await expect(core.runCli(id, input as never), c.name).rejects.toThrow(/core blocklist/);
    }
    expect(existsSync(join(bin, "RAN"))).toBe(false);
  });
  it("hostCandidates extracts URL / mongo / host:port / bracketed IPv6 hosts", () => {
    expect(hostCandidates("mongodb://u@a.test:1,b.test:2/x")).toEqual(expect.arrayContaining(["a.test", "b.test"]));
    expect(hostCandidates("[::ffff:228e:8727]:80")).toContain("::ffff:228e:8727");
    expect(hostCandidates("cn-hangzhou")).toEqual([]);
  });
  it("assertNoCoreBlockedTargets: IPv6-mapped literal refused", async () => {
    await expect(assertNoCoreBlockedTargets(["[::ffff:228e:8727]:80"], async () => [])).rejects.toThrow(/core blocklist/);
  });
});

describe("core blocklist: flow http actions and readiness polling use the guarded path", () => {
  const http = require_("node:http") as typeof import("node:http");
  async function servers() {
    // "blocked side": a server on 127.0.0.2 standing in for the blocked address (marked core-blocked for this test),
    // counting raw TCP connections.
    let blockedConns = 0;
    const blocked = http.createServer((_q, r) => r.end("REACHED"));
    blocked.on("connection", () => { blockedConns++; });
    await new Promise<void>((r) => blocked.listen(0, "127.0.0.2", r));
    const bport = (blocked.address() as { port: number }).port;
    const hits: string[] = [];
    const ok = http.createServer((q, r) => {
      hits.push(q.url ?? "");
      if (q.url === "/to-literal") { r.writeHead(302, { location: `http://${BAD}/` }); return r.end(); }
      if (q.url === "/to-standin") { r.writeHead(302, { location: `http://127.0.0.2:${bport}/` }); return r.end(); }
      if (q.url === "/to-standin-name") { r.writeHead(302, { location: `http://blocked.test:${bport}/` }); return r.end(); }
      if (q.url === "/to-self") { r.writeHead(302, { location: "/health" }); return r.end(); }
      r.writeHead(200, { "x-tok": "t1" }); r.end("healthy");
    });
    await new Promise<void>((r) => ok.listen(0, "127.0.0.1", r));
    const port = (ok.address() as { port: number }).port;
    return { port, hits, conns: () => blockedConns, close: () => { ok.close(); blocked.close(); } };
  }
  const resolver = async (h: string) => (h === "blocked.test" ? "127.0.0.2" : "127.0.0.1");
  const appReplay = (port: number) => ({ allowHosts: [`app.test:${port}`], allowCidrs: ["127.0.0.1/32"] });

  it("httpSource: allowlisted server 302 → blocked address (literal, stand-in IP, name resolving to it) is refused; zero connections on the blocked side", async () => {
    const undo = addTestCoreBlocked("127.0.0.2");
    const s = await servers();
    try {
      for (const path of ["/to-literal", "/to-standin", "/to-standin-name"]) {
        const r = await httpSource.run({ type: "http", url: `http://app.test:${s.port}${path}` }, { replay: appReplay(s.port), resolver });
        expect(r.evidenceText, path).toMatch(/core blocklist|not in the replay allowlist/);
        expect(r.status, path).toBeUndefined();
      }
      expect(s.conns()).toBe(0);
      // a same-host redirect still works (each hop re-checked, IP pinned)
      const good = await httpSource.run({ type: "http", url: `http://app.test:${s.port}/to-self` }, { replay: appReplay(s.port), resolver });
      expect(good).toMatchObject({ status: 200, body: "healthy" });
      // literal blocked target, no redirect
      // allowlisted on purpose: the core blocklist must still win (refused before any connection)
      expect((await httpSource.run({ type: "http", url: `http://${BAD}/` }, { replay: { allowHosts: [BAD], allowCidrs: [`${BAD}/32`] } })).evidenceText).toMatch(/core blocklist/);
    } finally { undo(); s.close(); }
  });

  it("even if the stand-in is allowlisted as the flow's own host, the core blocklist wins", async () => {
    const undo = addTestCoreBlocked("127.0.0.2");
    const s = await servers();
    try {
      const r = await httpSource.run({ type: "http", url: "http://blocked.test:1/" }, { replay: { allowHosts: ["blocked.test:1"], allowCidrs: ["127.0.0.2/32"] }, resolver });
      expect(r.evidenceText).toMatch(/core blocklist/);
      expect(s.conns()).toBe(0);
    } finally { undo(); s.close(); }
  });

  it("waitForUrl: 302 → blocked address refused at once (not retried); zero connections; same-host redirect + header still work", async () => {
    const undo = addTestCoreBlocked("127.0.0.2");
    const s = await servers();
    try {
      for (const path of ["/to-literal", "/to-standin", "/to-standin-name"]) {
        const t = Date.now();
        await expect(waitForUrl(`http://app.test:${s.port}${path}`, 20_000, 1_000, undefined, { resolver }), path).rejects.toThrow(/core blocklist|not in the replay allowlist/);
        expect(Date.now() - t).toBeLessThan(3_000);
      }
      expect(s.conns()).toBe(0);
      await waitForUrl(`http://app.test:${s.port}/to-self`, 5_000, 1_000, { name: "x-tok", value: "t1" }, { resolver });
      await expect(waitForUrl(`http://${BAD}:8080/health`, 20_000)).rejects.toThrow(/core blocklist/);
    } finally { undo(); s.close(); }
  });

  it("DNS rebinding: a host that resolves to an allowed IP first and the blocked one afterwards never reaches the second", async () => {
    const undo = addTestCoreBlocked("127.0.0.2");
    const s = await servers();
    let n = 0;
    const rebinding = async () => (n++ === 0 ? "127.0.0.1" : "127.0.0.2");
    try {
      const r = await httpSource.run({ type: "http", url: `http://rebind.test:${s.port}/to-self` }, { replay: { allowHosts: [`rebind.test:${s.port}`], allowCidrs: ["127.0.0.1/32"] }, resolver: rebinding });
      expect(r.status === undefined || r.status === 200).toBe(true);
      expect(s.conns()).toBe(0);
    } finally { undo(); s.close(); }
  });
});

describe("hostCandidates normalisation", () => {
  it("decimal / hex / short-dotted forms of the blocked address are normalised and refused", async () => {
    for (const f of ["579766055", "0x228e8727", "34.142.34599", "http://579766055/x", "0x228e8727:9876"]) {
      expect(hostCandidates(f), f).toContain(BAD);
      await expect(assertNoCoreBlockedTargets([f], async () => []), f).rejects.toThrow(/core blocklist/);
    }
  });
});
