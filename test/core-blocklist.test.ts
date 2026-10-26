// Core blocklist (34.142.135.39): refused on every outbound path even when allowlisted, incl. via DNS.
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertNoCoreBlockedTargets, checkHop, CliRejectedError, CORE_BLOCKED_IPS, guardedGet, guardedRequest, guardedWebSocket, hostCandidates, httpSource, ipProblem,
  promInstantQuery, Redactor, replayRequest, ReplayRejectedError, waitForUrl, WalkthroughCore, type ConnectorConfig, type Sandbox } from "../src/core/index.js";
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

describe("core blocklist: flow http actions and readiness polling", () => {
  it("httpSource refuses it (no request made)", async () => {
    const r = await httpSource.run({ type: "http", url: `http://${BAD}/` });
    expect(r.evidenceText).toMatch(/core blocklist/);
    expect(r.status).toBeUndefined();
  });
  it("waitForUrl refuses up front instead of polling", async () => {
    const t = Date.now();
    await expect(waitForUrl(`http://${BAD}:8080/health`, 20_000)).rejects.toThrow(/core blocklist/);
    expect(Date.now() - t).toBeLessThan(2_000);
  });
});
