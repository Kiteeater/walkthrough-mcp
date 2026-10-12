import { mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authFor, ipProblem, Redactor, replayRequest, WalkthroughCore, type Check, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { mkdtempSync } from "node:fs";
import { SB } from "./helpers.js";

// Fake secrets planted in every HAR spot that must be scrubbed.
const S = {
  cookie: "sessid=COOKIEsecret123", setCookie: "sid=SETCOOKIEsecret456; HttpOnly", bearer: "BEARERsecretTOKEN789",
  qtoken: "QTOKENsecretABC", qsig: "QSIGsecretDEF", qkey: "QAPIKEYsecretGHI", reqBody: "sk-lf-REQBODYsecret01", resBody: "pk-lf-RESBODYsecret02",
};
const har = (status = 500, url = "http://demo.local:PORT/api/orders") => JSON.stringify({ log: { version: "1.2", entries: [
  { request: { method: "GET", url: `${url}?access_token=${S.qtoken}&sig=${S.qsig}&api_key=${S.qkey}&page=1`,
      headers: [{ name: "Cookie", value: S.cookie }, { name: "Authorization", value: `Bearer ${S.bearer}` }, { name: "Accept", value: "application/json" }],
      cookies: [{ name: "sessid", value: "COOKIEsecret123" }], queryString: [{ name: "access_token", value: S.qtoken }, { name: "page", value: "1" }],
      postData: { text: `{"lfKey":"${S.reqBody}"}` } },
    response: { status, headers: [{ name: "Set-Cookie", value: S.setCookie }, { name: "content-type", value: "application/json" }], cookies: [{ name: "sid", value: "SETCOOKIEsecret456" }],
      content: { text: `{"error":"internal error","debug":"Authorization: Bearer ${S.bearer} ${S.resBody}"}`, mimeType: "application/json" } } },
  { request: { method: "GET", url: "http://demo.local/app.js", headers: [] }, response: { status: 200, headers: [], content: { text: "" } } },
] } });

// Test-account value; env name deliberately does NOT look secret, so only explicit per-run redaction can hide it.
const QA = "qaACCOUNTvalue12345";
const chk = (id: string, value: unknown): Check => ({ id, intent: id, method: "ui", target: "orders page", expect: { type: "ui", value } as never, severity_if_fail: "high" });
const uiOk = chk("ui-ok", { har: { urlMatch: "/api/orders", status: [200, 299] } });
const ui500 = chk("ui-500", { har: { urlMatch: "/api/orders", status: 500 } });
const text = chk("ui-text", { text: { contains: "Failed to load orders" } });
const status = chk("st", { type: "status", value: 200 } as never);
status.expect = { type: "status", value: 200 };

function mk(replay?: ReplayConfig, resolver?: (h: string) => Promise<string>, redactor: Redactor = new Redactor([])) {
  const root = mkdtempSync(join(tmpdir(), "wt-page-"));
  const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
  const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, o) => writeFileSync(o, "png") }, redactor, replay, resolver, env: { QA_LOGIN: QA } });
  return { core, root };
}
async function setup(replay?: ReplayConfig, resolver?: (h: string) => Promise<string>, redactor?: Redactor) {
  const { core, root } = mk(replay, resolver, redactor);
  const w = core.startWalkthrough({ title: "ui", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [uiOk, ui500, text, status] });
  const shot = (checkId: string) => core.captureEvidence(w.id, { type: "submit", checkId, kind: "screenshot", source: { tool: "computer-use" }, content: Buffer.from("PNG with text: Failed to load orders HTTP/1.1 200 \"status\": 200").toString("base64") });
  const harEv = (checkId: string, h = har()) => core.captureEvidence(w.id, { type: "submit", checkId, kind: "har", source: { tool: "playwright-mcp" }, content: h });
  return { core, root, id: w.id, shot, harEv };
}
const allArtifacts = (dir: string): string => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((d) => d.isFile()).map((d) => readFileSync(join(d.parentPath ?? (d as never as { path: string }).path, d.name), "utf8")).join("\n");

describe("page evidence: screenshots are never judged", () => {
  it("screenshot-only evidence cannot satisfy any expectation (ui har, ui text, status)", async () => {
    const { core, id, shot } = await setup();
    for (const c of ["ui-ok", "ui-500", "ui-text", "st"]) {
      const ev = await shot(c);
      const r = await core.evaluateCheck(id, { checkId: c, evidenceIds: [ev.id] });
      expect(r.status, c).toBe("inconclusive");
    }
  });
  it("plan_checks rejects malformed ui expectations", async () => {
    const { core } = mk();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    for (const v of [{}, { har: { urlMatch: "(", status: 200 } }, { har: { urlMatch: "/x" } }, { har: { urlMatch: "/x", status: 200 }, text: { contains: "a" } }, { text: { contains: "" } }])
      await expect(core.planChecks(w.id, { goal: "g", checks: [chk("bad", v)] })).rejects.toThrow();
  });
});

describe("page evidence: judging from HAR / DOM text", () => {
  it("HAR 500 fails a 2xx expectation; agent-only HAR that matches is at most pass_needs_review", async () => {
    const { core, id, harEv } = await setup();
    const a = await harEv("ui-ok");
    const r = await core.evaluateCheck(id, { checkId: "ui-ok", evidenceIds: [a.id] });
    expect(r.status).toBe("fail");
    expect(r.reasons.join()).toMatch(/→ 500，期望 200-299/);
    const b = await harEv("ui-500");
    expect((await core.evaluateCheck(id, { checkId: "ui-500", evidenceIds: [b.id] })).status).toBe("pass_needs_review");
  });
  it("agent-only HAR + screenshot -> still pass_needs_review", async () => {
    const { core, id, harEv, shot } = await setup();
    const a = await harEv("ui-500"), s = await shot("ui-500");
    expect((await core.evaluateCheck(id, { checkId: "ui-500", evidenceIds: [a.id, s.id] })).status).toBe("pass_needs_review");
  });
  it("text expectation reads DOM text, not HAR", async () => {
    const { core, id, harEv } = await setup();
    const h = await harEv("ui-text");
    expect((await core.evaluateCheck(id, { checkId: "ui-text", evidenceIds: [h.id] })).status).toBe("inconclusive");
    const t = await core.captureEvidence(id, { type: "submit", checkId: "ui-text", kind: "http", source: { tool: "dom" }, content: "Orders\nFailed to load orders (500)" });
    expect((await core.evaluateCheck(id, { checkId: "ui-text", evidenceIds: [t.id] })).status).toBe("pass_needs_review");
  });
  it("core page capture (method: ui fallback) is core-executed and judged normally", async () => {
    const { core, root } = mk({ allowHosts: ["demo.local"] }, async () => "93.184.216.34");
    (core as unknown as { deps: { capturer: unknown } }).deps.capturer = { screenshot: async () => {}, page: async () => ({ screenshot: Buffer.from("png"), har: har(500), text: "Failed to load orders", navigations: [], subresources: [{ url: "http://cdn.example/x.js?token=SUBRESsecret", method: "GET", type: "script", status: 200, ip: "127.0.0.1" }], blocked: [] }) };
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.planChecks(w.id, { goal: "g", checks: [ui500] });
    const evs = await core.capturePage(w.id, { url: "http://demo.local/", checkId: "ui-500" });
    expect(evs.map((e) => [e.type, e.executedBy])).toEqual([["screenshot", "core"], ["har", "core"], ["response", "core"]]);
    expect((await core.evaluateCheck(w.id, { checkId: "ui-500", evidenceIds: evs.map((e) => e.id) })).status).toBe("pass");
    const all = allArtifacts(join(root, ".walkthrough"));
    for (const v of Object.values(S)) expect(all).not.toContain(v);
    expect(all).not.toContain("SUBRESsecret");
    expect(readFileSync(join(core.dir(w.id), "commands.jsonl"), "utf8")).toMatch(/"type":"capture_page".*cdn\.example/);
  });
});

describe("HAR redaction", () => {
  it("Cookie / Set-Cookie / Authorization / secret query params / request+response bodies never reach artifacts", async () => {
    const { core, root, id, harEv } = await setup();
    const ev = await harEv("ui-500");
    await core.evaluateCheck(id, { checkId: "ui-500", evidenceIds: [ev.id] });
    await core.recordFinding(id, { title: "t", severity: "high", symptom: "s", root_cause_chain: [{ claim: "500", kind: "observed", evidence_ids: [ev.id] }], check_id: "ui-500" });
    const { renderWalkthrough } = await import("../src/core/index.js");
    renderWalkthrough(core, id);
    const all = allArtifacts(join(root, ".walkthrough"));
    for (const [k, v] of Object.entries(S)) expect(all, k).not.toContain(v);
    expect(all).toContain("page=1"); // non-secret query params survive
    const stored = JSON.parse(readFileSync(join(core.dir(id), ev.path), "utf8"));
    expect(stored.log.entries[0].response.status).toBe(500);
  });
  it("rejects a non-HAR payload", async () => {
    const { harEv } = await setup();
    await expect(harEv("ui-500", "not json")).rejects.toThrow(/not a HAR/);
  });
});

describe("HAR/screenshot files by path", () => {
  it("must resolve inside .walkthrough (no outside paths, no symlink escape) and respect the size cap", async () => {
    const { core, root, id } = await setup();
    const sub = (path: string, kind: "har" | "screenshot" = "har") => core.captureEvidence(id, { type: "submit", checkId: "ui-500", kind, source: { tool: "pw" }, path });
    const outside = join(root, "outside.har"); writeFileSync(outside, har());
    await expect(sub(outside)).rejects.toThrow(/must be inside/);
    await expect(sub("/etc/passwd", "screenshot")).rejects.toThrow(/must be inside/);
    const inbox = join(root, ".walkthrough", "inbox"); mkdirSync(inbox, { recursive: true });
    symlinkSync(outside, join(inbox, "link.har"));
    await expect(sub(join(inbox, "link.har"))).rejects.toThrow(/must be inside/);
    await expect(sub(join(inbox, "..", "..", "outside.har"))).rejects.toThrow(/must be inside/);
    writeFileSync(join(inbox, "big.har"), Buffer.alloc(5 * 1024 * 1024 + 1, 32));
    await expect(sub(join(inbox, "big.har"))).rejects.toThrow(/too large/);
    await expect(core.captureEvidence(id, { type: "submit", checkId: "ui-500", kind: "har", source: { tool: "pw" }, content: " ".repeat(5 * 1024 * 1024 + 1) })).rejects.toThrow(/too large/);
    writeFileSync(join(inbox, "ok.har"), har());
    expect((await sub(join(inbox, "ok.har"))).type).toBe("har");
  });
});

describe("replay (core-executed)", () => {
  let srv: http.Server, port = 0;
  const seen: http.IncomingHttpHeaders[] = [];
  beforeAll(async () => {
    srv = http.createServer((req, res) => {
      seen.push(req.headers);
      if (req.url?.startsWith("/api/orders")) {
        // Debug endpoint that echoes the session header back in a response header AND the body.
        const echo = String(req.headers["x-qa-session"] ?? "");
        res.writeHead(500, { "content-type": "application/json", "set-cookie": "srv=SRVsecret", "x-debug-echo": echo });
        return res.end(JSON.stringify({ error: "internal error", debug: `session was ${echo}` }));
      }
      if (req.url === "/redir-evil") { res.writeHead(302, { location: "http://evil.example/steal" }); return res.end(); }
      if (req.url === "/redir-meta") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }); return res.end(); }
      if (req.url === "/redir-self") { res.writeHead(302, { location: `http://demo.local:${port}/api/orders` }); return res.end(); }
      res.writeHead(200); res.end("ok");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    port = (srv.address() as AddressInfo).port;
  });
  afterAll(() => srv.close());
  const cfg = (): ReplayConfig => ({ allowHosts: [`demo.local:${port}`], allowCidrs: ["127.0.0.1/32"], auth: { header: "X-QA-Session", valueEnv: "QA_LOGIN" } });
  const local = async () => "127.0.0.1";
  const url = (p: string) => `http://demo.local:${port}${p}`;

  it("replays the HAR's GET, never forwards HAR cookies/auth, logs to the hash chain; check judges a normal fail/pass", async () => {
    const { core, root, id, harEv, shot } = await setup(cfg(), local, Redactor.fromEnv(process.env)); // real env redactor
    const a = await harEv("ui-ok", har(500, url("/api/orders")));
    const s = await shot("ui-ok");
    seen.length = 0;
    const r = await core.replayHar(id, { checkId: "ui-ok", evidenceId: a.id, urlMatch: "/api/orders" });
    expect(r).toMatchObject({ type: "har", executedBy: "core" });
    expect(seen).toHaveLength(1);
    const h = JSON.stringify(seen[0]);
    expect(h).not.toContain("COOKIEsecret123"); expect(h).not.toContain(S.bearer); expect(seen[0].cookie).toBeUndefined();
    expect(seen[0].authorization).toBeUndefined();
    expect(seen[0]["x-qa-session"]).toBe(QA); // configured test account, not the HAR's
    const res = await core.evaluateCheck(id, { checkId: "ui-ok", evidenceIds: [a.id, s.id, r.id] });
    expect(res.status).toBe("fail");
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8");
    expect(log).toMatch(/"type":"replay"/); expect(log).toMatch(/"executedBy":"core"/);
    expect(core.verifyCommandLog(id).ok).toBe(true);
    const all = allArtifacts(join(root, ".walkthrough"));
    const { renderWalkthrough } = await import("../src/core/index.js");
    await core.recordFinding(id, { title: "t", severity: "high", symptom: "s", root_cause_chain: [{ claim: "500", kind: "observed", evidence_ids: [r.id] }], check_id: "ui-ok" });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toContain("session was [REDACTED]"); // the echo is there, masked
    expect(html).not.toContain(QA);
    expect(JSON.stringify(core.load(id))).not.toContain(QA);
    const files = readdirSync(join(root, ".walkthrough"), { recursive: true, withFileTypes: true }).filter((d) => d.isFile());
    expect(files.length).toBeGreaterThan(4);
    expect(allArtifacts(join(root, ".walkthrough"))).not.toContain(QA);
    expect(all).not.toContain("SRVsecret"); expect(all).not.toContain(QA);
    // a matching expectation backed by a core replay is a normal pass, not needs-review
    const b = await harEv("ui-500", har(500, url("/api/orders")));
    const r2 = await core.replayHar(id, { checkId: "ui-500", evidenceId: b.id });
    expect((await core.evaluateCheck(id, { checkId: "ui-500", evidenceIds: [b.id, r2.id] })).status).toBe("pass");
  });
  it("replay is disabled without config", async () => {
    const { core, id, harEv } = await setup();
    const a = await harEv("ui-ok");
    await expect(core.replayHar(id, { checkId: "ui-ok", evidenceId: a.id })).rejects.toThrow(/not configured/);
  });
  it("POST is rejected", async () => {
    await expect(replayRequest(cfg(), { method: "POST", url: url("/api/orders") }, { resolver: local })).rejects.toThrow(/only GET\/HEAD/);
  });
  it("non-allowlisted host is rejected", async () => {
    await expect(replayRequest(cfg(), { method: "GET", url: "http://evil.example/" }, { resolver: local })).rejects.toThrow(/not in the replay allowlist/);
  });
  it("redirect to a non-allowlisted host is rejected (no auto-follow)", async () => {
    seen.length = 0;
    await expect(replayRequest(cfg(), { method: "GET", url: url("/redir-evil") }, { resolver: local })).rejects.toThrow(/evil.example is not in the replay allowlist/);
    expect(seen).toHaveLength(1);
  });
  it("redirect to the metadata IP is rejected", async () => {
    const c = { ...cfg(), allowHosts: [...cfg().allowHosts, "169.254.169.254"] };
    await expect(replayRequest(c, { method: "GET", url: url("/redir-meta") }, { resolver: local })).rejects.toThrow(/metadata/);
  });
  it("metadata addresses are always denied, even if listed", async () => {
    for (const ip of ["169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254", "::ffff:a9fe:a9fe"]) {
      expect(ipProblem(ip, ["169.254.0.0/16", "100.64.0.0/10", "fd00::/8", ip + (ip.includes(":") ? "/128" : "/32")]), ip).toMatch(/metadata/);
      await expect(replayRequest({ allowHosts: ["meta.host"], allowCidrs: ["169.254.0.0/16", "fd00::/8"] }, { method: "GET", url: "http://meta.host/" }, { resolver: async () => ip }), ip).rejects.toThrow(/metadata/);
    }
  });
  it("private ranges are denied unless the CIDR is listed", async () => {
    for (const ip of ["10.1.2.3", "172.20.0.5", "192.168.1.1", "fc00::1", "fd12::1"]) expect(ipProblem(ip), ip).toMatch(/denied/);
    expect(ipProblem("10.1.2.3", ["10.1.2.0/24"])).toBeUndefined();
    expect(ipProblem("10.1.3.3", ["10.1.2.0/24"])).toMatch(/denied/);
    await expect(replayRequest({ allowHosts: ["intra"] }, { method: "GET", url: "http://intra/" }, { resolver: async () => "192.168.1.1" })).rejects.toThrow(/denied/);
  });
  it.each([
    ["::1", []], ["fe80::1", []], ["fd00:ec2::254", ["fd00::/8"]], ["::ffff:169.254.169.254", ["169.254.0.0/16"]],
    ["::ffff:127.0.0.1", []], ["127.0.0.2", ["127.0.0.1/32"]], ["127.0.0.1", []], ["127.0.0.5", ["127.0.0.0/8"]],
  ])("loopback / link-local / mapped: %s rejected (allowCidrs %j)", (ip, allow) => {
    expect(ipProblem(ip as string, allow as string[])).toBeTruthy();
  });
  it("loopback only for the exact configured host", () => {
    expect(ipProblem("127.0.0.1", ["127.0.0.1/32"])).toBeUndefined();
    expect(ipProblem("::ffff:127.0.0.1", ["127.0.0.1/32"])).toBeUndefined();
  });
  it("cross-origin redirect (A → B, both allowlisted): B gets none of A's credentials; HAR cookies never sent", async () => {
    const got: http.IncomingHttpHeaders[] = [];
    const b = http.createServer((req, res) => { got.push(req.headers); res.writeHead(200); res.end("b"); });
    await new Promise<void>((r) => b.listen(0, "127.0.0.1", r));
    const bport = (b.address() as AddressInfo).port;
    const a = http.createServer((req, res) => { seen.push(req.headers); res.writeHead(302, { location: `http://other.local:${bport}/x`, "set-cookie": "a=1" }); res.end(); });
    await new Promise<void>((r) => a.listen(0, "127.0.0.1", r));
    const aport = (a.address() as AddressInfo).port;
    try {
      seen.length = 0;
      const c: ReplayConfig = { allowHosts: [`demo.local:${aport}`, `other.local:${bport}`, `demo.local:${bport}`], allowCidrs: ["127.0.0.1/32"], auth: { header: "X-QA-Session", valueEnv: "QA_LOGIN" } };
      const r = await replayRequest(c, { method: "GET", url: `http://demo.local:${aport}/start` }, { resolver: local, env: { QA_LOGIN: QA } });
      expect(r.status).toBe(200);
      expect(seen[0]["x-qa-session"]).toBe(QA);           // origin A: account attached
      expect(got[0]["x-qa-session"]).toBeUndefined();      // origin B: stripped
      expect(got[0].cookie).toBeUndefined(); expect(got[0].authorization).toBeUndefined();
      expect(r.sentSecrets).toEqual([QA]);
      // same host, different port → different origin → stripped too
      const a2 = http.createServer((req, res) => { res.writeHead(302, { location: `http://demo.local:${bport}/y` }); res.end(); });
      await new Promise<void>((r2) => a2.listen(0, "127.0.0.1", r2));
      const a2port = (a2.address() as AddressInfo).port;
      got.length = 0;
      await replayRequest({ ...c, allowHosts: [...c.allowHosts, `demo.local:${a2port}`] }, { method: "GET", url: `http://demo.local:${a2port}/` }, { resolver: local, env: { QA_LOGIN: QA } });
      expect(got[0]["x-qa-session"]).toBeUndefined();
      a2.close();
      // an origin explicitly bound in config gets the account re-attached
      got.length = 0;
      await replayRequest({ ...c, auth: { ...c.auth!, origins: [`http://demo.local:${aport}`, `http://other.local:${bport}`] } }, { method: "GET", url: `http://demo.local:${aport}/start` }, { resolver: local, env: { QA_LOGIN: QA } });
      expect(got[0]["x-qa-session"]).toBe(QA);
    } finally { a.close(); b.close(); }
  });
  it("authFor: https → http downgrade, other port, other host all drop the account", () => {
    const c: ReplayConfig = { allowHosts: [], auth: { header: "X-QA-Session", valueEnv: "QA_LOGIN" } };
    const env = { QA_LOGIN: QA };
    const first = "https://shop.example";
    expect(authFor(c, new URL("https://shop.example/a"), first, env)).toEqual({ "x-qa-session": QA });
    expect(authFor(c, new URL("https://shop.example:443/a"), first, env)).toEqual({ "x-qa-session": QA });
    expect(authFor(c, new URL("http://shop.example/a"), first, env)).toEqual({});        // downgrade
    expect(authFor(c, new URL("https://shop.example:8443/a"), first, env)).toEqual({});  // other port
    expect(authFor(c, new URL("https://evil.example/a"), first, env)).toEqual({});       // other host
  });
  it("DNS rebinding: each hop resolves once and is pinned; a second resolution to a forbidden IP is rejected", async () => {
    const answers = ["127.0.0.1", "169.254.169.254"];
    let calls = 0;
    const resolver = async () => answers[Math.min(calls++, 1)];
    await expect(replayRequest(cfg(), { method: "GET", url: url("/redir-self") }, { resolver })).rejects.toThrow(/metadata/);
    expect(calls).toBe(2); // one lookup per hop; http itself never re-resolves
    const answers2 = ["127.0.0.1", "10.0.0.9"]; let c2 = 0;
    await expect(replayRequest(cfg(), { method: "GET", url: url("/redir-self") }, { resolver: async () => answers2[Math.min(c2++, 1)] })).rejects.toThrow(/denied/);
  });
});

describe("name-pattern redaction and ReDoS guard", () => {
  it("secret header names by pattern; param names anchored to the last segment", async () => {
    const { SECRET_HEADER, SECRET_PARAM } = await import("../src/core/index.js");
    for (const h of ["X-Access-Token", "Api-Key", "X-Goog-Api-Key", "X-Session-Id", "Set-Cookie", "Proxy-Authorization", "X-CSRF-Token"]) expect(SECRET_HEADER.test(h), h).toBe(true);
    for (const h of ["Accept", "Content-Type", "User-Agent", "Cache-Control"]) expect(SECRET_HEADER.test(h), h).toBe(false);
    for (const n of ["access_token", "api_key", "X-Amz-Signature", "sid", "jwt", "ticket", "code", "client_secret"]) expect(SECRET_PARAM.test(n), n).toBe(true);
    for (const n of ["barcode", "zipcode", "monkey", "page", "sort"]) expect(SECRET_PARAM.test(n), n).toBe(false);
  });
  it("agent regexes: nested quantifiers, backrefs and over-long patterns are rejected", async () => {
    const { safeRegex } = await import("../src/core/index.js");
    for (const p of ["(a+)+$", "(a*)*", "(\\w+\\s?)+$", "(a|aa)+", "(.*){2,}", "(a)\\1", "x".repeat(201)]) expect(() => safeRegex(p), p).toThrow();
    expect(safeRegex("/api/orders$").test("http://x/api/orders")).toBe(true);
    const { core } = mk();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await expect(core.planChecks(w.id, { goal: "g", checks: [chk("r", { har: { urlMatch: "(a+)+$", status: 200 } })] })).rejects.toThrow(/ReDoS/);
  });
});
