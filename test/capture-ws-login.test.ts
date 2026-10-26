// Issues #18 / #19: capture_page connects WebSockets only to allowlisted hosts (same IP rules + pinning as HTTP) and
// can load a user-provided login state (Playwright storageState). Browsing stays read-only. Real Chromium.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadLoginState, PlaywrightCapturer, Redactor, renderWalkthrough, ReplayRejectedError, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const require = createRequire(import.meta.url);
const hasChromium = (() => { try { return existsSync(require("playwright").chromium.executablePath()); } catch { return false; } })();
if (process.env.REQUIRE_CHROMIUM && !hasChromium) throw new Error("REQUIRE_CHROMIUM is set but Chromium is not installed");
const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };

// Fake session values, stored under the real field names of a Playwright storageState file.
const WS_SECRET = "WSSECRETtok-9931ab", ROTATED = "ROTATEDval-3c71e09a";
const SUBSCRIBE = '{"op":"subscribe","topic":"orders"}';
const wsReceived: string[] = [];
const SESSION = "SESSIONval-7f3a91c2d4", CSRF = "CSRFval-55e10b7a", FOREIGN = "FOREIGNval-0c9d2e", LS_TOKEN = "LStoken-a81f22c0";

let srv: http.Server, port = 0;
const hits: string[] = [];
const cookiesSeen: string[] = [];
const wsHits: string[] = [];
const sockets = new Set<Socket>();

function wsFrame(text: string): Buffer { const p = Buffer.from(text); return Buffer.concat([Buffer.from([0x81, p.length]), p]); }
function wsDecode(b: Buffer): string | undefined { // single small masked frame from the client
  if (b.length < 6) return undefined;
  const len = b[1] & 0x7f, mask = b.subarray(2, 6), data = b.subarray(6, 6 + len);
  return Buffer.from(data.map((x, i) => x ^ mask[i % 4])).toString();
}

beforeAll(async () => {
  srv = http.createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    if (req.headers.cookie) cookiesSeen.push(`${req.url} ${req.headers.cookie}`);
    const html = (b: string) => { res.writeHead(200, { "content-type": "text/html" }); res.end(b); };
    const logged = (req.headers.cookie ?? "").includes(`sessionid=${SESSION}`);
    if (req.url === "/ws-page") return html(`<h1>ws page</h1><p id="ok">ws:pending</p><p id="bad">bad:pending</p><p id="meta">meta:pending</p><script>
const a = new WebSocket("ws://demo.local:${port}/echo");
a.onopen = () => { a.send(${JSON.stringify(SUBSCRIBE)}); a.send(JSON.stringify({ op: "delete", id: 42, token: "${WS_SECRET}" })); a.send(new Uint8Array([1, 2, 3])); }; a.onmessage = (e) => { document.getElementById("ok").textContent = "ws:" + e.data; };
a.onerror = () => { document.getElementById("ok").textContent = "ws:error"; };
const b = new WebSocket("ws://not-allowed.example:${port}/evil-ws");
b.onclose = () => { document.getElementById("bad").textContent = "bad:blocked"; }; b.onopen = () => { document.getElementById("bad").textContent = "bad:OPEN"; };
const c = new WebSocket("ws://169.254.169.254/meta-ws");
c.onclose = () => { document.getElementById("meta").textContent = "meta:blocked"; }; c.onopen = () => { document.getElementById("meta").textContent = "meta:OPEN"; };
</script>`);
    if (req.url === "/account") return html(`<h1>${logged ? "已登录 page" : "未登录 page"}</h1><p id="api">api:pending</p><p id="ls">ls:pending</p><p id="flag">flag:pending</p><script>
document.getElementById("flag").textContent = "flag:" + localStorage.getItem("beta_flag");
fetch("/api/me").then((r) => r.text()).then((t) => { document.getElementById("api").textContent = "api:" + t; });
document.getElementById("ls").textContent = "ls:" + localStorage.getItem("access_token");
fetch("/api/orders", { method: "POST", body: "x" }).catch(() => {});
</script>`);
    if (req.url === "/api/me") { res.writeHead(200, { "content-type": "text/plain", "set-cookie": [`sessionid=${ROTATED}; Path=/; HttpOnly`, "theme=1; Path=/"] }); return res.end(logged ? `me=alice rotated=${ROTATED}` : "me=anonymous"); }
    html("<h1>ok page</h1>");
  });
  srv.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  srv.on("upgrade", (req, sock: Socket) => {
    wsHits.push(req.url ?? "");
    const accept = createHash("sha1").update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    sock.on("data", (d) => { const t = wsDecode(d); if (t !== undefined && ((d[0] & 0x0f) === 1 || (d[0] & 0x0f) === 2)) wsReceived.push(t); if (t !== undefined && (d[0] & 0x0f) === 1) sock.write(wsFrame(`echo:${t}`)); });
    sock.on("error", () => undefined);
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => { for (const s of sockets) s.destroy(); srv.close(); });

function mk(capture?: { storageStatePath?: string; allowWebSocketHosts?: string[]; webSocketOutbound?: Record<string, string[]> }) {
  const root = mkdtempSync(join(tmpdir(), "wt-wslogin-"));
  const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: new PlaywrightCapturer(), redactor: new Redactor([WS_SECRET]), resolver: async () => "127.0.0.1",
    // 169.254.169.254 is allowlisted on purpose: the IP rule (not the allowlist) must stop its WebSocket.
    replay: { allowHosts: [`demo.local:${port}`, "169.254.169.254"], allowCidrs: ["127.0.0.1/32"], ...(capture ? { capture } : {}) } });
  return { core, root };
}
async function planned(core: WalkthroughCore) {
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [{ id: "p", intent: "p", method: "ui", target: "x", expect: { type: "ui", value: { text: { contains: "page" } } }, severity_if_fail: "high" }] });
  return w.id;
}
const files = (root: string) => readdirSync(join(root, ".walkthrough"), { recursive: true, withFileTypes: true }).filter((d) => d.isFile()).map((d) => ({ name: d.name, text: readFileSync(join(d.parentPath, d.name)).toString("latin1") }));
function expectHashes(core: WalkthroughCore, id: string, evs: { path: string; sha256?: string }[]) {
  for (const ev of evs) expect(ev.sha256, ev.path).toBe(createHash("sha256").update(readFileSync(join(core.dir(id), ev.path))).digest("hex"));
}
function writeState(root: string): string {
  const f = join(root, "login-state.json");
  writeFileSync(f, JSON.stringify({
    cookies: [
      { name: "sessionid", value: SESSION, domain: "demo.local", path: "/", expires: -1, httpOnly: true, secure: false, sameSite: "Lax" },
      { name: "csrftoken", value: CSRF, domain: ".demo.local", path: "/", expires: -1, httpOnly: false, secure: false, sameSite: "Lax" },
      { name: "theme", value: "1", domain: "demo.local", path: "/", expires: -1, httpOnly: false, secure: false, sameSite: "Lax" },
      { name: "sessionid", value: FOREIGN, domain: "other.example", path: "/", expires: -1, httpOnly: true, secure: false, sameSite: "Lax" },
    ],
    origins: [
      { origin: `http://demo.local:${port}`, localStorage: [{ name: "access_token", value: LS_TOKEN }, { name: "beta_flag", value: "true" }] },
      { origin: "http://other.example", localStorage: [{ name: "access_token", value: FOREIGN }] },
    ],
  }));
  return f;
}

describe("capture_page WebSocket (issue #18)", () => {
  const WS_ON = () => ({ allowWebSocketHosts: [`demo.local:${port}`, "169.254.169.254"], webSocketOutbound: { [`demo.local:${port}`]: [SUBSCRIBE] } });

  it.skipIf(!hasChromium)("OFF by default: an allowlisted host's WebSocket is blocked when capture.allowWebSocketHosts is unset", async () => {
    const { core } = mk();
    const id = await planned(core);
    const before = wsHits.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/ws-page` });
    expect(wsHits.length).toBe(before); // nothing reached the server
    const blocked = JSON.parse(readFileSync(join(core.dir(id), evs.find((e) => e.kind === "blocked")!.path), "utf8")).blocked as { url: string; type: string; reason: string }[];
    expect(blocked.find((b) => /\/echo$/.test(b.url))).toMatchObject({ type: "websocket", reason: expect.stringMatching(/off by default/) });
    expect(evs.some((e) => e.path.endsWith(".json") && e.kind === "http")).toBe(false);
  }, 90_000);

  it.skipIf(!hasChromium)("enabled host: receive-only — the exact-match subscribe is forwarded, a write message and binary are dropped; every page message is redacted evidence; non-allowlisted / metadata WS rejected", async () => {
    const { core, root } = mk(WS_ON());
    const id = await planned(core);
    const before = wsHits.length, beforeRecv = wsReceived.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/ws-page` });
    const text = readFileSync(join(core.dir(id), evs.find((e) => e.type === "response" && e.path.endsWith(".txt"))!.path), "utf8");
    expect(text).toContain(`ws:echo:${SUBSCRIBE}`);
    expect(text).toContain("bad:blocked");
    expect(text).toContain("meta:blocked");
    expect(wsHits.slice(before)).toEqual(["/echo"]); // the rejected ones never reached any server
    expect(wsReceived.slice(beforeRecv)).toEqual([SUBSCRIBE]); // the write message and the binary never left
    const wsEv = evs.find((e) => e.path.endsWith(".json") && e.kind === "http")!;
    const ws = JSON.parse(readFileSync(join(core.dir(id), wsEv.path), "utf8"));
    expect(ws.format).toBe("walkthrough-websockets/1");
    expect(ws.websockets).toEqual([expect.objectContaining({ url: `ws://demo.local:${port}/echo`, ip: "127.0.0.1", sent: 1, dropped: 2, received: 1 })]);
    expect(ws.messages).toHaveLength(3);
    expect(ws.messages[0]).toMatchObject({ direction: "page→server", forwarded: true, data: SUBSCRIBE });
    expect(ws.messages[1]).toMatchObject({ forwarded: false, data: expect.stringContaining('"op":"delete"') });
    expect(ws.messages[1].data).not.toContain(WS_SECRET);
    expect(ws.messages[2]).toMatchObject({ forwarded: false, binary: true, bytes: 3, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    const blocked = JSON.parse(readFileSync(join(core.dir(id), evs.find((e) => e.kind === "blocked")!.path), "utf8")).blocked as { url: string; type: string; reason: string }[];
    expect(blocked.filter((b) => b.type === "websocket-message")).toHaveLength(2);
    expect(blocked.find((b) => b.type === "websocket-message")!.reason).toMatch(/receive-only/);
    expect(blocked.find((b) => /evil-ws/.test(b.url))).toMatchObject({ type: "websocket", reason: expect.stringMatching(/off by default/) });
    expect(blocked.find((b) => /meta-ws/.test(b.url))).toMatchObject({ type: "websocket", reason: expect.stringMatching(/metadata/) });
    for (const f of files(root)) expect(f.text, f.name).not.toContain(WS_SECRET);
    expectHashes(core, id, evs);
    expect(core.verifyCommandLog(id).ok).toBe(true);
  }, 90_000);

  it.skipIf(!hasChromium)("wss/ws only: a non-ws scheme passed to the guard is rejected", async () => {
    const { core } = mk();
    const guard = await (core as unknown as { pinnedGuard(c: unknown): Promise<{ websocket(u: string): Promise<{ ip: string; close(): void }> }> }).pinnedGuard({ allowHosts: [`demo.local:${port}`, "ws-only.test"], allowCidrs: ["127.0.0.1/32"], capture: { allowWebSocketHosts: [`demo.local:${port}`, "not-allowed.example", "ws-only.test"] } });
    await expect(guard.websocket(`http://demo.local:${port}/x`)).rejects.toThrow(/websocket scheme/);
    await expect(guard.websocket(`ws://demo.local:${port + 1}/x`)).rejects.toThrow(/off by default/); // other port: not listed
    await expect(guard.websocket(`ws://not-allowed.example:${port}/x`)).rejects.toThrow(/allowlist/); // WS-listed but not in allowHosts
    const c = await guard.websocket(`ws://demo.local:${port}/x`); expect(c.ip).toBe("127.0.0.1"); c.close();
  });
});

describe("capture_page login state (issue #19)", () => {
  it.skipIf(!hasChromium)("storageState cookies + localStorage are used for allowlisted origins; cookie values and the file path never reach evidence; still read-only", async () => {
    const root0 = mkdtempSync(join(tmpdir(), "wt-state-"));
    const statePath = writeState(root0);
    const { core, root } = mk({ storageStatePath: statePath });
    const id = await planned(core);
    const beforeHits = hits.length, beforeCookies = cookiesSeen.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/account` });
    const text = readFileSync(join(core.dir(id), evs.find((e) => e.type === "response")!.path), "utf8");
    expect(text).toContain("已登录 page");
    expect(text).toContain("api:me=alice"); // sub-resource fetch carried the session cookie too
    expect(text).not.toContain(ROTATED); // Set-Cookie value received during capture is a secret
    expect(text).toContain("flag:true"); // too-short / trivial values are not redaction secrets
    expect(text).not.toContain(LS_TOKEN); // localStorage was loaded (the page printed it) but it is redacted in evidence
    expect(text).toMatch(/ls:\S+/);
    expect(text).not.toContain("ls:null");
    const seen = cookiesSeen.slice(beforeCookies);
    expect(seen.some((c) => c.startsWith("/account ") && c.includes(`sessionid=${SESSION}`) && c.includes(`csrftoken=${CSRF}`))).toBe(true);
    expect(seen.some((c) => c.startsWith("/api/me ") && c.includes(`sessionid=${SESSION}`))).toBe(true);
    expect(seen.some((c) => c.includes(FOREIGN))).toBe(false); // other.example's cookie was dropped, never sent
    expect(hits.slice(beforeHits).some((h) => h.startsWith("POST"))).toBe(false); // read-only even when logged in
    // no cookie / localStorage value and not the file path anywhere: state, command log, every evidence file, report
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    for (const f of [...files(root), { name: "report.html", text: html }]) for (const v of [SESSION, CSRF, FOREIGN, LS_TOKEN, ROTATED, statePath, "login-state.json"]) expect(f.text, `${f.name} leaks ${v}`).not.toContain(v);
    // HAR keeps the cookie NAMES (useful for review) with masked values
    const har = JSON.parse(readFileSync(join(core.dir(id), evs.find((e) => e.type === "har")!.path), "utf8"));
    const acct = har.log.entries.find((e: { request: { url: string } }) => /\/account$/.test(e.request.url));
    expect(acct.request.cookies.map((c: { name: string }) => c.name)).toEqual(expect.arrayContaining(["sessionid", "csrftoken"]));
    for (const c of acct.request.cookies) expect(c.value).not.toMatch(/val-/);
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.type === "capture_page");
    expect(log.loginState).toEqual({ cookies: 3, origins: 1, droppedCookies: 1, droppedOrigins: 1 });
    expectHashes(core, id, evs);
    expect(core.verifyCommandLog(id).ok).toBe(true);
  }, 90_000);

  it.skipIf(!hasChromium)("without login state the same page renders logged-out (no cookies are invented)", async () => {
    const { core } = mk();
    const id = await planned(core);
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/account` });
    const text = readFileSync(join(core.dir(id), evs.find((e) => e.type === "response")!.path), "utf8");
    expect(text).toContain("未登录 page");
    expect(text).toContain("api:me=anonymous");
  }, 90_000);
});

describe("loadLoginState", () => {
  const cfg = { allowHosts: ["app.test:8443", "api.app.test"] };
  it("keeps allowlisted cookies/origins, drops others, collects every value as a secret", () => {
    const s = loadLoginState(cfg, "/x", () => JSON.stringify({
      cookies: [
        { name: "JSESSIONID", value: "JSESSval-1111", domain: "app.test", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Strict" },
        { name: "sessionid", value: "SUBval-2222", domain: ".app.test" }, // matches api.app.test + app.test
        { name: "_ga", value: "GAval-3333", domain: ".tracker.test" },
      ],
      origins: [{ origin: "https://app.test:8443", localStorage: [{ name: "refresh_token", value: "RTval-4444" }] }, { origin: "https://tracker.test", localStorage: [{ name: "id", value: "TRval-5555" }] }],
    }));
    expect(s.storageState.cookies.map((c) => c.name)).toEqual(["JSESSIONID", "sessionid"]);
    expect(s.storageState.cookies[1]).toMatchObject({ path: "/", expires: -1, httpOnly: false, secure: false, sameSite: "Lax" });
    expect(s.storageState.origins.map((o) => o.origin)).toEqual(["https://app.test:8443"]);
    expect(s.secrets.sort()).toEqual(["GAval-3333", "JSESSval-1111", "RTval-4444", "SUBval-2222", "TRval-5555"]);
    expect(s.summary).toEqual({ cookies: 2, origins: 1, droppedCookies: 1, droppedOrigins: 1 });
  });
  it("cookie domain: exact host or a non-public-suffix parent only (`.example.com` ok, `com` / `co.uk` refused)", () => {
    const c = { allowHosts: ["shop.example.com", "a.b.co.uk"] };
    const ck = (domain: string) => ({ name: "sessionid", value: "SESSval-77777777", domain });
    const s = loadLoginState(c, "/x", () => JSON.stringify({ cookies: [ck(".example.com"), ck("example.com"), ck("shop.example.com"), ck("com"), ck(".com"), ck("co.uk"), ck(".b.co.uk"), ck("evil-example.com")] }));
    expect(s.storageState.cookies.map((x) => x.domain)).toEqual([".example.com", "example.com", "shop.example.com", ".b.co.uk"]);
    expect(s.summary.droppedCookies).toBe(4);
  });
  it("minimum secret length: short / trivial values (`1`, `true`) are not secrets, real values are", () => {
    const s = loadLoginState(cfg, "/x", () => JSON.stringify({ cookies: [
      { name: "theme", value: "1", domain: "app.test" }, { name: "remember_me", value: "true", domain: "app.test" },
      { name: "lang", value: "zh-TW", domain: "app.test" }, { name: "uid", value: "1234567", domain: "app.test" },
      { name: "sessionid", value: "SESSval-88888888", domain: "app.test" },
    ], origins: [{ origin: "https://app.test:8443", localStorage: [{ name: "beta_flag", value: "false" }, { name: "access_token", value: "ATval-99999999" }] }] }));
    expect(s.secrets.sort()).toEqual(["ATval-99999999", "SESSval-88888888"]);
    expect(s.storageState.cookies).toHaveLength(5); // still loaded into the browser, just not used as redaction strings
  });
  it("accepts a bare cookie array", () => {
    expect(loadLoginState(cfg, "/x", () => JSON.stringify([{ name: "sid", value: "SIDval-9", domain: "app.test" }])).storageState.cookies).toHaveLength(1);
  });
  it("errors never echo the file content", () => {
    const leak = "LEAKval-6666";
    for (const body of [`{"cookies": [{"name":"sessionid","value":"${leak}"`, JSON.stringify({ cookies: [{ name: "sessionid", value: leak }] }), JSON.stringify({ cookies: { sessionid: leak } })]) {
      let err: Error | undefined;
      try { loadLoginState(cfg, "/x", () => body); } catch (e) { err = e as Error; }
      expect(err).toBeInstanceOf(ReplayRejectedError);
      expect(err!.message).not.toContain(leak);
    }
  });
});
