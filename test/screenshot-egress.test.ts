// B1: capture_evidence type=screenshot (and flow screenshot captures) must take the same guarded browser path as
// capture_page. SAFETY: no browser in this file ever navigates to the real production IP. Browser "must be blocked"
// targets are a local stand-in (127.0.0.2, marked core-blocked via addTestCoreBlocked) with a server counting every
// connection; the real address only appears in a pure guard check that fails before any browser starts.
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { addTestCoreBlocked, checkHop, CORE_BLOCKED_IPS, PlaywrightCapturer, Redactor, ReplayRejectedError, runFlow, WalkthroughCore, type Capturer, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const require = createRequire(import.meta.url);
const hasChromium = (() => { try { return existsSync(require("playwright").chromium.executablePath()); } catch { return false; } })();
if (process.env.REQUIRE_CHROMIUM && !hasChromium) throw new Error("REQUIRE_CHROMIUM is set but Chromium is not installed");

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const PROD = CORE_BLOCKED_IPS[0];
const STANDIN = "127.0.0.2";

let srv: http.Server, port = 0;
let trap: net.Server, trapPort = 0, trapHits = 0;
let undo: () => void = () => undefined;
const core = (replay: ReplayConfig | undefined, capturer: Capturer = new PlaywrightCapturer()) =>
  new WalkthroughCore({ root: mkdtempSync(join(tmpdir(), "wt-shot-")), sandboxFactory: () => sandbox, capturer, redactor: new Redactor([]), ...(replay ? { replay } : {}) });

beforeAll(async () => {
  srv = http.createServer((req, res) => {
    if (req.url === "/redir") { res.writeHead(302, { location: `http://${STANDIN}:${trapPort}/` }); return res.end(); }
    res.writeHead(200, { "content-type": "text/html" }); res.end("<h1>ok</h1>");
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
  // Trap on the stand-in: any TCP connection at all is a guard failure.
  trap = net.createServer((s) => { trapHits++; s.destroy(); });
  await new Promise<void>((r) => trap.listen(0, STANDIN, r));
  trapPort = (trap.address() as AddressInfo).port;
  undo = addTestCoreBlocked(STANDIN);
});
afterAll(async () => { undo(); await new Promise((r) => srv.close(r)); await new Promise((r) => trap.close(r)); });

const both = (): ReplayConfig => ({ allowHosts: [`127.0.0.1:${port}`, `${STANDIN}:${trapPort}`], allowCidrs: ["127.0.0.1/32", `${STANDIN}/32`] });

describe("B1: guard unit check (no browser)", () => {
  it("the real production IP is refused by checkHop even when allowlisted", async () => {
    const cfg: ReplayConfig = { allowHosts: [PROD], allowCidrs: [`${PROD}/32`] };
    await expect(checkHop(cfg, new URL(`http://${PROD}/`))).rejects.toThrow(ReplayRejectedError);
    await expect(checkHop(cfg, new URL(`http://${PROD}/`))).rejects.toThrow(/core blocklist/);
  });
  it("capture_evidence screenshot to the production IP fails in core before the browser is called", async () => {
    let called = 0;
    const c = core({ allowHosts: [PROD], allowCidrs: [`${PROD}/32`] }, { page: async () => { called++; throw new Error("must not run"); } });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    await expect(c.captureEvidence(w.id, { type: "screenshot", url: `http://${PROD}/` })).rejects.toThrow(/core blocklist/);
    expect(called).toBe(0);
  });
  it("no unguarded screenshot entry point is left on the Playwright capturer", () => {
    expect("screenshot" in PlaywrightCapturer.prototype).toBe(false);
  });
  it("without replay.allowHosts a screenshot is refused", async () => {
    const c = core(undefined, { page: async () => { throw new Error("must not run"); } });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    await expect(c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` })).rejects.toThrow(ReplayRejectedError);
  });
});

describe.skipIf(!hasChromium)("B1: screenshot through real Chromium", () => {
  it("allowed local page: screenshot stored, only one evidence item", async () => {
    const c = core(both());
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const ev = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` });
    expect(readFileSync(join(c.dir(w.id), ev.path)).subarray(1, 4).toString()).toBe("PNG");
    expect(c.load(w.id).evidence).toHaveLength(1);
  }, 60_000);

  it("(1) direct core-blocked target (stand-in, even allowlisted) throws the guard error; no connection", async () => {
    const c = core(both());
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const before = trapHits;
    const err = await c.captureEvidence(w.id, { type: "screenshot", url: `http://${STANDIN}:${trapPort}/` }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(String(err.message)).toMatch(/core blocklist/);
    expect(trapHits).toBe(before);
  }, 60_000);

  it("(2) host outside allowHosts throws the guard error", async () => {
    const c = core({ allowHosts: [`127.0.0.1:${port + 1}`], allowCidrs: ["127.0.0.1/32"] });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const err = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(String(err.message)).toMatch(/allowHosts|not allowed|allowlist/i);
  }, 60_000);

  it("(3) 302 from an allowed page to the core-blocked stand-in throws the guard error; no connection", async () => {
    const c = core(both());
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const before = trapHits;
    const err = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/redir` }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(String(err.message)).toMatch(/core blocklist/);
    expect(trapHits).toBe(before);
    expect(c.load(w.id).evidence).toHaveLength(0);
  }, 60_000);

  it("flow screenshot captures use the guarded path: own page works, 302 to the stand-in throws; no connection", async () => {
    const ok = core(undefined);
    const r = await runFlow(ok, { title: "f", sandbox: SB, captures: [{ as: "s", type: "screenshot", url: `http://127.0.0.1:${port}/` }], claims: [] }, { skipWait: true });
    expect(ok.load(r.id).evidence[0].kind).toBe("screenshot");
    const bad = core(undefined);
    const before = trapHits;
    const err = await runFlow(bad, { title: "f", sandbox: SB, captures: [{ as: "s", type: "screenshot", url: `http://127.0.0.1:${port}/redir` }], claims: [] }, { skipWait: true }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(trapHits).toBe(before);
  }, 60_000);
});
