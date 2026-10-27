// B1: capture_evidence type=screenshot (and flow screenshot captures) must take the same guarded browser path as
// capture_page. SAFETY: no browser in this file ever navigates to the real production IP. Browser "must be blocked"
// targets are a local stand-in (127.0.0.2, marked core-blocked via addTestCoreBlocked) with a server counting every
// connection; the real address only appears in a pure guard check that fails before any browser starts.
import { createRequire } from "node:module";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

let srv: http.Server, port = 0, srvHits = 0;
const SECRET = "SHOTblockedTok9917";
let trap: net.Server, trapPort = 0, trapHits = 0;
let undo: () => void = () => undefined;
const core = (replay: ReplayConfig | undefined, capturer: Capturer = new PlaywrightCapturer()) =>
  new WalkthroughCore({ root: mkdtempSync(join(tmpdir(), "wt-shot-")), sandboxFactory: () => sandbox, capturer, redactor: new Redactor([]), ...(replay ? { replay } : {}) });

beforeAll(async () => {
  srv = http.createServer((req, res) => {
    srvHits++;
    if (req.url === "/with-blocked") { res.writeHead(200, { "content-type": "text/html" }); return res.end(`<h1>page</h1><img src="http://${STANDIN}:${trapPort}/x.png?token=${SECRET}">`); }
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
    const entry = JSON.parse(readFileSync(join(c.dir(w.id), "commands.jsonl"), "utf8").trim().split("\n").at(-1)!);
    expect(entry).toMatchObject({ type: "capture_screenshot", evidenceIds: [ev.id], blockedCount: 0 });
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
    const before = srvHits;
    const err = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(String(err.message)).toMatch(/allowHosts|not allowed|allowlist/i);
    expect(srvHits).toBe(before); // the not-allowlisted server got no request at all
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

  it("requests blocked while loading the page are written (redacted) to the command log", async () => {
    const c = core({ allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const before = trapHits;
    const ev = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/with-blocked` });
    expect(trapHits).toBe(before);
    const raw = readFileSync(join(c.dir(w.id), "commands.jsonl"), "utf8");
    expect(raw).not.toContain(SECRET);
    const entry = raw.trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.type === "capture_screenshot");
    expect(entry).toMatchObject({ evidenceIds: [ev.id], executedBy: "core" });
    expect(entry.blockedCount).toBeGreaterThanOrEqual(1);
    expect(entry.blocked.some((b: { url: string }) => b.url.includes(`${STANDIN}:${trapPort}/x.png`))).toBe(true);
    expect(c.verifyCommandLog(w.id).ok).toBe(true);
  }, 60_000);
});

describe("B1: flow policy is internal", () => {
  it("captureEvidence ignores any extra policy argument: without replay.allowHosts a screenshot is still refused", async () => {
    let called = 0;
    const c = core(undefined, { page: async () => { called++; throw new Error("must not run"); } });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const call = c.captureEvidence as unknown as (id: string, i: unknown, o: unknown) => Promise<unknown>;
    const err = await call.call(c, w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` }, { policy: { allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] } }).catch((e) => e);
    expect(err).toBeInstanceOf(ReplayRejectedError);
    expect(called).toBe(0);
  });
  it("the flow path derives its own policy (own host only) and still refuses core-blocked targets before the browser", async () => {
    let called = 0;
    const c = core(undefined, { page: async () => { called++; throw new Error("must not run"); } });
    await expect(runFlow(c, { title: "f", sandbox: SB, captures: [{ as: "s", type: "screenshot", url: `http://${STANDIN}:${trapPort}/` }], claims: [] }, { skipWait: true })).rejects.toThrow(/core blocklist/);
    expect(called).toBe(0);
  });
  it("the flow capability is not reachable from the instance, its prototype or the package entry", async () => {
    const c = core(both());
    const proto = WalkthroughCore.prototype;
    expect(Object.getOwnPropertyNames(proto).filter((k) => /flow/i.test(k))).toEqual([]);
    expect(Object.getOwnPropertySymbols(proto)).toEqual([]);
    expect(Object.keys(c).filter((k) => /flow/i.test(k))).toEqual([]);
    expect(Object.getOwnPropertySymbols(c)).toEqual([]);
    expect("captureFlowScreenshot" in c).toBe(false);
    const dist = await import(join(process.cwd(), "dist/core/index.js"));
    for (const mod of [dist, await import("../src/core/index.js")]) {
      expect(Object.keys(mod).filter((k) => /flowScreenshot|captureFlow/i.test(k))).toEqual([]);
      expect(Object.values(mod).some((v) => v instanceof WeakMap)).toBe(false);
    }
  });
});

describe("screenshot command log", () => {
  const okPage = (url: string) => ({ screenshot: Buffer.from("png"), har: JSON.stringify({ log: { entries: [] } }), text: "", navigations: [{ url, status: 200, ip: "127.0.0.1" }], subresources: [], blocked: [] });
  it("always writes a capture_screenshot entry; navigation URLs have every query value masked", async () => {
    const c = core(both(), { page: async (u) => okPage(u) });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    const ev = await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/?sess=UNKNOWNtok4421` });
    const raw = readFileSync(join(c.dir(w.id), "commands.jsonl"), "utf8");
    expect(raw).not.toContain("UNKNOWNtok4421");
    const entry = JSON.parse(raw.trim().split("\n").at(-1)!);
    expect(entry).toMatchObject({ type: "capture_screenshot", evidenceIds: [ev.id], blockedCount: 0 });
    expect(entry.navigations[0].url).toContain("sess=");
    expect(c.verifyCommandLog(w.id).ok).toBe(true);
  });
  it("capture_page also masks every query value in navigation URLs", async () => {
    const c = core(both(), { page: async (u) => okPage(u) });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    await c.planChecks(w.id, { goal: "g", checks: [{ id: "c1", intent: "c1", method: "ui", target: "page", expect: { type: "ui", value: { text: { contains: "x" } } }, severity_if_fail: "high" } as never] });
    await c.capturePage(w.id, { checkId: "c1", url: `http://127.0.0.1:${port}/?sess=UNKNOWNtok7731` });
    const raw = readFileSync(join(c.dir(w.id), "commands.jsonl"), "utf8");
    const entry = raw.trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.type === "capture_page");
    expect(JSON.stringify(entry.navigations)).not.toContain("UNKNOWNtok7731");
  });
  it("if the command log cannot be written, the PNG is removed and no evidence is registered", async () => {
    const c = core(both(), { page: async (u) => okPage(u) });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    mkdirSync(join(c.dir(w.id), "commands.jsonl"), { recursive: true }); // a directory: appending fails
    await expect(c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` })).rejects.toThrow();
    expect(existsSync(join(c.dir(w.id), "evidence", "ev-1.png"))).toBe(false);
    expect(c.load(w.id).evidence).toHaveLength(0);
  });
  // Precondition: a non-root user. The unlink failure comes from a read-only directory (0555), which root ignores
  // (CAP_DAC_OVERRIDE), so as root the PNG would be removed and the AggregateError path never taken.
  it.skipIf(process.getuid?.() === 0)("if the log write fails AND the PNG cannot be removed, both errors are reported (log error first, also as cause)", async () => {
    const c = core(both(), { page: async (u) => okPage(u) });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    mkdirSync(join(c.dir(w.id), "commands.jsonl"), { recursive: true }); // appending fails (EISDIR)
    const evDir = join(c.dir(w.id), "evidence");
    mkdirSync(evDir, { recursive: true });
    writeFileSync(join(evDir, "ev-1.png"), ""); // existing writable file: overwrite works...
    chmodSync(evDir, 0o555); // ...but unlinking it from a read-only directory fails (EACCES)
    let err: unknown;
    try { await c.captureEvidence(w.id, { type: "screenshot", url: `http://127.0.0.1:${port}/` }); } catch (e) { err = e; } finally { chmodSync(evDir, 0o755); }
    expect(err).toBeInstanceOf(AggregateError);
    const agg = err as AggregateError;
    expect(agg.errors).toHaveLength(2);
    expect((agg.errors[0] as NodeJS.ErrnoException).code).toBe("EISDIR");
    expect((agg.errors[1] as NodeJS.ErrnoException).code).toBe("EACCES");
    expect(agg.cause).toBe(agg.errors[0]);
    expect(agg.message).toContain("evidence/ev-1.png");
    expect(c.load(w.id).evidence).toHaveLength(0);
  });
  it("capture_page masks every query value in sub-resource URLs too", async () => {
    const page = (u: string) => ({ ...okPage(u), subresources: [{ url: `http://127.0.0.1:${port}/app.js?v=UNKNOWNsub5512&b=2`, method: "GET", type: "script", status: 200, ip: "127.0.0.1" }] });
    const c = core(both(), { page: async (u) => page(u) });
    const w = c.startWalkthrough({ title: "t", sandbox: SB });
    await c.planChecks(w.id, { goal: "g", checks: [{ id: "c1", intent: "c1", method: "ui", target: "page", expect: { type: "ui", value: { text: { contains: "x" } } }, severity_if_fail: "high" } as never] });
    await c.capturePage(w.id, { checkId: "c1", url: `http://127.0.0.1:${port}/` });
    const raw = readFileSync(join(c.dir(w.id), "commands.jsonl"), "utf8");
    expect(raw).not.toContain("UNKNOWNsub5512");
    const entry = raw.trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.type === "capture_page");
    expect(entry.subresources).toHaveLength(1);
    expect(entry.subresources[0].url).toMatch(/app\.js\?v=.+&b=/);
    expect(entry.subresources[0].url).not.toContain("b=2");
  });
  it("runFlow with a core that lacks the flow capability fails with a clear error before any capture", async () => {
    let called = 0;
    const real = core(both(), { page: async () => { called++; throw new Error("must not run"); } });
    const fake = Object.create(real) as WalkthroughCore; // same methods, but not the registered instance
    await expect(runFlow(fake, { title: "f", sandbox: SB, captures: [{ as: "s", type: "screenshot", url: `http://127.0.0.1:${port}/` }], claims: [] }, { skipWait: true }))
      .rejects.toThrow("runFlow: flow screenshot capture is not available for this core");
    expect(called).toBe(0);
  });
});
