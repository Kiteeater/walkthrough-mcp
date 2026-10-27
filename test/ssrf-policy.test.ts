import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PlaywrightCapturer, Redactor, ReplayRejectedError, WalkthroughCore, type Capturer, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { ipProblem, norm } from "../src/core/egress/policy.js";
import { SB } from "./helpers.js";

describe("IPv6 forms embedding IPv4 are judged by the IPv4 rules", () => {
  it.each([
    ["64:ff9b::a9fe:a9fe", "169.254.169.254", /metadata/], // NAT64
    ["2002:a9fe:a9fe::1", "169.254.169.254", /metadata/],  // 6to4
    ["::127.0.0.1", "127.0.0.1", /denied/],                  // IPv4-compatible
  ])("%s → %s rejected", (ip, v4, why) => {
    expect(norm(ip)).toBe(v4);
    expect(ipProblem(ip)).toMatch(why);
    // even with broad CIDRs listed: metadata stays denied; loopback only as the exact IPv4 host
    expect(ipProblem(ip, ["169.254.0.0/16", "64:ff9b::/96", "2002::/16", "::/96"])).toBeTruthy();
  });
  it("embedded loopback is allowed only by the exact IPv4 CIDR", () => {
    expect(ipProblem("::127.0.0.1", ["127.0.0.1/32"])).toBeUndefined();
    expect(ipProblem("64:ff9b::7f00:2", ["127.0.0.1/32"])).toMatch(/denied/);
    expect(ipProblem("2002:0a00:0001::", [])).toMatch(/denied/); // 10.0.0.1 via 6to4
    expect(ipProblem("64:ff9b::808:808")).toBeUndefined();        // public 8.8.8.8 via NAT64
  });
  it.each(["224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "198.18.0.1", "198.19.255.254", "2001:0:4136:e378::1", "ff02::1"])("%s is denied", (ip) => {
    expect(ipProblem(ip)).toMatch(/denied/);
  });
});

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
function coreWith(replay: ReplayConfig | undefined, resolver: (h: string) => Promise<string>, capturer: Capturer) {
  const root = mkdtempSync(join(tmpdir(), "wt-ssrf-"));
  return new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer, redactor: new Redactor([]), replay, resolver });
}
async function planned(core: WalkthroughCore) {
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [{ id: "p", intent: "p", method: "ui", target: "x", expect: { type: "ui", value: { har: { urlMatch: "/", status: 200 } } }, severity_if_fail: "high" }] });
  return w.id;
}
/** Fake browser: follows main-frame redirects only through the guard, like the Playwright route handler. */
const fakeBrowser: Capturer = {
  screenshot: async (_u, o) => writeFileSync(o, "png"),
  async page(url, guard) {
    const navigations = [];
    let u = url;
    for (let i = 0; i < 5; i++) {
      const r = await guard.fetch(u);
      navigations.push({ url: u, status: r.status, ip: r.ip });
      if (r.status >= 300 && r.status < 400 && r.headers.location) { u = new URL(r.headers.location, u).toString(); continue; }
      break;
    }
    return { screenshot: Buffer.from("png"), har: JSON.stringify({ log: { entries: [] } }), text: "", navigations, subresources: [], blocked: [] };
  },
};

describe("capture_page uses the replay policy for the main page", () => {
  let srv: http.Server, port = 0;
  beforeAll(async () => {
    srv = http.createServer((req, res) => {
      if (req.url === "/meta") { res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }); return res.end(); }
      if (req.url === "/hop") { res.writeHead(302, { location: "/final" }); return res.end(); }
      if (req.url === "/away") { res.writeHead(302, { location: "http://evil.example/" }); return res.end(); }
      res.writeHead(200, { "content-type": "text/html" }); res.end("<h1>ok</h1>");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    port = (srv.address() as AddressInfo).port;
  });
  afterAll(() => srv.close());
  const cfg = (): ReplayConfig => ({ allowHosts: [`demo.local:${port}`, "169.254.169.254"], allowCidrs: ["127.0.0.1/32"] });
  const local = async () => "127.0.0.1";

  it("needs replay config", async () => {
    const core = coreWith(undefined, local, fakeBrowser);
    await expect(core.capturePage(await planned(core), { checkId: "p", url: "http://demo.local/" })).rejects.toThrow(/allowHosts/);
  });
  it("non-allowlisted host is rejected before any browser starts", async () => {
    let started = false;
    const core = coreWith(cfg(), local, { ...fakeBrowser, page: async (...a) => { started = true; return fakeBrowser.page!(...a); } });
    await expect(core.capturePage(await planned(core), { checkId: "p", url: "http://evil.example/" })).rejects.toThrow(/not in the replay allowlist/);
    expect(started).toBe(false);
  });
  it("metadata IP is rejected (direct, and via an allowlisted hostname resolving to it)", async () => {
    const core = coreWith(cfg(), async () => "169.254.169.254", fakeBrowser);
    const id = await planned(core);
    await expect(core.capturePage(id, { checkId: "p", url: "http://169.254.169.254/" })).rejects.toThrow(/metadata/);
    await expect(core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/` })).rejects.toThrow(/metadata/);
  });
  it("allowlisted URL redirecting to the metadata IP / a foreign host is rejected at the hop", async () => {
    const core = coreWith(cfg(), local, fakeBrowser);
    const id = await planned(core);
    await expect(core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/meta` })).rejects.toThrow(ReplayRejectedError);
    await expect(core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/away` })).rejects.toThrow(/evil.example/);
    const ok = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/` });
    expect(ok).toHaveLength(3);
    expect(core.verifyCommandLog(id)).toEqual({ ok: true, entries: 1 }); // capture_page entries verify (evidenceIds[])
  });

  // Real Chromium (runs where `npx playwright install chromium` was done, e.g. locally and in CI e2e; skipped otherwise).
  const hasChromium = (() => { try { return existsSync(require("playwright").chromium.executablePath()); } catch { return false; } })();
  if (process.env.REQUIRE_CHROMIUM && !hasChromium) throw new Error("REQUIRE_CHROMIUM is set but Chromium is not installed");
  it.skipIf(!hasChromium)("real Playwright: redirect hop to 169.254.169.254 is blocked; main document comes from the pinned fetcher", async () => {
    const core = coreWith(cfg(), local, new PlaywrightCapturer());
    const id = await planned(core);
    await expect(core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/meta` })).rejects.toThrow(/metadata/);
    // demo.local only resolves through OUR resolver: Chromium could not load it on its own, so success proves pinning.
    const evs = await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/` });
    expect(evs.map((e) => e.type)).toEqual(["screenshot", "har", "response"]);
    // an allowed redirect is followed hop by hop by the guard and logged
    await core.capturePage(id, { checkId: "p", url: `http://demo.local:${port}/hop` });
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(log.at(-1).navigations.map((n: { url: string }) => new URL(n.url).pathname)).toEqual(["/hop", "/final", "/final"]);
  }, 60_000);
});
