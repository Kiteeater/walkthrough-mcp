// A2 behaviour lock: what replay.allowHosts lets through today, written down BEFORE the allowHosts parsing was merged
// into core/egress/allowhosts.ts. Every expectation here passed unchanged on main (bd331b2) and after the merge.
// Some rows lock quirks on purpose (no wildcards, bracketed IPv6 entries never match a hop); changing one of them is a
// behaviour change and belongs in its own PR. No network: the resolver is a stub and every address is loopback.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkHop, loadLoginState, Redactor, WalkthroughCore, type Capturer, type ReplayConfig, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

const LOOPBACK = "127.0.0.1";
const stubResolver = async () => LOOPBACK;
const cfg = (allowHosts: string[]): ReplayConfig => ({ allowHosts, allowCidrs: [`${LOOPBACK}/32`] });
const verdict = (allowHosts: string[], url: string) =>
  checkHop(cfg(allowHosts), new URL(url), stubResolver).then(() => "allow", (e: Error) => (/allowlist/.test(e.message) ? "deny" : `error: ${e.message}`));

describe("allowHosts hop verdicts (checkHop)", () => {
  it.each([
    // bare host: any port, case-insensitive, no subdomains, no suffix tricks
    [["shop.example"], "http://shop.example/", "allow"],
    [["shop.example"], "https://shop.example:8443/", "allow"],
    [["shop.example"], "http://SHOP.Example/", "allow"],
    [["shop.example"], "http://a.shop.example/", "deny"],
    [["shop.example"], "http://shop.example.evil/", "deny"],
    // host:port: only that port; the default port of the scheme counts
    [["Shop.Example:8080"], "http://shop.example:8080/", "allow"],
    [["shop.example:8080"], "http://shop.example/", "deny"],
    [["shop.example:443"], "https://shop.example/", "allow"],
    [["shop.example:443"], "http://shop.example/", "deny"],
    [["shop.example:80"], "http://shop.example/", "allow"],
    // no wildcard support
    [["*.example"], "http://a.example/", "deny"],
    [["*"], "http://a.example/", "deny"],
    // IP literals
    [["127.0.0.1"], "http://127.0.0.1:9/", "allow"],
    [["127.0.0.1:9"], "http://127.0.0.1:9/", "allow"],
    [["127.0.0.1:9"], "http://127.0.0.1:10/", "deny"],
    // IPv6 entries never match a hop (quirk, locked)
    [["[::1]:8080"], "http://[::1]:8080/", "deny"],
    [["[::1]"], "http://[::1]/", "deny"],
    [["::1"], "http://[::1]/", "deny"],
    // one matching entry among others is enough
    [["other.example", "shop.example:8080"], "http://shop.example:8080/", "allow"],
  ])("%j  %s → %s", async (hosts, url, want) => {
    expect(await verdict(hosts, url)).toBe(want);
  });
});

describe("allowHosts in capture_page pinning (Chromium host-resolver rules)", () => {
  it("one MAP per distinct allowed hostname, ports folded, IP literals and denied hosts skipped (a `*.example` entry becomes a Chromium wildcard MAP; requests are still judged per hop by checkHop)", async () => {
    let rules = "";
    const capturer: Capturer = { screenshot: async () => {}, page: async (_u, guard) => { rules = guard.hostResolverRules ?? ""; throw new Error("stop"); } };
    const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
    const resolver = async (h: string) => (h === "denied.local" ? "10.0.0.5" : LOOPBACK);
    const replay = cfg(["Demo.Local:8080", "demo.local", "127.0.0.1", "[::1]:9", "denied.local", "*.example"]);
    const core = new WalkthroughCore({ root: mkdtempSync(join(tmpdir(), "wt-a2-")), sandboxFactory: () => sandbox, capturer, redactor: new Redactor([]), replay, resolver });
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.planChecks(w.id, { goal: "g", checks: [{ id: "p", intent: "p", method: "ui", target: "x", expect: { type: "ui", value: { har: { urlMatch: "/", status: 200 } } }, severity_if_fail: "high" }] });
    await expect(core.capturePage(w.id, { checkId: "p", url: "http://demo.local/" })).rejects.toThrow("stop");
    expect(rules).toBe("MAP demo.local 127.0.0.1, MAP *.example 127.0.0.1, MAP * ~NOTFOUND");
  });
});

describe("allowHosts in login state (loadLoginState keeps its own matching)", () => {
  const load = (allowHosts: string[], state: unknown) => loadLoginState(cfg(allowHosts), "/x", () => JSON.stringify(state));
  const ck = (domain: string) => ({ name: "s", value: "v-0123456789", domain });
  it("cookie domains: port and brackets stripped from entries, then exact or non-public parent match", () => {
    const s = load(["shop.example:8080", "[::1]:9", "Mixed.Case", "*.example"], { cookies: ["shop.example", ".shop.example", "::1", "mixed.case", "a.example", "*.example", "example"].map(ck) });
    expect(s.storageState.cookies.map((c) => c.domain)).toEqual(["shop.example", ".shop.example", "::1", "mixed.case", "*.example"]);
    expect(s.summary.droppedCookies).toBe(2);
  });
  it("origins: entry must equal the origin's host (with port) or its hostname; default ports are not filled in", () => {
    const o = (origin: string) => ({ origin, localStorage: [] });
    const s = load(["shop.example:8080", "mixed.case", "[::1]:9", "secure.example:443"],
      { origins: ["http://shop.example:8080", "http://shop.example", "https://mixed.case:9999", "http://[::1]:9", "http://[::1]", "https://secure.example", "ftp://mixed.case"].map(o) });
    expect(s.storageState.origins.map((x) => x.origin)).toEqual(["http://shop.example:8080", "https://mixed.case:9999", "http://[::1]:9"]);
    expect(s.summary.droppedOrigins).toBe(4);
  });
});
