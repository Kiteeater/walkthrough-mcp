export const BLOCKED_EVIDENCE = "walkthrough-blocked-requests/1";

export interface BlockedRequest {
  /** Redacted before it is stored (core applies redactUrl + redactor). */
  url: string;
  method: string;
  /** Playwright resource type (document, image, script, fetch, …) or websocket / popup. */
  type: string;
  reason: string;
}

export interface PageCapture {
  /** PNG */ screenshot: Buffer; /** HAR JSON text */ har: string; /** visible DOM text */ text: string;
  /** Main-frame navigation hops, each fetched by the guard (policy-checked, IP-pinned). */
  navigations: { url: string; status: number; ip: string }[];
  /** Every other request the page made and walkthrough fetched for it (policy-checked, IP-pinned). */
  subresources: { url: string; method: string; type: string; status: number; ip: string }[];
  /** Requests that were NOT allowed (never reached the network). */
  blocked: BlockedRequest[];
}

/**
 * Network guard for capture_page. Every request the browser makes is answered by `request` (allowlist + IP rules,
 * resolved once per host per capture and pinned) or blocked. Throw (ReplayRejectedError) to block.
 */
export interface NavigationGuard {
  /** Main-frame navigation hop (GET, no redirect following). */
  fetch(url: string): Promise<{ status: number; headers: Record<string, string>; body: string; ip: string }>;
  /** Any other request (no redirect following; the capturer re-checks each hop). */
  request?(r: { url: string; method: string; headers: Record<string, string>; body?: Buffer }): Promise<{ status: number; headers: Record<string, string>; body: Buffer; ip: string }>;
  /** Chromium --host-resolver-rules: allowlisted hosts mapped to their checked IPs, everything else ~NOTFOUND. */
  hostResolverRules?: string;
}

export interface Capturer {
  /** Write a PNG screenshot of `url` to `outPath`. */
  screenshot(url: string, outPath: string): Promise<void>;
  /** Optional `method: ui` fallback for hosts without computer use: load `url`, return screenshot + HAR + DOM text. */
  page?(url: string, guard: NavigationGuard): Promise<PageCapture>;
}

const HOP_BY_HOP = /^(content-length|content-encoding|transfer-encoding|connection|keep-alive|set-cookie)$/i;
const MAX_HOPS = 5;
const READ_ONLY = new Set(["GET", "HEAD"]);

/** Playwright-backed capturer. Playwright is loaded lazily so unit tests never need a browser. */
export class PlaywrightCapturer implements Capturer {
  async screenshot(url: string, outPath: string): Promise<void> {
    const { chromium } = await import("playwright");
    const browser = await chromium.launch();
    try {
      const page = await browser.newPage();
      await page.goto(url, { waitUntil: "networkidle" });
      await page.screenshot({ path: outPath, fullPage: true });
    } finally {
      await browser.close();
    }
  }

  async page(url: string, guard: NavigationGuard): Promise<PageCapture> {
    const { chromium } = await import("playwright");
    const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "wt-page-"));
    const harPath = join(dir, "page.har");
    // Chromium's own DNS is replaced: allowlisted hosts → the IPs core already checked; anything else fails to resolve.
    // Defence in depth — every request is answered from the guard anyway, so Chromium should never connect itself.
    const browser = await chromium.launch({ args: [
      `--host-resolver-rules=${guard.hostResolverRules ?? "MAP * ~NOTFOUND"}`,
      // WebRTC (ICE/STUN/TURN) goes around route and the resolver; no proxy → no UDP at all. The init script below
      // also removes the APIs.
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ] });
    const navigations: PageCapture["navigations"] = [];
    const subresources: PageCapture["subresources"] = [];
    const blocked: BlockedRequest[] = [];
    const block = (u: string, method: string, type: string, e: unknown) => blocked.push({ url: u, method, type, reason: String((e as Error)?.message ?? e) });
    let mainBlocked: Error | undefined;
    let finalUrl: string | undefined;
    try {
      // Service workers can fetch outside page.route: blocked. Downloads off.
      const ctx = await browser.newContext({ recordHar: { path: harPath, content: "embed" }, serviceWorkers: "block", acceptDownloads: false });
      // serviceWorkers:"block" alone did not stop registration on a secure-context origin (test/capture-blocking), and
      // WebRTC bypasses route/DNS entirely: before any page script runs, in every frame, service-worker register()
      // rejects and RTCPeerConnection / webkitRTCPeerConnection / RTCDataChannel throw. Attempts are recorded.
      await ctx.exposeBinding("__wtBlocked", (_s, type: string, u: string) => block(String(u), "GET", String(type),
        type === "webrtc" ? "WebRTC is disabled in capture_page" : "service workers are blocked in capture_page"));
      await ctx.addInitScript(() => {
        const rep = (type: string, u: string) => { try { void (window as unknown as { __wtBlocked?: (t: string, u: string) => void }).__wtBlocked?.(type, u); } catch { /* ignore */ } };
        const sw = (navigator as Navigator & { serviceWorker?: ServiceWorkerContainer }).serviceWorker;
        if (sw) {
          const reject = (u: unknown) => { rep("serviceworker", new URL(String(u), location.href).href); return Promise.reject(new DOMException("service workers are blocked by walkthrough", "SecurityError")); };
          try { Object.defineProperty(sw, "register", { value: reject, configurable: false, writable: false }); } catch { /* ignore */ }
        }
        for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel", "RTCIceCandidate", "RTCSessionDescription"]) {
          const blocked = function (cfg?: { iceServers?: { urls?: string | string[] }[] }) {
            const urls = (cfg?.iceServers ?? []).flatMap((s) => ([] as string[]).concat(s?.urls ?? [])).join(" ");
            rep("webrtc", `${name}${urls ? ` ${urls}` : ""}`);
            throw new DOMException("WebRTC is disabled by walkthrough", "NotSupportedError");
          };
          try { Object.defineProperty(window, name, { value: blocked, configurable: false, writable: false }); } catch { /* ignore */ }
        }
      });
      const page = await ctx.newPage();
      // Popups / extra windows: closed at once (their requests are still routed and recorded below).
      ctx.on("page", (p) => { if (p !== page) { block(p.url() || "about:blank", "GET", "popup", "popups/new windows are not allowed in capture_page"); void p.close().catch(() => undefined); } });
      // WebSockets bypass page.route: intercepted with routeWebSocket and never connected (no IP-pinned WS proxy).
      await ctx.routeWebSocket(/.*/, (ws) => { block(ws.url(), "GET", "websocket", "websockets are not proxied by capture_page (no IP pinning)"); void ws.close({ code: 1008, reason: "blocked by walkthrough" }); });
      await ctx.route("**/*", async (route) => {
        const req = route.request();
        const isMain = req.isNavigationRequest() && (() => { try { return req.frame() === page.mainFrame(); } catch { return false; } })(); // popups: no frame yet
        if (!READ_ONLY.has(req.method().toUpperCase())) {
          block(req.url(), req.method(), req.resourceType(), `${req.method()} blocked (read-only: capture_page forwards only GET/HEAD)`);
          return route.abort("blockedbyclient");
        }
        if (isMain) {
          try {
            // Chromium does not re-route redirects of a fulfilled response, so hops are followed HERE, each one
            // through the guard (allowlist + IP rules, pinned IP).
            let u = req.url();
            for (let hop = 0; ; hop++) {
              const r = await guard.fetch(u);
              navigations.push({ url: u, status: r.status, ip: r.ip });
              if (r.status >= 300 && r.status < 400 && r.headers.location) {
                if (hop >= MAX_HOPS) throw new Error("too many redirects");
                u = new URL(r.headers.location, u).toString();
                continue;
              }
              if (u !== req.url()) {
                finalUrl = u;
                return route.fulfill({ status: 200, contentType: "text/html", body: `<meta http-equiv="refresh" content="0;url=${u.replace(/"/g, "%22")}">` });
              }
              const headers = Object.fromEntries(Object.entries(r.headers).filter(([k]) => !HOP_BY_HOP.test(k)));
              // The guard decoded the body as UTF-8 and fulfill re-encodes it as UTF-8: say so, or Chromium would guess
              // windows-1252 for a text/html without charset and mangle non-ASCII page text.
              for (const k of Object.keys(headers)) if (k.toLowerCase() === "content-type" && /^text\//i.test(headers[k]) && !/charset=/i.test(headers[k])) headers[k] += "; charset=utf-8";
              return route.fulfill({ status: r.status, headers, body: r.body });
            }
          } catch (e) {
            mainBlocked ??= e as Error;
            block(req.url(), req.method(), "document", e);
            return route.abort("blockedbyclient");
          }
        }
        // Everything else (images, scripts, XHR/fetch, iframes and their navigations, popups' requests, …):
        // fetched by the guard and fulfilled from it, redirects followed here hop by hop — Chromium never connects.
        const type = req.resourceType();
        let u = req.url();
        try {
          if (!guard.request) throw new Error("sub-resource requests are not allowed (no guard)");
          if (!/^https?:$/.test(new URL(u).protocol)) {
            if (/^(data|blob|about):/.test(u)) return route.continue(); // in-page, no network
            throw new Error(`unsupported scheme ${new URL(u).protocol}`);
          }
          const headers = Object.fromEntries(Object.entries(await req.allHeaders()).filter(([k]) => !HOP_BY_HOP.test(k) && !k.startsWith(":") && k !== "host" && k !== "cookie"));
          let method = req.method();
          let body = req.postDataBuffer() ?? undefined;
          for (let hop = 0; ; hop++) {
            const r = await guard.request({ url: u, method, headers, body });
            subresources.push({ url: u, method, type, status: r.status, ip: r.ip });
            if (r.status >= 300 && r.status < 400 && r.headers.location) {
              if (hop >= MAX_HOPS) throw new Error("too many redirects");
              u = new URL(r.headers.location, u).toString();
              if (r.status === 303 || ((r.status === 301 || r.status === 302) && method === "POST")) { method = "GET"; body = undefined; }
              continue;
            }
            return route.fulfill({ status: r.status, headers: Object.fromEntries(Object.entries(r.headers).filter(([k]) => !HOP_BY_HOP.test(k))), body: r.body });
          }
        } catch (e) {
          block(u, req.method(), type, e);
          return route.abort("blockedbyclient");
        }
      });
      await page.goto(url, { waitUntil: "networkidle", timeout: 30_000 }).catch((e) => { if (!mainBlocked) throw e; });
      if (finalUrl && !mainBlocked) await page.waitForURL(finalUrl, { waitUntil: "networkidle", timeout: 30_000 }).catch((e) => { if (!mainBlocked) throw e; });
      if (mainBlocked) throw mainBlocked;
      await page.waitForTimeout(300); // late timers (window.open, new WebSocket) still go through the handlers above
      const screenshot = await page.screenshot({ fullPage: true });
      const text = await page.innerText("body").catch(() => "");
      await ctx.close(); // flushes the HAR
      return { screenshot, har: readFileSync(harPath, "utf8"), text, navigations, subresources, blocked };
    } finally {
      await browser.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
