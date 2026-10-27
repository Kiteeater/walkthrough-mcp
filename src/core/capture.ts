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
  /** WebSockets that passed the guard (allowlisted host, checked + pinned IP) and were connected. */
  websockets?: { url: string; ip: string; sent: number; dropped: number; received: number }[];
  /** Every message the page tried to send on a connected WebSocket, forwarded or dropped (core redacts before storing). */
  wsMessages?: WsPageMessage[];
  /** Values of Set-Cookie headers the guard received during the capture (secrets for the capture; never stored). */
  setCookieValues?: string[];
}

export interface WsPageMessage {
  url: string;
  /** true: matched the per-host outbound allowlist exactly and was sent; false: dropped (receive-only). */
  forwarded: boolean;
  /** Text payload (binary: base64). */
  data: string;
  binary: boolean;
  bytes: number;
}

/** Playwright storageState subset (cookies + localStorage per origin). */
export interface LoginStorageState {
  cookies: { name: string; value: string; domain: string; path: string; expires: number; httpOnly: boolean; secure: boolean; sameSite: "Strict" | "Lax" | "None" }[];
  origins: { origin: string; localStorage: { name: string; value: string }[] }[];
}

/**
 * Network guard for capture_page. Every request the browser makes is answered by `request` (allowlist + IP rules,
 * resolved once per host per capture and pinned) or blocked. Throw (ReplayRejectedError) to block.
 */
export interface NavigationGuard {
  /** Main-frame navigation hop (GET, no redirect following). */
  fetch(url: string, headers?: Record<string, string>): Promise<{ status: number; headers: Record<string, string>; body: string; ip: string }>;
  /** Any other request (no redirect following; the capturer re-checks each hop). */
  request?(r: { url: string; method: string; headers: Record<string, string>; body?: Buffer }): Promise<{ status: number; headers: Record<string, string>; body: Buffer; ip: string }>;
  /** Chromium --host-resolver-rules: allowlisted hosts mapped to their checked IPs, everything else ~NOTFOUND. */
  hostResolverRules?: string;
  /** WebSocket pre-check (issue #18): allowlist + IP rules on the ws(s) URL; returns the pinned IP. Throw to block. */
  websocket?(url: string, headers?: Record<string, string>): Promise<import("./replay.js").GuardedWebSocket & {
    /** Exact text messages the page may send on this socket (capture.webSocketOutbound); everything else is dropped. */
    outbound: string[];
  }>;
  /** Login state loaded into the browser context (issue #19). Cookies are sent by Chromium's own per-origin rules. */
  storageState?: LoginStorageState;
}

export interface Capturer {
  /**
   * Load `url` under `guard` (every request, redirect and WebSocket goes through it) and return screenshot + HAR + DOM
   * text. This is the ONLY way the browser is driven: capture_page and capture_evidence type=screenshot both use it,
   * so there is no unguarded navigation path (B1).
   */
  page?(url: string, guard: NavigationGuard): Promise<PageCapture>;
}

const HOP_BY_HOP = /^(content-length|content-encoding|transfer-encoding|connection|keep-alive|set-cookie)$/i;
const MAX_HOPS = 5;
const READ_ONLY = new Set(["GET", "HEAD"]);

/** Playwright-backed capturer. Playwright is loaded lazily so unit tests never need a browser. */
export class PlaywrightCapturer implements Capturer {
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
    const websockets: NonNullable<PageCapture["websockets"]> = [];
    const wsMessages: WsPageMessage[] = [];
    const setCookieValues: string[] = [];
    const noteSetCookie = (h: Record<string, string>) => {
      for (const [k, v] of Object.entries(h)) if (k.toLowerCase() === "set-cookie")
        for (const part of String(v).split(/,(?=\s*[^;,=\s]+=)/)) { const m = /^\s*[^=;]+=([^;]*)/.exec(part); if (m?.[1]) setCookieValues.push(m[1].trim()); }
    };
    const block = (u: string, method: string, type: string, e: unknown) => blocked.push({ url: u, method, type, reason: String((e as Error)?.message ?? e) });
    let mainBlocked: Error | undefined;
    let finalUrl: string | undefined;
    try {
      // Service workers can fetch outside page.route: blocked. Downloads off.
      const ctx = await browser.newContext({ ...(guard.storageState ? { storageState: guard.storageState } : {}), recordHar: { path: harPath, content: "embed" }, serviceWorkers: "block", acceptDownloads: false });
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
      // WebSockets bypass page.route (issue #18): each one is checked by the guard (allowlist + IP rules, same pinned
      // resolution) and then proxied by walkthrough over its own IP-pinned connection; Chromium never connects itself.
      await ctx.routeWebSocket(/.*/, async (ws) => {
        const u = ws.url();
        try {
          if (!guard.websocket) throw new Error("websockets are not allowed (no guard)");
          // Cookies Chromium holds for this ws URL's http(s) origin (login state); Chromium itself never connects.
          const hu = new URL(u); hu.protocol = hu.protocol === "wss:" ? "https:" : "http:";
          const jar = (await ctx.cookies(hu.toString())).map((c) => `${c.name}=${c.value}`).join("; ");
          const conn = await guard.websocket(u, jar ? { cookie: jar } : undefined);
          const rec = { url: u, ip: conn.ip, sent: 0, dropped: 0, received: 0 };
          websockets.push(rec);
          // Receive-only by default: a page→server message goes out only if it EXACTLY matches the host's outbound
          // allowlist (e.g. a subscribe handshake). Every attempt is kept (core redacts it into evidence).
          ws.onMessage((m) => {
            const binary = typeof m !== "string";
            const data = binary ? Buffer.from(m as Buffer).toString("base64") : (m as string);
            const forwarded = !binary && conn.outbound.includes(m as string);
            wsMessages.push({ url: u, forwarded, data, binary, bytes: binary ? (m as Buffer).length : Buffer.byteLength(m as string) });
            if (forwarded) { rec.sent++; conn.send(m); return; }
            rec.dropped++;
            block(u, "SEND", "websocket-message", "page→server WebSocket message dropped (receive-only; not in capture.webSocketOutbound)");
          });
          conn.onMessage((m) => { rec.received++; ws.send(m); });
          ws.onClose((code) => conn.close(code && code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000));
          conn.onClose((code) => { void ws.close({ code: code === 1005 || code === 1006 ? 1000 : code }).catch(() => undefined); });
        } catch (e) {
          block(u, "GET", "websocket", e);
          void ws.close({ code: 1008, reason: "blocked by walkthrough" });
        }
      });
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
              // Cookie header as Chromium computed it for THIS url (login state, per-origin rules); dropped on hops.
              const cookie = hop === 0 ? (await req.allHeaders()).cookie : undefined;
              const r = await guard.fetch(u, cookie ? { cookie } : undefined);
              noteSetCookie(r.headers);
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
          const headers = Object.fromEntries(Object.entries(await req.allHeaders()).filter(([k]) => !HOP_BY_HOP.test(k) && !k.startsWith(":") && k !== "host"));
          let method = req.method();
          let body = req.postDataBuffer() ?? undefined;
          for (let hop = 0; ; hop++) {
            const r = await guard.request({ url: u, method, headers, body });
            noteSetCookie(r.headers);
            subresources.push({ url: u, method, type, status: r.status, ip: r.ip });
            if (r.status >= 300 && r.status < 400 && r.headers.location) {
              if (hop >= MAX_HOPS) throw new Error("too many redirects");
              u = new URL(r.headers.location, u).toString();
              delete headers.cookie; // cookies belong to the original URL only; never carried across a redirect
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
      return { screenshot, har: readFileSync(harPath, "utf8"), text, navigations, subresources, blocked, websockets, wsMessages, setCookieValues };
    } finally {
      await browser.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
