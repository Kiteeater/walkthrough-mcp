export interface PageCapture {
  /** PNG */ screenshot: Buffer; /** HAR JSON text */ har: string; /** visible DOM text */ text: string;
  /** Main-frame navigation hops, each fetched by the guard (policy-checked, IP-pinned). */
  navigations: { url: string; status: number; ip: string }[];
  /** Sub-resource requests the page made (logged, NOT blocked — see README). */
  subresources: string[];
}

/** Fetches ONE main-frame navigation hop under the replay policy (allowlist + IP rules, pinned IP, no redirect follow). Throws to block. */
export interface NavigationGuard {
  fetch(url: string): Promise<{ status: number; headers: Record<string, string>; body: string; ip: string }>;
}

export interface Capturer {
  /** Write a PNG screenshot of `url` to `outPath`. */
  screenshot(url: string, outPath: string): Promise<void>;
  /** Optional `method: ui` fallback for hosts without computer use: load `url`, return screenshot + HAR + DOM text. */
  page?(url: string, guard: NavigationGuard): Promise<PageCapture>;
}

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
    const browser = await chromium.launch();
    const navigations: PageCapture["navigations"] = [];
    const subresources: string[] = [];
    let blocked: Error | undefined;
    let finalUrl: string | undefined;
    try {
      const ctx = await browser.newContext({ recordHar: { path: harPath, content: "embed" }, serviceWorkers: "block" });
      const page = await ctx.newPage();
      // Every main-frame navigation (including each redirect hop, which re-enters this handler) is fetched by OUR
      // guarded, IP-pinned fetcher and fulfilled from it, so Chromium never resolves/connects for the main document.
      await ctx.route("**/*", async (route) => {
        const req = route.request();
        if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
          try {
            // Chromium does not re-route redirects of a fulfilled response, so hops are followed HERE, each one
            // through the guard (allowlist + IP rules, pinned IP).
            let u = req.url();
            for (let hop = 0; ; hop++) {
              const r = await guard.fetch(u);
              navigations.push({ url: u, status: r.status, ip: r.ip });
              if (r.status >= 300 && r.status < 400 && r.headers.location) {
                if (hop >= 5) throw new Error("too many redirects");
                u = new URL(r.headers.location, u).toString();
                continue;
              }
              if (u !== req.url()) {
                // Re-navigate to the final URL so relative sub-resources resolve correctly; that navigation comes
                // back through this handler and is checked again.
                finalUrl = u;
                return route.fulfill({ status: 200, contentType: "text/html", body: `<meta http-equiv="refresh" content="0;url=${u.replace(/"/g, "%22")}">` });
              }
              const headers = Object.fromEntries(Object.entries(r.headers).filter(([k]) => !/^(content-length|content-encoding|transfer-encoding|set-cookie)$/i.test(k)));
              return route.fulfill({ status: r.status, headers, body: r.body });
            }
          } catch (e) {
            blocked ??= e as Error;
            return route.abort("blockedbyclient");
          }
        }
        subresources.push(`${req.method()} ${req.url()}`);
        return route.continue();
      });
      await page.goto(url, { waitUntil: "networkidle", timeout: 30_000 }).catch((e) => { if (!blocked) throw e; });
      if (finalUrl && !blocked) await page.waitForURL(finalUrl, { waitUntil: "networkidle", timeout: 30_000 }).catch((e) => { if (!blocked) throw e; });
      if (blocked) throw blocked;
      const screenshot = await page.screenshot({ fullPage: true });
      const text = await page.innerText("body").catch(() => "");
      await ctx.close(); // flushes the HAR
      return { screenshot, har: readFileSync(harPath, "utf8"), text, navigations, subresources };
    } finally {
      await browser.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
