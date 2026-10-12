export interface PageCapture { /** PNG */ screenshot: Buffer; /** HAR JSON text */ har: string; /** visible DOM text */ text: string }

export interface Capturer {
  /** Write a PNG screenshot of `url` to `outPath`. */
  screenshot(url: string, outPath: string): Promise<void>;
  /** Optional `method: ui` fallback for hosts without computer use: load `url`, return screenshot + HAR + DOM text. */
  page?(url: string): Promise<PageCapture>;
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

  async page(url: string): Promise<PageCapture> {
    const { chromium } = await import("playwright");
    const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "wt-page-"));
    const harPath = join(dir, "page.har");
    const browser = await chromium.launch();
    try {
      const ctx = await browser.newContext({ recordHar: { path: harPath, content: "embed" } });
      const page = await ctx.newPage();
      await page.goto(url, { waitUntil: "networkidle" });
      const screenshot = await page.screenshot({ fullPage: true });
      const text = await page.innerText("body").catch(() => "");
      await ctx.close(); // flushes the HAR
      return { screenshot, har: readFileSync(harPath, "utf8"), text };
    } finally {
      await browser.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
