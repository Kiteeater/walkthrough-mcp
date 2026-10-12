export interface Capturer {
  /** Write a PNG screenshot of `url` to `outPath`. */
  screenshot(url: string, outPath: string): Promise<void>;
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
}
