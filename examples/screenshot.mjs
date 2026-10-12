// Screenshot of an audit page's first screen: node examples/screenshot.mjs <index.html> <out.png>
import { chromium } from "playwright";
import { resolve } from "node:path";
const [html, out = "docs/audit-page.png"] = process.argv.slice(2);
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1100, height: 1100 }, locale: "zh-CN", timezoneId: process.env.SHOT_TZ || "Asia/Taipei" });
await p.goto(`file://${resolve(html)}`);
await p.screenshot({ path: out });
await b.close();
console.log(out);
