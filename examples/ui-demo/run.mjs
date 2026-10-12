#!/usr/bin/env node
// PR #10 demo: UI evidence. The "agent" drives the orders page with Playwright (standing in for computer use /
// Playwright MCP), hands over screenshot + HAR + DOM text (agent-reported); walkthrough judges from the HAR (never the
// screenshot) and replays GET /api/orders itself (core-executed, SSRF-checked, hash-chained) to confirm the 500.
// usage: node examples/ui-demo/run.mjs [root]   → prints {"id": ...} on the last line
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { chromium } from "playwright";
import { createCore, renderWalkthrough } from "../../dist/core/index.js";

const root = resolve(process.argv[2] ?? ".");
const port = 3300, base = `http://127.0.0.1:${port}`;
const svc = spawn(process.execPath, ["examples/orders-service/server.js"], { env: { PATH: process.env.PATH, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
await new Promise((r, j) => { svc.stdout.on("data", (d) => String(d).includes("listening") && r()); svc.on("exit", (c) => j(new Error(`service exited ${c}`))); });

// Replay policy: only this host; loopback allowed only because the exact address is listed (default: denied).
const core = createCore(root, undefined, { allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] });
try {
  const w = core.startWalkthrough({ title: "Orders page shows an error — UI evidence", sandbox: { backend: "local", cwd: ".", up: "true", down: "true", local: { up: "true" } } });
  const id = w.id;
  await core.planChecks(id, { goal: "The orders page lists orders", checks: [
    { id: "ui-orders", intent: "orders page loads its data", method: "ui", target: `${base}/orders`, expect: { type: "ui", value: { har: { urlMatch: "/api/orders$", status: [200, 299] } } }, severity_if_fail: "high" },
    { id: "ui-banner", intent: "no error banner on the orders page", method: "ui", target: `${base}/orders`, expect: { type: "absent", value: "Failed to load orders" }, severity_if_fail: "medium" },
  ] });

  // ---- agent side (computer use / Playwright MCP): record HAR into .walkthrough/, screenshot, DOM text ----
  const inbox = join(root, ".walkthrough", "inbox", id); mkdirSync(inbox, { recursive: true });
  const harPath = join(inbox, "orders.har");
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ recordHar: { path: harPath, content: "embed" }, extraHTTPHeaders: { cookie: "session=agent-session-cookie-SHOULD-NOT-LEAK" } });
  const page = await ctx.newPage();
  await page.goto(`${base}/orders`, { waitUntil: "networkidle" });
  await page.waitForSelector("text=Failed to load orders", { timeout: 10_000 });
  const png = await page.screenshot({ fullPage: true });
  const dom = await page.innerText("body");
  await ctx.close(); await browser.close();

  const src = { tool: "playwright", server: "playwright-mcp" };
  const shot = await core.captureEvidence(id, { type: "submit", checkId: "ui-orders", kind: "screenshot", source: src, content: png.toString("base64") });
  const har = await core.captureEvidence(id, { type: "submit", checkId: "ui-orders", kind: "har", source: src, path: harPath });
  const text = await core.captureEvidence(id, { type: "submit", checkId: "ui-banner", kind: "http", source: { tool: "playwright", server: "playwright-mcp", command: "innerText(body)" }, content: dom });

  // ---- core side: replay the key request ourselves ----
  const replay = await core.replayHar(id, { checkId: "ui-orders", evidenceId: har.id, urlMatch: "/api/orders$", method: "GET" });
  const r1 = await core.evaluateCheck(id, { checkId: "ui-orders", evidenceIds: [shot.id, har.id, replay.id] });
  const r2 = await core.evaluateCheck(id, { checkId: "ui-banner", evidenceIds: [text.id] });

  const srcLink = await core.linkSource(id, { file: "examples/orders-service/orders.js", line: 9, note: "orderTotal reads order.items, missing on legacy order 3" });
  await core.recordFinding(id, {
    title: "Orders page shows 'Failed to load orders': GET /api/orders returns 500", severity: "high", check_id: "ui-orders",
    symptom: "The orders page renders a red error banner instead of the order list.",
    repro_steps: [`open ${base}/orders`, `GET ${base}/api/orders → 500`],
    root_cause_chain: [
      { claim: "the page shows the error banner (screenshot, human audit only)", kind: "observed", evidence_ids: [shot.id] },
      { claim: "GET /api/orders → 500: agent's HAR, confirmed by walkthrough's own replay", kind: "observed", evidence_ids: [har.id, replay.id] },
      { claim: "listOrders → orderTotal reads items of legacy order 3, which has none", kind: "inferred", evidence_ids: [], source_ref: srcLink.id },
    ],
  });
  renderWalkthrough(core, id);
  console.error(`checks: ui-orders=${r1.status} ui-banner=${r2.status}`);
  console.log(JSON.stringify({ id, checks: { "ui-orders": r1.status, "ui-banner": r2.status } }));
} finally { svc.kill(); }
