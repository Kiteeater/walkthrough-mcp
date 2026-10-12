// Readiness must prove it is OUR service: a 2xx from whatever else holds the port is not "ready".
import http from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { waitForUrl } from "../src/core/flow.js";

async function serve(token?: string) {
  const s = http.createServer((_q, r) => { if (token) r.setHeader("x-walkthrough-demo-token", token); r.end("ok"); });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return { s, url: `http://127.0.0.1:${(s.address() as AddressInfo).port}/health` };
}

describe("waitForUrl with a per-run token header", () => {
  it("a foreign 200 (no / wrong token) is not ready: times out with a clear error", async () => {
    const { s, url } = await serve("someone-else");
    try {
      await expect(waitForUrl(url, 1200, 300, { name: "x-walkthrough-demo-token", value: "ours" }))
        .rejects.toThrow(/timed out waiting for .*without the expected x-walkthrough-demo-token header — another process on that port\?/);
    } finally { s.close(); }
  });
  it("our service (matching token) is ready; the demo flow config requires the token", async () => {
    const { s, url } = await serve("ours");
    try { await expect(waitForUrl(url, 2000, 300, { name: "x-walkthrough-demo-token", value: "ours" })).resolves.toBeUndefined(); } finally { s.close(); }
    const flow = JSON.parse(readFileSync("examples/trace-demo/walkthrough.trace.json", "utf8"));
    expect(flow.waitFor.header).toEqual({ name: "x-walkthrough-demo-token", value: "${HEALTH_TOKEN}" });
  });
});

describe("flow config ${VAR} expansion (per-run port / token, issue #22)", () => {
  it("expands upper-case env vars everywhere; an unset one is a clear error", async () => {
    const { expandEnv } = await import("../src/core/flow.js");
    expect(expandEnv({ waitFor: { url: "http://127.0.0.1:${PORT}/health", header: { name: "x", value: "${TOK}" } }, list: ["${PORT}"] }, "f.json", { PORT: "4321", TOK: "t1" }))
      .toEqual({ waitFor: { url: "http://127.0.0.1:4321/health", header: { name: "x", value: "t1" } }, list: ["4321"] });
    expect(() => expandEnv({ u: "http://127.0.0.1:${PORT}/" }, "f.json", {})).toThrow("f.json: ${PORT} is not set");
  });
  it("the e2e configs use no fixed port and require the health token", () => {
    for (const f of ["examples/walkthrough.config.json", "examples/walkthrough.local.json"]) {
      const raw = readFileSync(f, "utf8");
      expect(raw, f).not.toMatch(/:3000\b/);
      expect(JSON.parse(raw).waitFor).toEqual({ url: "http://127.0.0.1:${PORT}/health", header: { name: "x-walkthrough-demo-token", value: "${DEMO_HEALTH_TOKEN}" }, timeoutMs: 90000 });
    }
    expect(readFileSync("examples/orders-service/compose.yaml", "utf8")).not.toMatch(/"3000:3000"/);
  });
});
