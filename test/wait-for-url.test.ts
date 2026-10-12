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
