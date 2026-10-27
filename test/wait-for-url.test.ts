// Readiness must prove it is OUR service: a 2xx from whatever else holds the port is not "ready".
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    const used: string[] = [];
    expect(expandEnv({ waitFor: { url: "http://127.0.0.1:${PORT}/health", header: { name: "x", value: "${DEMO_HEALTH_TOKEN}" } }, list: ["${PORT}"] }, "f.json", { PORT: "4321", DEMO_HEALTH_TOKEN: "t1" }, used))
      .toEqual({ waitFor: { url: "http://127.0.0.1:4321/health", header: { name: "x", value: "t1" } }, list: ["4321"] });
    expect(used).toEqual(["t1"]); // PORT is substituted but not a secret: never redacted
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

describe("flow config substitution is allowlisted and redacted", () => {
  it("a secret-like variable is rejected even when it is set in the environment", async () => {
    const { loadFlowConfig, FLOW_ENV_ALLOWLIST } = await import("../src/core/flow.js");
    expect(FLOW_ENV_ALLOWLIST).toEqual(["PORT", "DEMO_HEALTH_TOKEN"]);
    const dir = mkdtempSync(join(tmpdir(), "wt-flow-"));
    const f = join(dir, "flow.json");
    writeFileSync(f, JSON.stringify({ title: "t", sandbox: { cwd: "." }, captures: [], claims: [], agent: { baseUrl: "http://x/?k=${CLOUD_ACCESS_KEY_SECRET}" } }));
    const old = process.env.CLOUD_ACCESS_KEY_SECRET;
    process.env.CLOUD_ACCESS_KEY_SECRET = "super-secret-value-123";
    try {
      expect(() => loadFlowConfig(f)).toThrow(/\$\{CLOUD_ACCESS_KEY_SECRET\} is not allowed in a flow config \(allowed: PORT, DEMO_HEALTH_TOKEN\)/);
      writeFileSync(f, JSON.stringify({ title: "${lower_case}", sandbox: { cwd: "." }, captures: [], claims: [] }));
      expect(() => loadFlowConfig(f)).toThrow(/\$\{lower_case\} is not allowed/);
    } finally { if (old === undefined) delete process.env.CLOUD_ACCESS_KEY_SECRET; else process.env.CLOUD_ACCESS_KEY_SECRET = old; }
  });

  it("the substituted token value never reaches evidence, walkthrough state or the report", async () => {
    const { loadFlowConfig, runFlow } = await import("../src/core/flow.js");
    const { WalkthroughCore, Redactor } = await import("../src/core/index.js");
    const root = mkdtempSync(join(tmpdir(), "wt-flow-red-"));
    const f = join(root, "flow.json");
    const token = "tok-" + Math.random().toString(36).slice(2) + "-xyz";
    writeFileSync(f, JSON.stringify({ title: "run ${DEMO_HEALTH_TOKEN}", sandbox: { backend: "local", cwd: ".", up: "", down: "", local: { up: "true" } }, captures: [],
      claims: [{ question: "q ${DEMO_HEALTH_TOKEN}", conclusion: "c", kind: "inferred" }] }));
    const old = process.env.DEMO_HEALTH_TOKEN;
    process.env.DEMO_HEALTH_TOKEN = token;
    try {
      const cfg = loadFlowConfig(f);
      expect(cfg.substituted).toEqual([token]);
      const sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
      const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async () => {} }, redactor: new Redactor([]) });
      const { id, html } = await runFlow(core, cfg, { skipWait: true, agent: async (wid) => {
        await core.planChecks(wid, { goal: "g", checks: [{ id: "a", intent: "a", method: "http", target: "GET /a", expect: { type: "status", value: 200 }, severity_if_fail: "high" }] });
        await core.captureEvidence(wid, { type: "submit", checkId: "a", kind: "http", source: { tool: "t" }, content: `HTTP/1.1 200\nx-walkthrough-demo-token: ${token}` });
      } });
      const files = readdirSync(core.dir(id), { recursive: true, withFileTypes: true }).filter((d) => d.isFile()).map((d) => readFileSync(join(d.parentPath, d.name), "utf8")).join("\n");
      expect(files).toContain("[REDACTED]");
      expect(files).not.toContain(token);
      expect(readFileSync(html, "utf8")).not.toContain(token);
    } finally { if (old === undefined) delete process.env.DEMO_HEALTH_TOKEN; else process.env.DEMO_HEALTH_TOKEN = old; }
  });
});

describe("PORT is substituted but never redacted", () => {
  it("digits equal to the run's PORT survive verbatim in evidence (timestamp / order id / amount); the token is still masked", async () => {
    const { loadFlowConfig, runFlow, FLOW_ENV_VARS } = await import("../src/core/flow.js");
    const { WalkthroughCore, Redactor } = await import("../src/core/index.js");
    expect(FLOW_ENV_VARS).toEqual({ PORT: { redact: false }, DEMO_HEALTH_TOKEN: { redact: true } });
    const root = mkdtempSync(join(tmpdir(), "wt-flow-port-"));
    const f = join(root, "flow.json");
    const port = "43117", token = "tok-" + Math.random().toString(36).slice(2) + "-abc";
    writeFileSync(f, JSON.stringify({ title: "svc 127.0.0.1:${PORT}", waitFor: { url: "http://127.0.0.1:${PORT}/health", header: { name: "x-walkthrough-demo-token", value: "${DEMO_HEALTH_TOKEN}" } },
      sandbox: { backend: "local", cwd: ".", up: "", down: "", local: { up: "true" } }, captures: [], claims: [] }));
    const old = { p: process.env.PORT, t: process.env.DEMO_HEALTH_TOKEN };
    process.env.PORT = port; process.env.DEMO_HEALTH_TOKEN = token;
    try {
      const cfg = loadFlowConfig(f);
      expect(cfg.substituted).toEqual([token]);
      expect(cfg.title).toBe(`svc 127.0.0.1:${port}`);
      const sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
      const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async () => {} }, redactor: new Redactor([]), replay: { allowHosts: [`127.0.0.1:${port}`] } });
      const body = `HTTP/1.1 200\nx-walkthrough-demo-token: ${token}\n\n{"orderId":"ord-${port}","createdAt":"2026-10-13T07:${port.slice(0, 2)}:00.${port}Z","amount":${port}.50,"url":"http://127.0.0.1:${port}/api"}`;
      let evPath = "";
      const { id, html } = await runFlow(core, cfg, { skipWait: true, agent: async (wid) => {
        await core.planChecks(wid, { goal: "g", checks: [{ id: "a", intent: "a", method: "http", target: "GET /a", expect: { type: "status", value: 200 }, severity_if_fail: "high" }] });
        evPath = (await core.captureEvidence(wid, { type: "submit", checkId: "a", kind: "http", source: { tool: "t" }, content: body })).path;
      } });
      const ev = readFileSync(join(core.dir(id), evPath), "utf8");
      expect(ev).toContain(`"orderId":"ord-${port}"`);
      expect(ev).toContain(`.${port}Z`);
      expect(ev).toContain(`"amount":${port}.50`);
      expect(ev).toContain(`127.0.0.1:${port}/api`);
      expect(ev).not.toContain(token);
      expect(ev).toContain("x-walkthrough-demo-token: [REDACTED]");
      const report = readFileSync(html, "utf8");
      expect(report).toContain(`svc 127.0.0.1:${port}`); // title: PORT substituted, not masked
      expect(report).not.toContain(token);
    } finally {
      if (old.p === undefined) delete process.env.PORT; else process.env.PORT = old.p;
      if (old.t === undefined) delete process.env.DEMO_HEALTH_TOKEN; else process.env.DEMO_HEALTH_TOKEN = old.t;
    }
  });
});
