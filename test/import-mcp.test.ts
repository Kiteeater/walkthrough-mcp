import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createSandboxFactory, Redactor, renderWalkthrough, WalkthroughCore, MASK, type Capturer } from "../src/core/index.js";
import { runTraceAgent } from "../src/demo-agent/trace.js";
import { mockCore, SB } from "./helpers.js";

const check = (id: string, value = '"items"') => ({ id, intent: id, method: "mcp" as const, target: "t", expect: { type: "regex" as const, value }, severity_if_fail: "high" as const });

async function setup(secrets: string[] = []) {
  const { core, root } = mockCore({ secrets });
  const w = core.startWalkthrough({ title: "imp", sandbox: SB });
  await core.planChecks(w.id, { goal: "g", checks: [check("h"), check("t"), check("d")] });
  const http = await core.captureEvidence(w.id, { type: "submit", checkId: "h", kind: "http", source: { tool: "fetch" }, content: 'HTTP 500\n\n{"traceId":"tr-42"}' });
  return { core, root, id: w.id, http };
}

describe("import_mcp_result (connector:<name>)", () => {
  it("stores an agent-reported, hashed mcp_result tagged with server, tool and params, linked by key", async () => {
    const { core, root, id, http } = await setup();
    const ev = await core.importMcpResult(id, { checkId: "t", connector: "langfuse", tool: "get_trace", params: { traceId: "tr-42" }, result: { id: "tr-42", metadata: { orderId: "ord-3" } }, links: [{ evidenceId: http.id, key: "tr-42" }] });
    expect(ev).toMatchObject({ kind: "mcp_result", executedBy: "agent", source: "connector:langfuse", mcpCall: { connector: "langfuse", server: "langfuse", tool: "get_trace", params: { traceId: "tr-42" } }, links: [{ evidenceId: http.id, key: "tr-42" }] });
    expect(ev.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(join(root, ".walkthrough", id, ev.path), "utf8")).toContain("# reported by agent: langfuse.get_trace");
  });

  it("rejects unlinked evidence: no links, key missing from the linked evidence, or from the result", async () => {
    const { core, id, http } = await setup();
    const base = { checkId: "t", connector: "langfuse", tool: "get_trace", result: { id: "tr-42" } };
    await expect(core.importMcpResult(id, { ...base, links: [] })).rejects.toThrow(/must link/);
    await expect(core.importMcpResult(id, { ...base, links: [{ evidenceId: http.id, key: "tr-99" }] })).rejects.toThrow(/unlinked.*ev-1/);
    await expect(core.importMcpResult(id, { ...base, result: { id: "other" }, links: [{ evidenceId: http.id, key: "tr-42" }] })).rejects.toThrow(/unlinked.*imported result/);
    await expect(core.importMcpResult(id, { ...base, links: [{ evidenceId: "ev-404", key: "tr-42" }] })).rejects.toThrow(/evidence not found/);
  });

  it("rejects a link to tampered evidence (hash mismatch)", async () => {
    const { core, root, id, http } = await setup();
    writeFileSync(join(root, ".walkthrough", id, http.path), 'HTTP 200\n\n{"traceId":"tr-42"}');
    await expect(core.importMcpResult(id, { connector: "langfuse", tool: "get_trace", result: { id: "tr-42" }, links: [{ evidenceId: http.id, key: "tr-42" }] })).rejects.toThrow(/hash mismatch/);
  });

  it("an imported file edited afterwards can no longer be cited", async () => {
    const { core, root, id, http } = await setup();
    const ev = await core.importMcpResult(id, { checkId: "t", connector: "mongodb", tool: "find", params: { filter: { _id: "tr-42" } }, result: [{ _id: "tr-42", items: [] }], links: [{ evidenceId: http.id, key: "tr-42" }] });
    writeFileSync(join(root, ".walkthrough", id, ev.path), "edited");
    await expect(core.evaluateCheck(id, { checkId: "t", evidenceIds: [ev.id] })).rejects.toThrow(/hash mismatch/);
  });

  it("rejects unknown connectors and write tools", async () => {
    const { core, id, http } = await setup();
    const links = [{ evidenceId: http.id, key: "tr-42" }];
    await expect(core.importMcpResult(id, { connector: "redis", tool: "get", result: "tr-42", links })).rejects.toThrow(/unknown MCP connector/);
    await expect(core.importMcpResult(id, { connector: "mongodb", tool: "insert-many", result: "tr-42", links })).rejects.toThrow(/read-only import list/);
    await expect(core.importMcpResult(id, { connector: "mongodb", tool: "delete-many", result: "tr-42", links })).rejects.toThrow(/read-only import list/);
  });

  it("stores no credentials: credential params dropped, URI userinfo stripped, env secrets redacted everywhere", async () => {
    const { core, root, id, http } = await setup(["sk-lf-SECRET-123"]);
    const ev = await core.importMcpResult(id, {
      checkId: "d", connector: "mongodb", tool: "find",
      params: { connectionString: "mongodb://reader:hunter2@db:27017/shop", password: "hunter2", apiKey: "k-1", nested: { authorization: "Basic eHh4", note: "sk-lf-SECRET-123" }, filter: { _id: "tr-42" } },
      result: [{ _id: "tr-42", uri: "mongodb://reader:hunter2@db/shop", token: "sk-lf-SECRET-123" }],
      links: [{ evidenceId: http.id, key: "tr-42" }],
    });
    const p = ev.mcpCall!.params as Record<string, any>;
    expect(p.password).toBe(MASK); expect(p.apiKey).toBe(MASK); expect(p.nested.authorization).toBe(MASK);
    expect(p.connectionString).toBe(`mongodb://${MASK}@db:27017/shop`);
    expect(p.nested.note).toBe(MASK);
    const dir = join(root, ".walkthrough", id);
    const all = readFileSync(join(dir, "walkthrough.json"), "utf8") + readFileSync(join(dir, ev.path), "utf8");
    for (const s of ["hunter2", "sk-lf-SECRET-123", "eHh4", "k-1"]) expect(all).not.toContain(s);
  });
});

describe("agent-reported evidence is at most pass_needs_review", () => {
  it("a check backed only by agent-reported evidence cannot reach a clean pass, and the report flags it", async () => {
    const { core, id, http } = await setup();
    const ev = await core.importMcpResult(id, { checkId: "d", connector: "mongodb", tool: "find", result: [{ _id: "tr-42", items: [1] }], links: [{ evidenceId: http.id, key: "tr-42" }] });
    const r = await core.evaluateCheck(id, { checkId: "d", evidenceIds: [ev.id] });
    expect(r.status).toBe("pass_needs_review");
    expect(r.reasons.join()).toMatch(/reported by the agent/);
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toContain('data-needs-review="1"');
    expect(html).toMatch(/<tr class="pass_needs_review"><td>d /);
  });

  it("a failing agent-only check stays fail; core-executed evidence still yields a clean pass", async () => {
    const { core, id, http } = await setup();
    const ev = await core.importMcpResult(id, { checkId: "d", connector: "mongodb", tool: "find", result: [{ _id: "tr-42" }], links: [{ evidenceId: http.id, key: "tr-42" }] });
    expect((await core.evaluateCheck(id, { checkId: "d", evidenceIds: [ev.id] })).status).toBe("fail");
    const logs = await core.captureEvidence(id, { type: "logs", service: "web", checkId: "t" });
    await core.planChecks(id, { goal: "g", checks: [check("l", "listening")], append: true });
    const l2 = await core.captureEvidence(id, { type: "logs", service: "web", checkId: "l" });
    expect(logs.executedBy).toBe("core");
    expect((await core.evaluateCheck(id, { checkId: "l", evidenceIds: [l2.id] })).status).toBe("pass");
  });
});

describe("cross-source root-cause chain: HTTP 500 → Langfuse trace → Mongo doc → file:line", () => {
  it("the trace agent builds the chain with real MongoDB + mock Langfuse; HTML marks agent-reported vs executed-by-us steps", async () => {
    const { MongoMemoryServer } = await import("mongodb-memory-server");
    const { MongoClient } = await import("mongodb");
    const { startMockLangfuse } = await import("../examples/trace-demo/mock-langfuse.mjs" as string);
    const mms = await MongoMemoryServer.create();
    const mongo = new MongoClient(mms.getUri());
    await mongo.db("shop").collection("orders").insertMany([{ _id: "ord-1", items: [{ price: 1, qty: 1 }] }, { _id: "ord-3", legacyTotal: 12 }] as never);
    const lfPort = 41000 + Math.floor(Math.random() * 5000), port = lfPort + 6000;
    const lf = await startMockLangfuse(lfPort, "pk", "sk-test-xyz");
    const auth = "Basic " + Buffer.from("pk:sk-test-xyz").toString("base64");
    Object.assign(process.env, { MONGO_URL: mms.getUri(), LANGFUSE_URL: `http://127.0.0.1:${lfPort}`, LANGFUSE_PUBLIC_KEY: "pk", LANGFUSE_SECRET_KEY: "sk-test-xyz", PORT: String(port) });
    const root = resolve(".");
    const core = new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer: { screenshot: async () => {} } as Capturer, redactor: new Redactor(["sk-test-xyz"]) });
    const w = core.startWalkthrough({ title: "trace", sandbox: { backend: "local", cwd: join(root, "examples/trace-demo/service"), up: "", down: "", local: { up: "exec node server.js", passEnv: ["MONGO_URL", "LANGFUSE_URL", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "PORT"], killTimeoutMs: 1000 } } });
    await core.runInSandbox(w.id, "up");
    try {
      for (let i = 0; i < 80; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) break; } catch { /* wait */ } await new Promise((r) => setTimeout(r, 100)); }
      await runTraceAgent(core, w.id, {
        getTrace: async (t) => (await fetch(`http://127.0.0.1:${lfPort}/api/public/traces/${t}`, { headers: { authorization: auth } })).json(),
        find: (db, c, f) => mongo.db(db).collection(c).find(f as never).toArray(),
      }, { goal: "totals work", baseUrl: `http://127.0.0.1:${port}`, orders: ["ord-1", "ord-3"] });
    } finally {
      await core.runInSandbox(w.id, "down"); await mongo.close(); lf.close(); await mms.stop();
      for (const k of ["MONGO_URL", "LANGFUSE_URL", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "PORT"]) delete process.env[k];
    }
    const out = core.load(w.id);
    expect(out.findings).toHaveLength(1);
    const chain = out.findings![0].root_cause_chain;
    const evOf = (i: number) => out.evidence.find((e) => e.id === chain[i].evidence_ids[0])!;
    expect(chain).toHaveLength(4);
    expect(chain.every((l) => l.kind === "observed")).toBe(true);
    expect(evOf(0)).toMatchObject({ kind: "http", executedBy: "agent" });
    expect(evOf(1)).toMatchObject({ kind: "mcp_result", executedBy: "agent", mcpCall: { connector: "langfuse", tool: "get_trace" } });
    expect(evOf(2)).toMatchObject({ kind: "mcp_result", executedBy: "agent", mcpCall: { connector: "mongodb", tool: "find" } });
    expect(evOf(2).links![0].evidenceId).toBe(evOf(1).id);
    expect(evOf(1).links![0].evidenceId).toBe(evOf(0).id);
    expect(evOf(3)).toMatchObject({ kind: "log", executedBy: "core" });
    const src = out.sources.find((s) => s.id === chain[3].source_ref)!;
    expect(`${src.file}:${src.line}`).toBe("examples/trace-demo/service/pricing.js:3");
    expect(out.checkResults!.find((r) => r.checkId === "chk-1")?.status).toBe("pass_needs_review");
    const html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html.match(/<li class="step prov-agent"/g)).toHaveLength(3);
    expect(html.match(/<li class="step prov-core"/g)).toHaveLength(1);
    expect(JSON.stringify(out) + html).not.toContain("sk-test-xyz");
  }, 180_000);
});
