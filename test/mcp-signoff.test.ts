// sign_off is a human act: it is not on the MCP tool surface, and an MCP call to it is refused.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";

describe("MCP surface: no sign_off", () => {
  it("tools/list has no sign_off; tools/call sign_off is refused; the walkthrough stays unsigned", async () => {
    const root = mkdtempSync(join(tmpdir(), "wt-mcp-"));
    const client = new Client({ name: "test", version: "0" });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: ["dist/mcp/index.js"], env: { ...process.env, WALKTHROUGH_ROOT: root } as Record<string, string> }));
    try {
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toContain("render_walkthrough");
      expect(names).not.toContain("sign_off");
      expect(names.some((n) => /sign/i.test(n))).toBe(false);
      const started = await client.callTool({ name: "start_walkthrough", arguments: { title: "t", cwd: root, up: "true", down: "true" } });
      const id = JSON.parse((started.content as { text: string }[])[0].text).id as string;
      let refused = false, res: unknown;
      try { res = await client.callTool({ name: "sign_off", arguments: { id, decision: "accept" } }); refused = (res as { isError?: boolean }).isError === true; }
      catch (e) { refused = /not found|unknown|sign_off/i.test(String((e as Error).message)); }
      expect(refused, JSON.stringify(res)).toBe(true);
      const { WalkthroughCore } = await import("../src/core/index.js");
      const core = new WalkthroughCore({ root, sandboxFactory: () => ({ up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" }), capturer: { screenshot: async () => undefined } });
      expect((core.load(id) as { signoff?: unknown }).signoff).toBeUndefined();
    } finally { await client.close(); }
  }, 60_000);
});
