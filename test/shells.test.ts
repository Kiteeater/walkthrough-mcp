import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const ALLOWED = [/^\.\.\/core\/index\.js$/, /^@modelcontextprotocol\/sdk\//, /^zod$/, /^node:util$/];
const MAX_LINES = 80;

describe.each(["src/mcp/index.ts", "src/cli/index.ts"])("thin shell %s", (file) => {
  const src = readFileSync(file, "utf8");
  it("imports only from core (plus transport/arg-parsing libs)", () => {
    const imports = [...src.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const i of imports) expect(ALLOWED.some((r) => r.test(i)), i).toBe(true);
    expect(src).not.toMatch(/node:fs|node:child_process|createHash/);
  });
  it(`stays under ${MAX_LINES} lines`, () => {
    expect(src.split("\n").length).toBeLessThanOrEqual(MAX_LINES);
  });
});

describe("core boundary", () => {
  it("core never imports the demo agent (planning belongs to the agent)", async () => {
    const { readdirSync } = await import("node:fs");
    // recursive: src/core has subdirectories (egress/)
    for (const f of readdirSync("src/core", { recursive: true, withFileTypes: true })) {
      if (!f.isFile()) continue;
      const p = `${f.parentPath ?? f.path}/${f.name}`;
      expect(readFileSync(p, "utf8"), p).not.toMatch(/from\s+["'][^"']*demo-agent/);
    }
  });
});
