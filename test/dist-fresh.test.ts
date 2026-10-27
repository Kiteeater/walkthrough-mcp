// dist/ is rebuilt by test/global-setup.ts before every run. This checks the result: every emitted .js has its
// source .ts (no orphans such as a leftover dist/core/blocklist.js), and every source has its emitted .js.
import { readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

function files(dir: string, ext: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(ext) && !f.endsWith(".d.ts")).map((f) => relative(dir, join(dir, f)).slice(0, -ext.length)).sort();
}

describe("dist matches src", () => {
  it("one dist .js per src .ts, nothing extra, nothing missing", () => {
    expect(files("dist", ".js")).toEqual(files("src", ".ts"));
  });
});
