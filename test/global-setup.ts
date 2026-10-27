// Vitest globalSetup: runs once, before any test file. Tests that execute dist/ (CLI, MCP server over stdio, the
// package entry, demo runners) must see the current src, so dist is removed and rebuilt from scratch every run.
// Removing first (instead of judging staleness) is the only way to drop orphans: tsc never deletes a .js whose .ts
// was removed (e.g. the old dist/core/blocklist.js), and mtimes cannot tell an orphan from a fresh file.
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { createRequire } from "node:module";

export default function setup(): void {
  rmSync("dist", { recursive: true, force: true });
  const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
  execFileSync(process.execPath, [tsc, "-p", "tsconfig.json"], { stdio: "inherit" });
}
