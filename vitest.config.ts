import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Clean + build dist once before any test file runs: several tests execute dist/ (CLI, MCP server, package entry).
    globalSetup: ["./test/global-setup.ts"],
  },
});
