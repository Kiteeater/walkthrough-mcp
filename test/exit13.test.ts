import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Regression for the CI e2e failure "exit code 13" (Node: unsettled top-level await).
 * The CLI top-level-awaits runFlow -> waitForUrl -> fetch(). If that fetch never settles and holds no
 * ref'd handle (here: a stub that returns a bare pending promise), the event loop drains and Node exits 13
 * with no output. waitForUrl must give every attempt a ref'd deadline so the run always settles.
 * Runs against dist/ (test/global-setup.ts rebuilds it before every run).
 */
const CLI = resolve("dist/cli/index.js");
describe("exit 13: waitForUrl with a fetch that never settles", () => {
  it("dist/cli/index.js exists (test/global-setup.ts builds it)", () => {
    expect(existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
  });

  it("the CLI run settles with a timeout error instead of Node exiting 13", () => {
    expect(existsSync(CLI), `${CLI} missing`).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), "wt-exit13-"));
    const cfg = join(dir, "flow.json");
    writeFileSync(cfg, JSON.stringify({
      title: "exit13", sandbox: { cwd: ".", up: "true", down: "true" },
      waitFor: { url: "http://127.0.0.1:9/health", timeoutMs: 1500, attemptTimeoutMs: 300 }, captures: [], claims: [],
    }));
    // flow hosts must be in replay.allowHosts (read from <root>/walkthrough.config.json)
    writeFileSync(join(dir, "walkthrough.config.json"), JSON.stringify({ replay: { allowHosts: ["127.0.0.1:9"] } }));
    const script = join(dir, "run.mjs");
    writeFileSync(script, `globalThis.fetch = () => new Promise(() => {});
process.argv = [process.argv[0], "walkthrough", "run", "--config", ${JSON.stringify(cfg)}, "--root", ${JSON.stringify(dir)}];
await import(${JSON.stringify("file://" + CLI)});`);
    const r = spawnSync(process.execPath, [script], { encoding: "utf8", timeout: 20_000 });
    expect(r.status, `exit ${r.status}; stderr: ${r.stderr}`).toBe(1);
    expect(r.stderr).toContain("timed out");
    expect(r.stderr).toContain("timed out waiting for http://127.0.0.1:9/health");
  });
});
