import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ReplayConfig } from "./replay.js";
import { prometheusFromEnv } from "./metrics.js";
import { PlaywrightCapturer, type Capturer } from "./capture.js";
import { createSandboxFactory } from "./sandbox.js";
import { WalkthroughCore } from "./walkthrough.js";

export * from "./types.js";
export * from "./redact.js";
export * from "./sandbox.js";
export * from "./capture.js";
export * from "./metrics.js";
export * from "./walkthrough.js";
export * from "./render.js";
export * from "./flow.js";
export * from "./checks.js";
export * from "./registry.js";
export * from "./sources.js";
export * from "./schemas.js";
export * from "./settle.js";
export * from "./argv.js";
export * from "./runcli.js";

/** Default wiring: Docker Compose sandbox + Playwright capturer. */
export function createCore(root = process.cwd(), capturer: Capturer = new PlaywrightCapturer(), replay?: ReplayConfig): WalkthroughCore {
  return new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer, replay: replay ?? replayConfigFrom(root), prometheus: prometheusFromEnv() });
}

/** `replay` block of `<root>/walkthrough.config.json`, if any (or the file named by WALKTHROUGH_CONFIG). */
export function replayConfigFrom(root: string): ReplayConfig | undefined {
  const f = process.env.WALKTHROUGH_CONFIG ?? join(root, "walkthrough.config.json");
  if (!existsSync(f)) return undefined;
  try { return (JSON.parse(readFileSync(f, "utf8")) as { replay?: ReplayConfig }).replay; } catch { return undefined; }
}

export function readJsonFile(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}
export * from "./imports.js";
export * from "./har.js";
export * from "./replay.js";
export * from "./alerts.js";
export * from "./lockfile.js";
export * from "./execpolicy.js";
