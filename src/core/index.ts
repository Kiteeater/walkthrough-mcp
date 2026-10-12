import { readFileSync } from "node:fs";
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

/** Default wiring: Docker Compose sandbox + Playwright capturer. */
export function createCore(root = process.cwd(), capturer: Capturer = new PlaywrightCapturer()): WalkthroughCore {
  return new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer });
}

export function readJsonFile(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}
