import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ReplayConfig } from "./replay.js";
import { prometheusFromEnv } from "./metrics.js";
import { PlaywrightCapturer, type Capturer } from "./capture.js";
import { createSandboxFactory } from "./sandbox.js";
import { WalkthroughCore } from "./walkthrough.js";
import type { ConnectorConfig } from "./runcli.js";
import { parseJsonConfig, parseReplayConfig, parseRootConfig } from "./config.js";

// Public API of the package (the only entry in package.json "exports"): what the CLI, the MCP server, the demo agent
// and the examples use, plus the types needed to construct a WalkthroughCore. Guard internals (egress/*, loginstate)
// are not re-exported; tests import those from their source files.
export type { Check, CheckResult, Expect, RootCauseLink, SandboxConfig, Severity, Walkthrough } from "./types.js";
export { Redactor } from "./redact.js";
export { createSandboxFactory, LocalSandbox, type Sandbox } from "./sandbox.js";
export { PlaywrightCapturer, type Capturer } from "./capture.js";
export type { PrometheusConfig } from "./metrics.js";
export { ClaimRejectedError, WalkthroughCore } from "./walkthrough.js";
export { renderWalkthrough } from "./render.js";
export { loadFlowConfig, runFlow, type FlowConfig } from "./flow.js";
export { DEFAULT_ALERTS, traceStack } from "./checks.js";
export {
  captureEvidenceShape, captureInput, COLLECT_WATCH_DESC, collectWatchShape, evaluateCheckShape, importInput, importMcpResultShape,
  planChecksShape, QUERY_METRICS_DESC, queryMetricsShape, recordFindingShape, START_WATCH_DESC, startWatchShape, watchInput,
} from "./schemas.js";
export { CliRejectedError, PRESET_CONNECTORS, type ConnectorConfig } from "./runcli.js";
export type { ReplayConfig } from "./replay.js";
export { ReplayRejectedError } from "./egress/policy.js";
export { ConfigError } from "./config.js";
export { spawnDetachedPoller } from "./alerts.js";

/** Default wiring: Docker Compose sandbox + Playwright capturer. */
export function createCore(root = process.cwd(), capturer: Capturer = new PlaywrightCapturer(), replay?: ReplayConfig, connectors?: ConnectorConfig[]): WalkthroughCore {
  return new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer, replay: replay ? parseReplayConfig(replay, "createCore(replay)") : replayConfigFrom(root), prometheus: prometheusFromEnv(), ...(connectors ? { connectors } : {}) });
}

/**
 * `replay` block of `<root>/walkthrough.config.json` (or the file named by WALKTHROUGH_CONFIG). No file → no replay
 * config. A file that is not JSON or does not match the strict schema is a ConfigError, never "no config".
 */
function replayConfigFrom(root: string): ReplayConfig | undefined {
  const f = process.env.WALKTHROUGH_CONFIG ?? join(root, "walkthrough.config.json");
  if (!existsSync(f)) return undefined;
  return parseRootConfig(parseJsonConfig(readFileSync(f, "utf8"), f), f).replay;
}

export function readJsonFile(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}
