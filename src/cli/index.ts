#!/usr/bin/env node
// Thin CLI shell. All behaviour lives in src/core.
import { parseArgs } from "node:util";
import { spawnDetachedPoller, createCore, loadFlowConfig, readJsonFile, renderWalkthrough, runFlow } from "../core/index.js";

const USAGE = `usage:
  walkthrough run --config <file> [--sandbox compose|local] [--up <cmd>] [--down <cmd>] [--root <dir>]
      (every host the flow contacts — waitFor.url, screenshot captures — must be in replay.allowHosts of
       <root>/walkthrough.config.json, otherwise the run is refused before the sandbox starts)
  walkthrough render <id> [--root <dir>]
  walkthrough sign-off <id> --decision accept|reject [--comment <text>] [--root <dir>]
      (HUMAN ONLY: the report-level decision; not exposed over MCP)
  walkthrough import-review <review.json> [--root <dir>]
  walkthrough metrics <id> --query <promql> [--check <checkId>] [--time <unix|rfc3339>] [--root <dir>]
      (read-only Prometheus instant query; env WALKTHROUGH_PROMETHEUS_URL [+ WALKTHROUGH_PROMETHEUS_TOKEN];
       host must be in replay.allowHosts of <root>/walkthrough.config.json)
  walkthrough watch start <id> [--window <s>, default 60] [--interval <s>] [--root <dir>]   → prints the watch id; a detached poller runs
  walkthrough watch collect <watchId> [--root <dir>]                         → evidence + findings (interrupted if the poller died)
      (read-only GET /api/v1/alerts; window <= 900 s, interval 1-60 s; state in <root>/.walkthrough/watches/<watchId>.json)`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { window: { type: "string" }, interval: { type: "string" }, query: { type: "string" }, check: { type: "string" }, time: { type: "string" }, config: { type: "string" }, sandbox: { type: "string" }, up: { type: "string" }, down: { type: "string" }, root: { type: "string" }, decision: { type: "string" }, comment: { type: "string" } },
});
const [cmd, arg] = positionals;
const core = createCore(values.root ?? process.cwd());

try {
  if (cmd === "run" && values.config) {
    const r = await runFlow(core, loadFlowConfig(values.config, { up: values.up, down: values.down, backend: values.sandbox as "local" | undefined }));
    console.log(JSON.stringify(r));
  } else if (cmd === "sign-off" && arg && (values.decision === "accept" || values.decision === "reject")) {
    console.log(JSON.stringify(await core.signOff(arg, { decision: values.decision, comment: values.comment })));
  } else if (cmd === "render" && arg) {
    console.log(renderWalkthrough(core, arg));
  } else if (cmd === "metrics" && arg && values.query) {
    console.log(JSON.stringify(await core.queryMetrics(arg, { query: values.query, checkId: values.check, time: values.time })));
  } else if (cmd === "watch" && arg === "start" && positionals[2]) {
    // The CLI is one-shot: record the watch, then hand polling to a detached child that only writes the watch state file.
    const s = await core.startWatch(positionals[2], { windowS: values.window ? Number(values.window) : undefined, intervalS: values.interval ? Number(values.interval) : undefined, background: "none" });
    const pid = spawnDetachedPoller(process.argv[1], s.id, values.root ?? process.cwd());
    console.log(JSON.stringify({ watchId: s.id, deadline: s.deadline, pollerPid: pid }));
  } else if (cmd === "watch" && arg === "_poll" && positionals[2]) {
    await core.runPoller(positionals[2]);
  } else if (cmd === "watch" && arg === "collect" && positionals[2]) {
    console.log(JSON.stringify(await core.collectWatch(positionals[2])));
  } else if (cmd === "import-review" && arg) {
    console.log(JSON.stringify(await core.importReview(readJsonFile(arg))));
  } else {
    console.error(USAGE);
    process.exitCode = 2;
  }
} catch (e) {
  console.error(core.redact(String((e as Error).message)));
  process.exitCode = 1;
}
