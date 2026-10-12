#!/usr/bin/env node
// Thin CLI shell. All behaviour lives in src/core.
import { parseArgs } from "node:util";
import { createCore, loadFlowConfig, readJsonFile, renderWalkthrough, runFlow } from "../core/index.js";

const USAGE = `usage:
  walkthrough run --config <file> [--sandbox compose|local] [--up <cmd>] [--down <cmd>] [--root <dir>]
  walkthrough render <id> [--root <dir>]
  walkthrough import-review <review.json> [--root <dir>]`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { config: { type: "string" }, sandbox: { type: "string" }, up: { type: "string" }, down: { type: "string" }, root: { type: "string" } },
});
const [cmd, arg] = positionals;
const core = createCore(values.root ?? process.cwd());

try {
  if (cmd === "run" && values.config) {
    const r = await runFlow(core, loadFlowConfig(values.config, { up: values.up, down: values.down, backend: values.sandbox as "local" | undefined }));
    console.log(JSON.stringify(r));
  } else if (cmd === "render" && arg) {
    console.log(renderWalkthrough(core, arg));
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
