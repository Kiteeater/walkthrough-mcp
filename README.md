# walkthrough-mcp

Don't review the diff — **run the change and answer "what does it actually do?" with evidence.**
Built on WeZZard's walkthrough idea: audit the execution result, not the code.

## Audit-only workflow

Humans only audit the **final result**: which problems the agent found, how it reported them, and the root-cause
trace. Everything in between is the agent's job, with no human in the loop:

1. The agent plans its checks (`plan_checks`). Every check needs a **machine-checkable expectation**
   (`status`, `statusRange`, `bodyIncludes`, `exitCode`, or `watch.alerts`); a check without one is rejected.
2. `run_checks` executes them in the sandbox, stores every response and log slice as sha256 evidence, and
   **the core, not the agent, judges pass/fail** against the expectation.
3. Each failed check auto-drafts an observed finding. The root cause is traced by grepping the captured logs for a
   stack trace and mapping the first in-project frame to `file:line` (`link_source`).
4. `render_walkthrough` produces an audit view. The first screen shows only conclusions: number of findings, a
   severity breakdown, and a one-line root cause (with the source line) per finding. Each finding expands into its
   evidence chain; per-claim Agree/Flag is optional and collapsed.
5. A human gives one report-level sign-off (认可 / 打回 + comment), exported to `review.json` and imported back.

Planning belongs to the agent. The example's deterministic, rule-based planner lives in `src/demo-agent/`
(outside the core), so the demo needs no LLM: it derives one generic check per declared route and knows nothing about bugs.

## Install

```bash
npm install
npm run build
npx playwright install chromium   # needed for screenshots
```

Requires Node 20+ and Docker with the Compose plugin.

## CLI

```bash
# Run a declarative walkthrough plan (sandbox up -> exec -> capture -> claims -> down -> HTML)
node dist/cli/index.js run --config examples/walkthrough.config.json [--up "<cmd>"] [--down "<cmd>"] [--root .]

# Re-render HTML for an existing walkthrough
node dist/cli/index.js render <id>

# Write Agree/Flag decisions exported from the HTML back into the walkthrough JSON
node dist/cli/index.js import-review review.json
```

Output lives in `.walkthrough/<id>/`: `walkthrough.json`, `evidence/`, `index.html`.
After `import-review`, re-rendering shows each claim's review status and note under it, prefills each note input with the saved note (so re-exporting keeps it), plus a summary block (observed / inferred / agreed / flagged counts) at the top; all of it is escaped and redacted.
The HTML is fully static: click Agree/Flag (with an optional note) per question, then
**Export review.json** downloads your decisions for `import-review`.

## Local backend (no Docker)

`--sandbox local` (CLI), `"backend": "local"` in the config's `sandbox` block, or `sandbox: "local"` on the
`start_walkthrough` MCP tool runs the service as a **host child process**. `sandbox.local.up` is the long-running
command; its stdout/stderr become the `logs` evidence (`source` = `local:<service>`). `down` kills the process group.
The child env is an **allowlist**: only `PATH`, `HOME`, `LANG`, `TMPDIR` and `TERM` pass by default; any other host
var must be listed in `sandbox.local.passEnv` (e.g. `["DEMO_API_KEY"]`). `down()` sends SIGTERM to the process group,
waits `sandbox.local.killTimeoutMs` (default 5000 ms), then SIGKILLs.
This is **not isolated**: every page of the rendered HTML carries a red 「本地运行、未隔离」 badge.

```bash
bash examples/run-local-e2e.sh   # real run: node service + Playwright chromium -> examples/output/
```

`examples/output/` holds a committed real run: `index.html`, `walkthrough.json`, `evidence/`, `review.json`
and `walkthrough-html.png` (a screenshot of the rendered page).

## MCP config

```json
{
  "mcpServers": {
    "walkthrough": {
      "command": "node",
      "args": ["/path/to/walkthrough-mcp/dist/mcp/index.js"],
      "env": { "WALKTHROUGH_ROOT": "/path/to/your/project" }
    }
  }
}
```

Tools: `start_walkthrough`, `run_in_sandbox` (up | down | exec), `capture_evidence` (screenshot | logs),
`link_source` (file + line), `record_claim` (observed | inferred), `plan_checks`, `run_checks`,
`record_finding` (title, severity critical/high/medium/low, what happened, repro, root cause = source link and/or
log evidence id, evidence ids, observed | inferred), `render_walkthrough`.

### Pluggable sources (seam for environment connectors)

Check actions (`action.type`: `http`, `command`, later `connector:<name>`), observations (`observe[].source`:
`log`, later `connector:<name>`) and verifiers (`verify.type`: `rule` today; `script`, `playwright`, `computer-use`
reserved) all go through a registry in `src/core/registry.ts`. New read-only connectors register there without
touching `run_checks` or `record_finding`; their results become sha256 evidence like everything else.

## Evidence format

Every evidence item is stored under `.walkthrough/<id>/evidence/` and described as:

```json
{ "id": "ev-1", "type": "screenshot", "path": "evidence/ev-1.png",
  "sha256": "…", "createdAt": "2026-10-13T06:00:00.000Z", "source": "http://localhost:3000/" }
```

`type` is `screenshot`, `logs` (`source` = `docker:<service>` / `local:<service>`) or `response` (an HTTP response
or command output captured by a check). Claims reference evidence **only by id**.
An `observed` claim is rejected if it cites no evidence, cites an unknown id, or the evidence file's
sha256 no longer matches. `inferred` claims may have no evidence.

> The stored sha256 lives in the mutable `walkthrough.json`, so it catches **accidental** changes to evidence
> files, not deliberate tampering (anyone who can edit the evidence can also edit the hash).

Writes to `walkthrough.json` are serialised per walkthrough id within one process, so concurrent tool calls
don't lose data. Multiple processes writing the same walkthrough are not coordinated.

## Secrets

Keys are read from environment variables only. Values of env vars whose names look secret
(`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`) are masked as `[REDACTED]`
in captured logs, run output, evidence metadata, walkthrough JSON and HTML. JSON is redacted field by field
(values and keys), so secrets containing quotes or backslashes are masked too. Screenshots are pixels and are
not redacted — don't render secrets on pages you capture.

## Example

`examples/orders-service` is a tiny order service with a real bug: the change in `examples/sample-change.patch`
computes totals from line items, but a legacy order has none, so `GET /api/orders` returns 500 with a stack trace in
the logs. `bash examples/run-local-e2e.sh` (or `run-e2e.sh` with Docker) lets the demo agent plan checks from
`routes.json`, run them, find the 500 and trace it to `orders.js:9`. The committed real run lives in `examples/output/`
(`walkthrough-html.png` is the first screen; `walkthrough-html-full.png` is the whole page).

## CI

The workflow is currently parked at `ci/github-workflow-ci.yml` (the push token lacks the `workflow` scope).
It runs unit tests plus the Docker Compose + Playwright e2e and uploads the HTML artifact, once it's moved to `.github/workflows/ci.yml`.

## Roadmap

- PR 2: Prometheus implementation of the read-only `MetricsAdapter` (`src/core/metrics.ts`).

## License

MIT
