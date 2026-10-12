# walkthrough-mcp

Don't review the diff — **run the change and answer "what does it actually do?" with evidence.**
Inspired by WeZZard's walkthrough idea.

A TypeScript MCP server (stdio) and CLI sharing one core (`src/core`). It brings up a Docker Compose
sandbox, captures evidence (Playwright screenshots, docker logs), links source lines, records claims
marked `observed` or `inferred`, and renders a static HTML walkthrough a human can Agree/Flag.

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
`link_source` (file + line), `record_claim` (observed | inferred), `render_walkthrough`.

## Evidence format

Every evidence item is stored under `.walkthrough/<id>/evidence/` and described as:

```json
{ "id": "ev-1", "type": "screenshot", "path": "evidence/ev-1.png",
  "sha256": "…", "createdAt": "2026-10-13T06:00:00.000Z", "source": "http://localhost:3000/" }
```

`type` is `screenshot` or `logs` (`source` = `docker:<service>`). Claims reference evidence **only by id**.
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

`examples/hello-service` is a tiny web service; `examples/sample-change.patch` describes the change
(a new `/api/greeting` endpoint and home banner). `bash examples/run-e2e.sh` runs the whole flow and produces
HTML with one observed and one inferred claim. CI runs it and uploads the HTML as the `walkthrough-html` artifact.

## CI

The workflow is currently parked at `ci/github-workflow-ci.yml` (the push token lacks the `workflow` scope).
It runs unit tests plus the Docker Compose + Playwright e2e and uploads the HTML artifact, once it's moved to `.github/workflows/ci.yml`.

## Roadmap

- PR 2: Prometheus implementation of the read-only `MetricsAdapter` (`src/core/metrics.ts`).

## License

MIT
