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
The HTML is fully static: click Agree/Flag (with an optional note) per question, then
**Export review.json** downloads your decisions for `import-review`.

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

## Secrets

Keys are read from environment variables only. Values of env vars whose names look secret
(`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`) are masked as `[REDACTED]`
in captured logs, run output, evidence metadata, walkthrough JSON and HTML. Screenshots are pixels and are
not redacted — don't render secrets on pages you capture.

## Example

`examples/hello-service` is a tiny web service; `examples/sample-change.patch` describes the change
(a new `/api/greeting` endpoint and home banner). `bash examples/run-e2e.sh` runs the whole flow and produces
HTML with one observed and one inferred claim. CI runs it and uploads the HTML as the `walkthrough-html` artifact.

## Roadmap

- PR 2: Prometheus implementation of the read-only `MetricsAdapter` (`src/core/metrics.ts`).

## License

MIT
