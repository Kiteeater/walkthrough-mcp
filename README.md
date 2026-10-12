# walkthrough-mcp

Don't review the diff — **run the change and answer "what does it actually do?" with evidence.**
Built on WeZZard's walkthrough idea: audit the execution result, not the code.

## Audit-only workflow

Humans only audit the **final result**: which problems the agent found, how it reported them, and the root-cause
trace. Everything in between is the agent's job, with no human in the loop:

1. The agent plans its checks (`plan_checks`): `{id, intent, method: cli|mcp|ui|http|script, target,
   expect{type: status|count|regex|threshold|absent, value}, severity_if_fail}`. A check without a machine-checkable
   `expect` is rejected. The response carries `next_actions` telling the agent how to proceed with each check.
2. **The agent executes every check itself** (its own tools, an external MCP, computer use) and submits the raw,
   unedited output with `capture_evidence(type=submit, check_id, kind, source, content)`. walkthrough can also
   capture screenshots and sandbox logs itself; evidence is marked "reported by agent" or "captured by walkthrough",
   redacted, and sha256-hashed.
3. `evaluate_check(check_id, evidence_ids)`: **the core judges pass / fail / inconclusive**. The call carries no
   verdict, evidence must belong to that check and be unmodified, and nothing else can change the result.
4. The agent records findings with `record_finding(title, severity, symptom, repro_steps[], root_cause_chain[{claim,
   kind: observed|inferred, evidence_ids, source_ref?}])`. Observed steps must cite verified evidence.
5. `render_walkthrough` produces an audit view. The first screen shows only conclusions: number of findings, a
   severity breakdown, and a one-line root cause (with the source line) per finding. Each finding expands into its
   root-cause chain and evidence; per-claim Agree/Flag is optional and collapsed.
6. A human gives one report-level sign-off (`sign_off`: accept 认可 / reject 打回 + comment), in the page via
   `review.json` + `import-review`, or through the tool.

Planning and execution belong to the agent. The example's deterministic stand-in lives in `src/demo-agent/`
(outside the core), so the demo needs no LLM: it derives generic checks per declared route (2xx + no error alerts
in the logs during that request), sends the requests itself, submits the output, and traces stack frames from the
log evidence. It knows nothing about bugs. Run it with
`node dist/demo-agent/run.js examples/walkthrough.config.json examples/orders-service/routes.json`.

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

Tools: `start_walkthrough`, `run_in_sandbox` (up | down | exec), `plan_checks`, `capture_evidence`
(submit | screenshot | logs), `evaluate_check`, `record_finding`, `link_source` (file + line), `record_claim`
(observed | inferred), `render_walkthrough`, `sign_off` (accept | reject).

### Pluggable sources (seam for environment connectors)

Action sources (`http`, `command`, `connector:<name>` for imported MCP results), observe sources (`log`, later `connector:<name>`) and
verifiers (`verify.type`: `rule` today; `script`, `playwright`, `computer-use` reserved) go through a registry in
`src/core/registry.ts`. `evaluate_check` only talks to the verifier registry. Action and observe sources are the
execution seam the agent uses (the demo agent sends its HTTP requests through `http`), so a new read-only
connector is registered there and its output is submitted and judged like everything else.

## Importing results from other MCP servers

walkthrough never connects to your databases or observability stack. Mount the official servers on your host agent
**read-only**, call them yourself, then hand the raw result over with `import_mcp_result`:

| connector | server | recommended read-only setup | tools accepted for import |
|---|---|---|---|
| `mongodb` | `mongodb-mcp-server` | `npx -y mongodb-mcp-server --readOnly` (or `MDB_MCP_READ_ONLY=true`) **and** a read-only DB user | `find`, `aggregate`, `count`, `list-databases`, `list-collections`, `collection-schema`, `collection-indexes`, `explain`, `db-stats` |
| `aliyun` | `alibaba-cloud-ops-mcp-server` | `--services sls,cms --extra-config "{'sls':['GetLogs','GetHistograms'],'cms':['DescribeAlertLogList','DescribeMetricList']}"` with a read-only RAM sub-account | `sls_GetLogs`, `sls_GetHistograms`, `cms_DescribeAlertLogList`, `cms_DescribeMetricList`, `ecs_DescribeInstances` |
| `langfuse` | Langfuse MCP | allowlist only the read tools in your MCP client (the server exposes write tools by default); use a project-scoped key | `get_trace`, `list_traces`, `get_observation`, `list_observations`, `get_session`, `list_sessions` |

```jsonc
// import_mcp_result
{ "id": "wt-…", "check_id": "chk-2-trace", "connector": "langfuse", "tool": "get_trace",
  "params": { "traceId": "73c6…" }, "result": { /* raw tool result */ },
  "links": [{ "evidence_id": "ev-4", "key": "73c6…" }] }
```

- Stored as `kind: "mcp_result"`, `executedBy: "agent"` (**reported by the agent**, lower trust), `source: "connector:<name>"`,
  plus `mcpCall: {connector, server, tool, params}`; redacted and sha256-hashed like all evidence.
- `params`: credential-looking keys (`password`, `token`, `apiKey`, `authorization`, `secret`…) are replaced by
  `[REDACTED]`, `scheme://user:pass@` userinfo is stripped, then env-secret redaction runs. Never pass credentials.
- Rejected: unknown connector, a tool outside the read-only list (e.g. `insert-many`), no `links`, a linked evidence id
  that is missing or whose hash no longer matches, or a link `key` that does not occur in **both** the linked evidence
  and the imported result.
- A check judged only on agent-reported evidence is at most `pass_needs_review`; the report's first screen flags it.
  Root-cause chain steps in the HTML are marked **agent 自报** (dashed amber) vs **我们执行** (solid green).

Demo: `npm run build && node examples/trace-demo/run.mjs .` starts a real MongoDB (`mongodb-memory-server`, or
`$MONGO_URL`), a mock Langfuse and `examples/trace-demo/service`. The agent finds `GET /api/orders/ord-3/total` → 500,
follows the response's trace id into Langfuse, the trace's `orderId` into Mongo (doc has no `items`), and the stack
trace to `pricing.js:3`: `HTTP 500 → Langfuse trace → Mongo doc → file:line`. Committed run: `examples/output-trace/`.

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
>
> The same holds for the `run_cli` command log: its hash-chain tail (`commandLogHead`) is stored in `walkthrough.json`,
> which is itself mutable. Edits or truncation of `commands.jsonl` are detected, but someone who recomputes the whole
> log **and** the tail together is not. Proper external anchoring of the tail is planned before PR #10.

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

CI lives in `.github/workflows/ci.yml`: it runs unit tests plus the Docker Compose + Playwright e2e and uploads the HTML artifact (`walkthrough-html`).

## Roadmap

- PR 2: Prometheus implementation of the read-only `MetricsAdapter` (`src/core/metrics.ts`).

## License

MIT
