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

Action sources (`http`, `command`, later `connector:<name>`), observe sources (`log`, later `connector:<name>`) and
verifiers (`verify.type`: `rule` today; `script`, `playwright`, `computer-use` reserved) go through a registry in
`src/core/registry.ts`. `evaluate_check` only talks to the verifier registry. Action and observe sources are the
execution seam the agent uses (the demo agent sends its HTTP requests through `http`), so a new read-only
connector is registered there and its output is submitted and judged like everything else.

## run_cli and verify_command_log

`run_cli` lets the agent ask the core to run a **read-only, allowlisted** CLI on its behalf. The core executes it
(`executedBy: "core"`), stores the redacted output as evidence and appends one line to `commands.jsonl`.

- **argv only**: spawned as `spawn(binary, args)` with `shell: false`; arguments containing shell syntax (`;`, `|`, `$()`, …) are rejected.
- **Subcommand allowlist** per connector (e.g. `aliyun sls GetLogs`, `mqadmin topicStatus`).
- **Per-subcommand argument allowlist** (`args` in the connector config): after the subcommand, only listed flags are
  accepted, as `--flag value` or `--flag=value`, matched exactly (case-sensitive). Everything else is rejected,
  including global flags such as `--endpoint`, `--insecure`, `--body-file`, `--config-path`, `--profile` and credential flags.
- `--region` is rejected unless the subcommand lists it **and** the value is in the connector's `regions` allowlist
  (default: none, the profile's own region is used).
- `--profile` is appended by us from config; the agent can never choose a profile or pass credentials.
- **Env**: the child env is built from an allowlist only (`PATH`, `HOME`, `LANG`, `TMPDIR`, `TERM` + configured
  `passEnv`). `ALIBABA_CLOUD_*`, `ALICLOUD_*`, `ALIYUN_*`, `ACS_*` are always stripped, even if listed in `passEnv`;
  run_cli accepts no env from the caller.
- **Credentials** are read only from the CLI's own profile config file (e.g. `~/.aliyun/config.json`); passing
  credentials via env vars is not supported (env is stripped by design).
- **mongosh** never takes agent argv: only fixed `find` / `aggregate` / `countDocuments` templates; `$out`, `$merge`,
  `$where`, `$function`, `$accumulator` are rejected at any depth.

`verify_command_log` recomputes the hash chain of `commands.jsonl` (each entry hashes its content plus the previous
hash) and compares the tail with the `{seq, hash}` head recorded in `walkthrough.json`, detecting edited, reordered or
truncated entries.

### Threat model / limits

- The hash chain is **unkeyed** (plain SHA-256, no secret). It detects accidental or partial tampering, not a
  deliberate rewrite: anyone who can write the walkthrough directory can recompute the whole log **and** the head in
  `walkthrough.json` together. Same limitation as evidence hashes. External anchoring is planned before PR #10.
- `run_in_sandbox exec` is a separate, broader path: it runs arbitrary argv in the sandbox and **does not go through
  the run_cli allowlist**, so it can still invoke e.g. `aliyun` with any flags if the binary and login state are
  reachable. Tracking issue: [#8](https://github.com/Kiteeater/walkthrough-mcp/issues/8).
- The allowlist is only as safe as the flags it lists; review additions to `args` like code.

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

CI lives in `.github/workflows/ci.yml`: it runs unit tests plus the Docker Compose + Playwright e2e and uploads the HTML artifact (`walkthrough-html`).

## Roadmap

- PR 2: Prometheus implementation of the read-only `MetricsAdapter` (`src/core/metrics.ts`).

## License

MIT
