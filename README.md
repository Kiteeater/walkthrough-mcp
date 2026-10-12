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
- Judgment rule: if **any** evidence fails the expectation → `fail`, whoever executed it. If all satisfy it: at least one
  core-executed piece → `pass`; agent-reported only → `pass_needs_review` (flagged on the report's first screen).
  (`count` is judged on the combined evidence.)
- Imported results and params are also scrubbed of generic secret patterns (`sk-lf-…`, `pk-lf-…`, `Bearer …`,
  `Authorization` / `Cookie` / `X-Api-Key` values, `sk-…`, `AKIA…`, `LTAI…`), not only env-known secrets.
- `plan_checks` with `append: true` (+ required `triggering_evidence_id`) adds follow-up checks mid-run. Append-only:
  an existing id (or a changed `expect`) is rejected; each appended check is a hash-chained `plan_append` entry in
  `commands.jsonl` (timestamp, check sha256, triggering evidence) checked by `verify_command_log`; the report lists them
  separately as **追查中追加**.
  Root-cause chain steps in the HTML are marked **agent 自报** (dashed amber) vs **我们执行** (solid green).

Demo: `npm run build && node examples/trace-demo/run.mjs .` starts a real MongoDB (`mongodb-memory-server`, or
`$MONGO_URL`), a mock Langfuse and `examples/trace-demo/service`. The agent finds `GET /api/orders/ord-3/total` → 500,
follows the response's trace id into Langfuse, the trace's `orderId` into Mongo (doc has no `items`), and the stack
trace to `pricing.js:3`: `HTTP 500 → Langfuse trace → Mongo doc → file:line`. Committed run: `examples/output-trace/`.

## run_cli and verify_command_log

`run_cli` lets the agent ask the core to run a **read-only, allowlisted** CLI on its behalf. The core executes it
(`executedBy: "core"`), stores the redacted output as evidence and appends one line to `commands.jsonl`.

- **argv only**: spawned as `spawn(binary, args)` with `shell: false`; arguments containing shell syntax (`;`, `|`, `$()`, …) are rejected.
- **Subcommand allowlist** per connector (e.g. `aliyun sls GetLogs`, `mqadmin topicStatus`).
- **Per-subcommand argument allowlist** (`args` in the connector config): after the subcommand, only listed flags are
  accepted, as `--flag value` or `--flag=value`, matched exactly (case-sensitive). Everything else is rejected,
  including global flags such as `--endpoint`, `--insecure`, `--body-file`, `--config-path`, `--profile` and credential flags.
- **aliyun / mqadmin argument values may not start with `-`** (side effect of the flag-value check: a value like `-1`
  or `-foo` is treated as a smuggled flag and rejected).
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

## UI evidence (screenshots, HAR) and replay

The host agent drives the page itself (computer use / Playwright MCP) and hands over what it got with
`capture_evidence(type=submit, kind=screenshot|har)`; DOM text goes in as `kind=http`. All of it is **agent-reported**.

- **Screenshots are never judged.** They are for human audit only: the audit view shows them next to the network
  evidence. A check backed only by a screenshot is `inconclusive`, whatever the expectation.
- **`expect.type: "ui"`** judges network or text: `{"har": {"urlMatch": "/api/orders$", "status": [200, 299], "bodyMatch?": "...", "method?": "GET"}}`
  reads HAR entries; `{"text": {"contains": "..."}}` reads DOM text. Exactly one of the two. Agent-supplied regexes
  (`urlMatch`, `bodyMatch`, `replay_request.url_match`) get a ReDoS guard: ≤ 200 chars, no backreferences, no nested
  or alternation quantifiers like `(a+)+` / `(a|aa)*`; matched against at most 2 KB of URL / 64 KB of body. Other
  expect patterns are capped at 500 chars.
- **HAR redaction** before anything is stored: header values are masked when the header NAME matches a credential
  pattern (`authorization`, `cookie`, `token`, `api-key`, `secret`, `session`, `auth`, `csrf`, `signature`, `jwt`… so
  `X-Access-Token`, `X-Goog-Api-Key`, `X-Session-Id`, `Set-Cookie` are covered) and all cookie values are masked;
  query/form params are masked when the whole name or its last `-`/`_`/`.` segment is a credential word (`token`,
  `access_token`, `key`, `api_key`, `secret`, `sig`, `signature`, `password`, `session`, `sid`, `jwt`, `ticket`, `code`…;
  `barcode`, `zipcode`, `monkey` are kept); request and response bodies (and
  every other string) go through the generic secret patterns plus env-secret redaction.
- **HAR/screenshot by `path`**: the file must resolve (realpath, so symlinks are followed) to a regular file inside
  `.walkthrough/`; HAR ≤ 5 MB, screenshot ≤ 10 MB. Content submitted inline has the same caps.
- **Provenance**: agent-reported HAR/screenshots alone give at most `pass_needs_review`, same as other imports.
- **No computer use on the host?** `capture_page(check_id, url)` makes walkthrough load the page with Playwright and
  store screenshot + HAR + DOM text as core-executed evidence (needs `npx playwright install chromium`; CI e2e has it).
  It uses the **same policy as replay** (needs `replay.allowHosts`): the URL is pre-checked before a browser starts,
  and every main-frame navigation, including each redirect hop, is intercepted (`route`) and fetched by walkthrough's
  own fetcher (allowlist + IP rules, DNS resolved once, connection pinned to that IP), then handed to Chromium. So
  the main document can't be redirected or DNS-rebound to a forbidden address. Navigations and sub-resources are
  logged in the `capture_page` entry of `commands.jsonl`.
  **Known gap:** sub-resources (scripts, images, XHR/fetch), iframe navigations, popups opened with `window.open`
  (their main frame is a different page) and WebSockets (which don't go through `route` at all) are loaded by Chromium
  itself with its own DNS: they are logged where visible, **not blocked**, and not pinned. `capture_page` sends no
  test-account credentials. A page on an allowlisted host can make the browser request
  internal addresses. Tracked in [#11](https://github.com/Kiteeater/walkthrough-mcp/issues/11); until then use
  `capture_page` only against your own service inside the sandbox.
- **Over-redaction note:** the `code` query parameter (OAuth authorization codes) is always masked, so a harmless
  `?code=…` (e.g. a product or error code) shows up as `[REDACTED]`; judge on the status/body instead.

### replay_request (core-executed)

`replay_request(check_id, evidence_id, url_match?, method?)` takes **one** request from a HAR item and walkthrough
sends it itself; the result is stored as a one-entry HAR (`executedBy: core`) and appended to the hash-chained
`commands.jsonl`. So a UI finding can be confirmed by evidence we executed, and judged as a normal pass/fail.

Configure it in `walkthrough.config.json` (no `replay` block → replay is disabled):

```json
{ "replay": { "allowHosts": ["orders.staging.example.com", "127.0.0.1:3300"], "allowCidrs": ["127.0.0.1/32"],
              "auth": { "header": "Authorization", "valueEnv": "WALKTHROUGH_TEST_ACCOUNT_AUTH" } } }
```

- Only `GET` / `HEAD`. Only the method and URL come from the HAR; its cookies, `Authorization` and other headers and
  body are never sent. If the target needs auth, the test-account value comes from the env var named in config
  (`auth.valueEnv`). It is bound to origins (scheme://host:port): `auth.origins` if given, else only the origin of the
  replayed URL. Headers are rebuilt per hop, so a redirect to another host, port or scheme (including https → http)
  carries no account and no cookies; only an origin listed in `auth.origins` gets the account again.
- The account value is added to the redactor for that run before anything is written (HAR, `commands.jsonl`, evidence
  source, HTML), even when its env name doesn't look secret, so a server that echoes it back can't leak it.
- Host must be in `allowHosts` (optionally `host:port`). Redirects are not followed automatically: each hop goes
  through the allowlist and IP checks again (max 3).
- IP policy, checked on the address actually connected to (DNS resolved once per hop, connection pinned to that IP and
  the socket's remote address re-checked, so DNS rebinding can't swap it):
  - cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) is **always** denied, even if listed;
  - private (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`), link-local (`169.254/16`, `fe80::/10`),
    loopback (`127/8`, `::1`), `0/8`, multicast (`224/4`, `ff00::/8`), reserved (`240/4`), benchmarking
    (`198.18/15`), Teredo (`2001::/32`) and NAT64 local-use (`64:ff9b:1::/48`) are denied unless the CIDR is listed
    in `allowCidrs`. The allowed private/loopback scope is exactly the configured CIDRs; loopback exceptions must be
    exact hosts (`127.0.0.1/32`, `::1/128`), wider loopback ranges are ignored;
  - IPv6 forms that embed an IPv4 address are judged by the IPv4 rules: IPv4-mapped `::ffff:0:0/96`
    (`::ffff:127.0.0.1`, `::ffff:a9fe:a9fe`), IPv4-compatible `::/96` (`::127.0.0.1`), NAT64 `64:ff9b::/96`
    (`64:ff9b::a9fe:a9fe`) and 6to4 `2002::/16` (`2002:a9fe:a9fe::1`). To allow one, list the IPv4 form.
- The local demo lists `127.0.0.1/32` explicitly; nothing is reachable on loopback by default.

Demo (`node examples/ui-demo/run.mjs`, part of `examples/run-e2e.sh`): the orders page calls `/api/orders` and shows
"Failed to load orders"; the agent's screenshot shows the banner, its HAR shows the 500, walkthrough replays
`GET /api/orders` → 500, and the check is a normal `fail`. The finding shows the screenshot and the replay side by side.

## Prometheus metrics (read-only)

`query_metrics` (MCP) / `walkthrough metrics <id> --query <promql> [--check <id>] [--time <t>]` (CLI) make walkthrough
run **one instant query** itself and store the response as **core-executed** evidence (`kind: metric`, sha256,
redacted) plus a hash-chained `metrics_query` entry in `commands.jsonl`. No Grafana, no dashboards.

- Endpoint from env: `WALKTHROUGH_PROMETHEUS_URL` (base URL, e.g. `https://prom.internal:9090` or
  `https://host/prometheus`), optional bearer token from `WALKTHROUGH_PROMETHEUS_TOKEN` (or the env var named by
  `WALKTHROUGH_PROMETHEUS_TOKEN_ENV`). The token value is added to the redactor for the run before anything is written
  (evidence, log, source, HTML), whatever its env name.
- **Only `GET /api/v1/query`.** The URL is built by walkthrough (`<base>/api/v1/query?query=…[&time=…]`); a base URL
  that already points at an `/api/` path (admin, write, remote_write, query_range, alerts…) or carries a query string is
  rejected, and every redirect hop must still be `/api/v1/query`.
- **Same SSRF policy as replay**: the endpoint host must be in `replay.allowHosts` of `walkthrough.config.json`; IP
  rules, DNS pinning and per-hop redirect checks apply; the token is bound to the endpoint's origin (dropped on any
  redirect to another origin).
- Limits: query ≤ 2000 chars, response ≤ 1 MB (larger → rejected, not truncated), 10 s overall timeout (configurable
  via `CoreDeps.prometheus`).
- **Expectation** `{"type": "metric", "value": {"op": ">", "value": 0, "query?": "<promql>"}}` (ops `> >= < <= == !=`),
  judged by `evaluate_check`. Exactly one series with one finite value is required: an empty result, `NaN`/`±Inf`,
  multiple series or a non-`success` Prometheus status is **inconclusive** (never treated as 0). Aggregate to one series
  (`sum(...)`). Metric evidence is executed by walkthrough, so it gives a normal pass/fail (not `pass_needs_review`).
- A finding that cites metric evidence shows it on the first screen ("📈 指标佐证 · metric confirms: `<query>` = value").

Demo: the trace demo (`examples/trace-demo`, part of `run-e2e.sh`) starts a mock Prometheus
(`mock-prometheus.mjs`, bearer token required) whose `http_requests_total` shows a 5xx spike; the agent appends a check
"5xx ratio of `/api/orders/:id/total` over 5m > 0", walkthrough queries it (0.5 → pass) and the finding's chain reads
HTTP 500 → Prometheus 5xx ratio → Langfuse trace → Mongo record → `pricing.js:3`.

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

- Prometheus: range queries / alerting rules are not supported (instant queries only).

## License

MIT
