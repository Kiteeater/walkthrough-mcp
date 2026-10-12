# Read-only access checklist (company environment)

Walkthrough only ever **reads** production-like systems. Ask for the narrowest read-only access below, one
credential per system, dedicated to walkthrough (so it can be revoked and audited on its own). Nothing here is
connected by default; every value below is a placeholder.

General rules
- Credentials live in the environment of the process that starts walkthrough (MCP server / CLI) or in the tool's
  own profile file — never in `walkthrough.config.json`, prompts or committed files.
- Every host walkthrough itself calls must be listed in `replay.allowHosts` of `<project>/walkthrough.config.json`
  (IP policy, redirect re-checks and redaction apply).
- Values of the env vars named below are added to the redactor; they never appear in evidence or the audit page.

| System | What to request | Where the config goes | How walkthrough uses it |
|---|---|---|---|
| **Aliyun** (SLS logs, ECS/ACK describe) | A RAM user or role with only `ReadOnlyAccess`-style policies scoped to the needed products (e.g. `AliyunLogReadOnlyAccess`; custom policy limited to `log:Get*`, `log:List*`, `ecs:Describe*`) on the needed projects/regions. No `*:Create*`/`Update*`/`Delete*`. | `aliyun configure --profile walkthrough-ro` → `~/.aliyun/config.json`. Point walkthrough at the profile name. Env-var credentials are **not** supported (see run_cli). | `run_cli` allowlist of read-only subcommands; `--endpoint`/`--insecure`-style globals are rejected; every call is logged in `commands.jsonl`. |
| **MongoDB** | A user with the built-in `read` role on the specific database(s) only (not `readAnyDatabase`, no `readWrite`). Prefer a secondary / analytics node. | Connection string in the connection setting (env) of the MongoDB MCP server you already run, with that server in its read-only mode. | Results come in through `import_mcp_result` (agent-reported, lower trust). |
| **RocketMQ** | An ACL account allowed only to query: topic/route/consumer-progress/message lookup (`mqadmin topicList`, `topicRoute`, `consumerProgress`, `queryMsgById`). No `updateTopic`, `deleteTopic`, `resetOffset`, `sendMessage`. | `mqadmin` with `-n <nameserver>`; ACL access/secret key in the tool's ACL config file (`conf/tools.yml`), not in env passed to the agent. | Planned: `run_cli` allowlist of the query subcommands above (not shipped yet). |
| **Langfuse** | A project-scoped API key pair for the one project. Use it only with the read API (`GET /api/public/traces/*`, `/observations`). Langfuse keys are not read-only by design, so keep this key for walkthrough alone and rotate it. | `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` / `LANGFUSE_HOST` in the env of the Langfuse MCP server. | `import_mcp_result` of `get_trace` (agent-reported). |
| **Prometheus** | Read access to `GET /api/v1/query` and `GET /api/v1/alerts` only — through a proxy/gateway that denies `/api/v1/admin/*`, remote write and everything else; a bearer token for that proxy. | `WALKTHROUGH_PROMETHEUS_URL` (base URL, e.g. `http://prometheus.internal.example:9090`), `WALKTHROUGH_PROMETHEUS_TOKEN` (or the env name set via `tokenEnv`); host in `replay.allowHosts`. | `query_metrics`, `start_watch`/`collect_watch` (core-executed). Walkthrough also refuses any other path itself. |

Request template (copy into the ticket):

```text
Purpose: automated, read-only verification of changes (walkthrough). No writes, no admin.
System: <Aliyun | MongoDB | RocketMQ | Langfuse | Prometheus>
Scope: <projects / databases / topics / project / endpoints>
Permissions: <from the table above>
Credential delivery: <profile name / secret store entry>, owned by <team>, rotated every <N> days.
```
