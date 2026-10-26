---
name: walkthrough
description: Verify a change by running it and recording evidence through the walkthrough MCP server. Use when asked to check what a change actually does, test a requirement, or investigate a failure with evidence a human can audit.
---

# Walkthrough workflow

You plan and execute the checks. walkthrough stores the evidence and decides every verdict. Do not state a verdict
yourself; only `evaluate_check` decides pass / fail / inconclusive. A human reads the audit page and signs off.
`sign_off` is not an MCP tool: you cannot sign, and an MCP call to it is refused. The human signs with the CLI
(`walkthrough sign-off`) or `import-review`.

Write check intents, findings, chain steps and reasons in the user's language (e.g. 中文).

## 0. Safety rules (read first)

- **Read-only only.** Use read-only accounts, read-only CLI presets (`run_cli`) and GET-only replays. Never run
  writes, deletes, restarts or config changes against shared environments.
- **No production accounts.** Use staging or sandbox credentials scoped to read-only. If only a production account is
  available, stop and ask.
- **Blocked targets.** `34.142.135.39` is on walkthrough's core blocklist and is always refused (also via DNS,
  even if allowlisted); don't try to work around a refusal. Never target it or any host the operator lists as
  blocked, and don't add such hosts to `replay.allowHosts` / `allowCidrs` / `capture.allowWebSocketHosts`. If a requirement points at a blocked host, stop and
  report that instead of testing.
- **No credentials in evidence.** Never paste tokens, keys, passwords or cookies into `capture_evidence`, claims or
  findings. Secrets go in the server's environment only. Redaction is a backstop, not permission. Screenshots are not
  redacted, so don't capture pages that show secrets.
- **No fake results.** Every piece of evidence must be real, unedited output from a run you actually did. If you
  cannot run something, record that as inconclusive with the reason. Never invent output.

## 1. Get the requirement

Restate in one or two sentences what the change should do and which user-visible behaviours it touches. If the
requirement is ambiguous, ask before planning. Note the environment (local sandbox, staging) and what read-only
access you have.

## 2. Reason and plan (before touching anything)

1. `start_walkthrough {title, sandbox}`. Then `run_in_sandbox up` if the system runs locally.
2. `plan_checks {goal, checks}`: one check per behaviour. Each check needs:
   - `id` and `intent`;
   - `method` (`http` | `ui` | `cli` | `mcp` | `script`) and `target`;
   - a machine-checkable `expect`: `status`, `count`, `regex`, `threshold`, `absent`, `ui`, `metric` or `sls_empty`;
   - `severity_if_fail`.

   Plan before looking at any results. A check without a checkable `expect` is rejected.
3. Optional: `start_watch {id, window_s}` before triggering anything, so alerts are watched in the background.

## 3. Call MCP tools only for real testing

Use a tool only to execute a planned check or to trace a failure. Don't call tools to look busy, and don't re-run a
check to get a different answer.

Prefer the tools where walkthrough runs the action itself. They count as stronger evidence:

| Need | Tool |
|---|---|
| HTTP request (GET, allowlisted host) | `replay_request` |
| Page screenshot / HAR | `capture_page` |
| Prometheus instant query | `query_metrics` |
| Read-only CLI (cloud logs, MQ, …) | `run_cli` (preset allowlists; `\|`, credential and endpoint flags are rejected) |
| Sandbox logs | `capture_evidence {type: logs}` |
| Output you produced yourself | `capture_evidence {type: submit}` (raw, unedited) |
| Results from another MCP server | `import_mcp_result` |

Then call `evaluate_check {checkId, evidenceIds}` for every check. Accept the result; don't argue with it.

## 4. Trace failures

For each fail:
- add follow-up checks with `plan_checks {append: true, triggeringEvidenceId}`;
- execute them as above;
- `link_source {file, line}` for the code involved;
- `record_claim` for individual observed or inferred statements.

## 5. Record findings with evidence

`record_finding {title, severity, symptom, check_id, repro_steps, root_cause_chain, ruled_out?, inconclusive?}`

- **`root_cause_chain`**: each step is `observed` (must cite verified evidence ids) or `inferred` (clearly marked
  as reasoning).
- **`ruled_out` (已排除): gated by core.** Each item is rejected unless all of these hold:
  - it has a `check_id`;
  - that check's latest verdict is `pass` (`pass_needs_review` is not enough: agent-reported evidence alone cannot
    rule something out);
  - it cites only evidence that verdict was judged on.

  Rule something out only after a check you planned for it passed.
- **`inconclusive` (未下结论).** Use it when you looked but could not decide, with a `claim`, a `reason` and its
  evidence. Typical causes:
  - the check's verdict is `inconclusive`;
  - an SLS query whose `meta.progress` is not `Complete`;
  - missing access;
  - a timeout.

  These render in their own 未下结论 block with the reason. Never move them into `ruled_out`, and never drop them.

## 6. Finish

1. `collect_watch {watch_id}` if you started one.
2. `render_walkthrough`.
3. Optionally `verify_command_log` to confirm the command log's hash chain.
4. Reply with the audit page path, the number of findings, any 未下结论 items with their reasons, and
   "ready for sign-off". Stop there. A human signs off.
