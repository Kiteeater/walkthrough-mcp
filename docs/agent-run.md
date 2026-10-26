# End-to-end agent run on the demo environment

**Status: not yet executed.** This was blocked on the CI box: no headless agent CLI (`claude`, `codex`, `gemini`, `aider`, `opencode`, …) is installed there, and no LLM API key is available. Nothing under `examples/` claims an agent run happened. Once someone with an LLM key runs the steps below, they should commit the transcript summary and report path under `examples/agent-run/`.

This run is **manual by design**: it needs an LLM key, so it cannot run as a secret-free CI job. The deterministic, no-LLM equivalent that CI already runs is `npm run demo` (job `demo`). It uses the stand-in agent in `src/demo-agent/`.

## Scope / safety
- Demo environment only: local orders service, in-process MongoDB, mock Langfuse/Prometheus/mqadmin/aliyun, random loopback ports.
- No user machine, no company systems, no real cloud credentials. Do not configure aliyun; the mock CLI is used.
- The agent must **not** sign off. `sign_off` is not an MCP tool, and the prompt forbids running `walkthrough sign-off` (an agent with shell access could still run it; see issue #39).

## 1. Start the demo services (keep them running)
```bash
npm ci && npm run build
export PORT=$(node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')
export DEMO_HEALTH_TOKEN=$(node -e 'console.log(require("crypto").randomBytes(12).toString("hex"))')
HOST=127.0.0.1 node examples/orders-service/server.js &   # the demo orders service, loopback only
```

## 2. MCP config (stdio)
Example for Claude Code (`.mcp.json` at the repo root). Other agent CLIs accept the same command/args/env.
```json
{
  "mcpServers": {
    "walkthrough": {
      "command": "node",
      "args": ["dist/mcp/index.js"],
      "env": { "WALKTHROUGH_ROOT": "." }
    }
  }
}
```
Config used: `examples/walkthrough.local.json`, with `${PORT}` / `${DEMO_HEALTH_TOKEN}` taken from step 1 (export them in the shell that launches the agent).

## 3. Prompt
> Follow skills/walkthrough/SKILL.md. Requirement: "订单详情接口返回的 total 必须等于各行项目 price×qty 之和；GET /api/orders/3 不得返回 5xx." Use config examples/walkthrough.local.json. Plan checks, run them with the walkthrough MCP tools, record findings with evidence, and render the report. Do NOT sign off and do NOT run `walkthrough sign-off`. Finish by printing the report path.

## 4. Command (headless)
```bash
mkdir -p examples/agent-run
claude -p "$(cat docs/agent-run.prompt.txt)" --mcp-config .mcp.json \
  --allowedTools "mcp__walkthrough__*" --disallowedTools "Bash Edit Write" \
  --verbose --output-format stream-json > examples/agent-run/transcript.raw.jsonl
```
`--allowedTools` only **pre-approves** the listed tools. It does not disable other tools. `--disallowedTools "Bash Edit Write"` is what removes shell and file edits, so the agent should not be able to run `walkthrough sign-off`. Do not rely on this alone. Flag names and behaviour change between releases, so **verify both flags against the Claude Code version you run** (`claude --version`, `claude --help`), and always do the post-run checks below.

**Other agent CLIs (e.g. grok):** these flags are Claude Code-specific. A grok CLI (or any other agent) run needs its own tool-restriction check: confirm from that CLI's docs/`--help` how to disable shell and file-write tools, and still do the post-run checks.

## 5. Post-run checks (must all pass before committing)
```bash
# 1. no shell / edit / write tool calls in the transcript (prints OK only if none)
grep -qE '"name":"(Bash|Edit|Write)"' examples/agent-run/transcript.raw.jsonl && echo "FAIL: shell/edit/write used" || echo OK
# 2. not signed off (prints OK only if no signOff)
WT=$(ls -td .walkthrough/*/ | head -1)
grep -q '"signOff"' "$WT/walkthrough.json" && echo "FAIL: signed off" || echo OK
```

## 6. Redact, then commit
Never commit `DEMO_HEALTH_TOKEN` or any credential. Redact the raw transcript and commit only the redacted copy:
```bash
sed -E \
  -e "s/${DEMO_HEALTH_TOKEN}/<DEMO_HEALTH_TOKEN>/g" \
  -e 's/(sk-ant-|sk-|xai-|ghp_|gho_|github_pat_)[A-Za-z0-9_-]{8,}/<REDACTED_KEY>/g' \
  -e 's/("?(authorization|x-api-key|api[_-]?key|token|password|secret|cookie)"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]]+/\1<REDACTED>/Ig' \
  examples/agent-run/transcript.raw.jsonl > examples/agent-run/transcript.jsonl
rm examples/agent-run/transcript.raw.jsonl
# verify: must print nothing
grep -n -e "$DEMO_HEALTH_TOKEN" -E -e 'sk-ant-|xai-|ghp_|github_pat_' examples/agent-run/transcript.jsonl
```
Commit only:
- `examples/agent-run/transcript.jsonl` (the redacted copy; `transcript.raw.jsonl` is gitignored);
- `examples/agent-run/summary.md`: tool calls in order, findings, check verdicts, the report path (`.walkthrough/<id>/index.html`), and the post-run check results.

Review the diff by eye before pushing.
