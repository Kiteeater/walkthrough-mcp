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

## 5. Post-run checks (must all print OK before committing)
Each check prints `FAIL` if its input is missing, unreadable or empty, and if `grep` itself errors (exit 2). It never passes on a read error.
```bash
T=examples/agent-run/transcript.raw.jsonl
fail=0
# 0. transcript present, readable, non-empty
if [ -r "$T" ] && [ -s "$T" ]; then echo "OK: transcript present"; else echo "FAIL: transcript missing/unreadable/empty: $T"; fail=1; fi
# 1. no shell / edit / write tool calls
if [ "$fail" = 0 ]; then
  rc=0; grep -qE '"name"[[:space:]]*:[[:space:]]*"(Bash|Edit|Write)"' "$T" || rc=$?
  case $rc in 0) echo "FAIL: Bash/Edit/Write tool call in transcript"; fail=1;; 1) echo "OK: no Bash/Edit/Write calls";; *) echo "FAIL: grep error ($rc) on $T"; fail=1;; esac
fi
# 2. this run's walkthrough id, taken from the transcript (exactly one wt-<14 digits>-<6 hex> id), not "newest dir"
WT_ID=""
if [ "$fail" = 0 ]; then
  ids=$(grep -oE 'wt-[0-9]{14}-[0-9a-f]{6}' "$T" | sort -u) || true
  if [ "$(printf '%s\n' "$ids" | grep -c .)" = 1 ]; then WT_ID=$ids; echo "OK: walkthrough id $WT_ID"; else echo "FAIL: expected exactly one walkthrough id in transcript, got: ${ids:-none}"; fail=1; fi
fi
# 3. not signed off
if [ -n "$WT_ID" ]; then
  W=".walkthrough/$WT_ID/walkthrough.json"
  if [ -r "$W" ] && [ -s "$W" ]; then
    rc=0; grep -q '"signOff"' "$W" || rc=$?
    case $rc in 0) echo "FAIL: $WT_ID is signed off"; fail=1;; 1) echo "OK: not signed off";; *) echo "FAIL: grep error ($rc) on $W"; fail=1;; esac
  else echo "FAIL: $W missing/unreadable/empty"; fail=1; fi
fi
[ "$fail" = 0 ] && echo "POST-RUN CHECKS: OK" || echo "POST-RUN CHECKS: FAIL"
```
Record `walkthrough_id: $WT_ID` in `summary.md`.

## 6. Redact, then commit
Never commit `DEMO_HEALTH_TOKEN` or any credential. The token must be a plain hex/alnum string (as generated in step 1), because it is used inside a `sed` pattern. Run this block as one unit, in a subshell so `set -e` does not close your terminal. The raw file is removed only after `sed` succeeds and both verification greps come back clean.
```bash
(
set -euo pipefail
: "${DEMO_HEALTH_TOKEN:?DEMO_HEALTH_TOKEN must be set to redact it}"
RAW=examples/agent-run/transcript.raw.jsonl OUT=examples/agent-run/transcript.jsonl
[ -r "$RAW" ] && [ -s "$RAW" ] || { echo "FAIL: $RAW missing/unreadable/empty"; exit 1; }
# sensitive field prefix: key (optionally quoted, also \"escaped\" inside JSON strings), then : or =, then optional quote
P='\\?"?(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|secret)\\?"?[[:space:]]*[:=][[:space:]]*\\?"?'
sed -E \
  -e "s/${DEMO_HEALTH_TOKEN}/<DEMO_HEALTH_TOKEN>/g" \
  -e 's/(sk-ant-|sk-|xai-|ghp_|gho_|github_pat_)[A-Za-z0-9_-]{8,}/<REDACTED_KEY>/g' \
  -e "s/(${P})[^\",\\\\]*/\\1<REDACTED>/Ig" \
  "$RAW" > "$OUT"
[ -s "$OUT" ] || { echo "FAIL: redacted output empty"; exit 1; }
# verify 1: no token / known key prefixes left (grep exit 1 = clean; 0 = leak; 2 = error)
rc=0; grep -nF -e "$DEMO_HEALTH_TOKEN" "$OUT" || rc=$?; [ "$rc" = 1 ] || { echo "FAIL: DEMO_HEALTH_TOKEN left (rc=$rc)"; exit 1; }
rc=0; grep -nE 'sk-ant-|xai-|ghp_|gho_|github_pat_' "$OUT" || rc=$?; [ "$rc" = 1 ] || { echo "FAIL: API-key-like value left (rc=$rc)"; exit 1; }
# verify 2 (reverse): every cookie/authorization/token/password/secret/api-key value must be exactly <REDACTED>
rc=0; grep -oiE "${P}[^\",\\\\]*" "$OUT" | sed -E "s/^${P}//I" | grep -vxF '<REDACTED>' || rc=$?
[ "$rc" = 1 ] || { echo "FAIL: sensitive field with a non-<REDACTED> value (rc=$rc)"; exit 1; }
rm -- "$RAW"
echo "REDACTION: OK ($OUT)"
)
```
Commit only:
- `examples/agent-run/transcript.jsonl` (the redacted copy; `transcript.raw.jsonl` is gitignored);
- `examples/agent-run/summary.md`: `walkthrough_id`, tool calls in order, findings, check verdicts, the report path (`.walkthrough/<id>/index.html`), and the post-run check output.

Review the diff by eye before pushing.
