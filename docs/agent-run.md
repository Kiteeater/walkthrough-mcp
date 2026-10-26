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
claude -p "$(cat docs/agent-run.prompt.txt)" --mcp-config .mcp.json \
  --allowedTools "mcp__walkthrough__*" --output-format stream-json > examples/agent-run/transcript.jsonl
```
Restricting `--allowedTools` to the MCP tools keeps shell (and therefore `walkthrough sign-off`) out of reach.

## 5. What to commit
- `examples/agent-run/summary.md`: tool calls in order, findings, check verdicts, and the report path (`.walkthrough/<id>/index.html`).
- Check that the walkthrough status is not signed off (`walkthrough.json` has no `signOff`).
