#!/usr/bin/env bash
# End-to-end: build, let the demo agent run its checks against Docker Compose + Playwright, assert the findings.
set -euo pipefail
cd "$(dirname "$0")/.."
# Generate the demo secret WITHOUT xtrace so its value never reaches CI logs.
: "${DEMO_API_KEY:=e2e-demo-key-$RANDOM$RANDOM}"
export DEMO_API_KEY
set -x

[ -d dist ] || npm run build
rm -rf .walkthrough e2e-output
# The demo agent plans checks from the declared routes (no knowledge of any bug), executes them itself,
# submits raw output via capture_evidence, and the core judges each check.
result="$(node dist/demo-agent/run.js examples/walkthrough.config.json examples/orders-service/routes.json --root .)" || { rc=$?; echo "demo run exited $rc" >&2; ls -la .walkthrough/*/ 2>&1 || true; exit $rc; }
echo "$result"
id="$(node -e 'console.log(JSON.parse(process.argv[1]).id)' "$result")"
dir=".walkthrough/$id"
html="$dir/index.html"

grep -q 'class="badge observed"' "$html"
grep -q 'Export review.json' "$html"
grep -q 'id="verdict"' "$html"
ls "$dir"/evidence/*.png >/dev/null
# Assert what the agent FOUND, not just page markers.
node examples/assert-findings.mjs "$dir/walkthrough.json"
set +x
if grep -rqF "$DEMO_API_KEY" "$dir"; then echo "secret leaked into output" >&2; exit 1; fi
set -x

# Round-trip a review decision + report sign-off through import-review.
printf '{"walkthroughId":"%s","decisions":[{"claimId":"claim-1","decision":"agree"},{"claimId":"claim-2","decision":"flag","note":"needs a runtime check"}],"signoff":{"decision":"reject","comment":"fix the traced root cause first"}}' "$id" > /tmp/review.json
node dist/cli/index.js import-review /tmp/review.json --root .
node dist/cli/index.js render "$id" --root . >/dev/null
grep -q '"decision": "flag"' "$dir/walkthrough.json"
grep -q '"decision": "reject"' "$dir/walkthrough.json"

mkdir -p e2e-output && cp -r "$dir" e2e-output/
echo "E2E OK: $html"
