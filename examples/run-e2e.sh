#!/usr/bin/env bash
# End-to-end: build, run the sample walkthrough against Docker Compose + Playwright, verify the HTML.
set -euxo pipefail
cd "$(dirname "$0")/.."
: "${DEMO_API_KEY:=e2e-demo-key-$RANDOM$RANDOM}"
export DEMO_API_KEY

[ -d dist ] || npm run build
rm -rf .walkthrough e2e-output
# The demo agent plans its checks from the declared routes (no knowledge of any bug).
node dist/demo-agent/planner.js examples/walkthrough.config.json examples/orders-service/routes.json examples/.generated.compose.json
result="$(node dist/cli/index.js run --config examples/.generated.compose.json --root .)" || { rc=$?; echo "walkthrough run exited $rc" >&2; ls -la .walkthrough/*/ 2>&1 || true; cat .walkthrough/*/walkthrough.json 2>&1 || true; exit $rc; }
echo "$result"
id="$(node -e 'console.log(JSON.parse(process.argv[1]).id)' "$result")"
dir=".walkthrough/$id"
html="$dir/index.html"

grep -q 'class="badge observed"' "$html"
grep -q 'class="badge inferred"' "$html"
grep -q 'Export review.json' "$html"
ls "$dir"/evidence/*.png >/dev/null
grep -q 'id="verdict"' "$dir/index.html"
node -e 'const w=require(process.argv[1]);console.log("checks:",w.checkResults.map(r=>r.checkId+"="+r.status).join(" "));for(const f of w.findings||[])console.log("finding:",f.severity,f.title)' "$PWD/$dir/walkthrough.json"
if grep -rqF "$DEMO_API_KEY" ".walkthrough/$id"; then echo "secret leaked into output" >&2; exit 1; fi

# Round-trip a review decision through import-review.
printf '{"walkthroughId":"%s","decisions":[{"claimId":"claim-1","decision":"agree"},{"claimId":"claim-2","decision":"flag","note":"needs a runtime check"}],"signoff":{"decision":"reject","comment":"fix the traced root cause first"}}' "$id" > /tmp/review.json
node dist/cli/index.js import-review /tmp/review.json --root .
node dist/cli/index.js render "$id" --root . >/dev/null
grep -q '"decision": "flag"' ".walkthrough/$id/walkthrough.json"

mkdir -p e2e-output && cp -r ".walkthrough/$id" e2e-output/
echo "E2E OK: $html"
