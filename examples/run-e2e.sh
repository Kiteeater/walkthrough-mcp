#!/usr/bin/env bash
# End-to-end: build, run the sample walkthrough against Docker Compose + Playwright, verify the HTML.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEMO_API_KEY:=e2e-demo-key-$RANDOM$RANDOM}"
export DEMO_API_KEY

[ -d dist ] || npm run build
rm -rf .walkthrough e2e-output
result="$(node dist/cli/index.js run --config examples/walkthrough.config.json --root .)"
echo "$result"
id="$(node -e 'console.log(JSON.parse(process.argv[1]).id)' "$result")"
html=".walkthrough/$id/index.html"

grep -q 'class="badge observed"' "$html"
grep -q 'class="badge inferred"' "$html"
grep -q 'Export review.json' "$html"
test -s ".walkthrough/$id/evidence/ev-1.png"
if grep -rqF "$DEMO_API_KEY" ".walkthrough/$id"; then echo "secret leaked into output" >&2; exit 1; fi

# Round-trip a review decision through import-review.
printf '{"walkthroughId":"%s","decisions":[{"claimId":"claim-1","decision":"agree"},{"claimId":"claim-2","decision":"flag","note":"needs a runtime check"}]}' "$id" > /tmp/review.json
node dist/cli/index.js import-review /tmp/review.json --root .
node dist/cli/index.js render "$id" --root . >/dev/null
grep -q '"decision": "flag"' ".walkthrough/$id/walkthrough.json"

mkdir -p e2e-output && cp -r ".walkthrough/$id" e2e-output/
echo "E2E OK: $html"
