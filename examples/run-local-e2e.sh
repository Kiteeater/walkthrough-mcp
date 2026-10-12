#!/usr/bin/env bash
# Real end-to-end run WITHOUT Docker: local backend (host child process, not isolated) + Playwright chromium.
# Writes the generated walkthrough, review.json and a screenshot of the rendered HTML into examples/output/.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEMO_API_KEY:=local-demo-key-$RANDOM$RANDOM}"
export DEMO_API_KEY
export LC_ALL=C

npm run build >/dev/null
rm -rf .walkthrough examples/output
# The demo agent plans its checks from the declared routes (no knowledge of any bug).
node dist/demo-agent/planner.js examples/walkthrough.local.json examples/orders-service/routes.json examples/.generated.local.json
result="$(node dist/cli/index.js run --sandbox local --config examples/.generated.local.json --root .)"
echo "$result"
id="$(node -e 'console.log(JSON.parse(process.argv[1]).id)' "$result")"
dir=".walkthrough/$id"

printf '{"walkthroughId":"%s","decisions":[{"claimId":"claim-1","decision":"agree","note":"home page screenshot matches"},{"claimId":"claim-2","decision":"flag","note":"inferred only; needs a runtime check"}],"signoff":{"decision":"reject","comment":"fix the traced root cause, then re-run the walkthrough"}}\n' "$id" > "$dir/review.json"
node dist/cli/index.js import-review "$dir/review.json" --root .
node dist/cli/index.js render "$id" --root . >/dev/null

node -e '
const { chromium } = require("playwright");
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1100, height: 900 } });
  await p.goto("file://" + require("path").resolve(process.argv[1])); await p.screenshot({ path: process.argv[2] }); await p.screenshot({ path: process.argv[2].replace(/\.png$/, "-full.png"), fullPage: true });
  await b.close();
})();' "$dir/index.html" "$dir/walkthrough-html.png"

grep -q 'class="badge observed"' "$dir/index.html"
grep -q 'class="badge inferred"' "$dir/index.html"
grep -q '本地运行、未隔离' "$dir/index.html"
grep -q 'class="review flag"' "$dir/index.html"
grep -q 'data-count="agreed">1<' "$dir/index.html"
grep -q 'id="verdict"' "$dir/index.html"
node -e 'const w=require(process.argv[1]);console.log("checks:",w.checkResults.map(r=>r.checkId+"="+r.status).join(" "));for(const f of w.findings||[])console.log("finding:",f.severity,f.title)' "$PWD/$dir/walkthrough.json"
if grep -rqF "$DEMO_API_KEY" "$dir"; then echo "secret leaked into output" >&2; exit 1; fi

mkdir -p examples/output && cp -r "$dir"/. examples/output/
echo "LOCAL E2E OK: examples/output/index.html"
