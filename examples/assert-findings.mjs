// Fail unless the agent's run produced at least one HIGH finding whose root-cause chain points at orders.js.
// usage: node examples/assert-findings.mjs <walkthrough.json>
import { readFileSync } from "node:fs";

const w = JSON.parse(readFileSync(process.argv[2], "utf8"));
console.log("checks:", (w.checkResults ?? []).map((r) => `${r.checkId}=${r.status}`).join(" "));
const srcFile = (id) => w.sources.find((s) => s.id === id);
const hits = (w.findings ?? []).filter((f) => f.severity === "high" && f.root_cause_chain.some((l) => /(^|\/)orders\.js$/.test(srcFile(l.source_ref)?.file ?? "")));
for (const f of w.findings ?? []) {
  const src = f.root_cause_chain.map((l) => srcFile(l.source_ref)).find(Boolean);
  console.log("finding:", f.severity, f.title, "->", src ? `${src.file}:${src.line}` : "(no source)");
}
if (!hits.length) {
  console.error("E2E ASSERT FAILED: expected >=1 high-severity finding whose root cause points to orders.js");
  process.exit(1);
}
if (!(w.checkResults ?? []).some((r) => r.status === "fail")) { console.error("E2E ASSERT FAILED: no failed check"); process.exit(1); }
console.log(`asserted: ${hits.length} high finding(s) rooted in orders.js`);
