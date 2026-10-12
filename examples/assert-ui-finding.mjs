// usage: node examples/assert-ui-finding.mjs <walkthrough dir>
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
const dir = process.argv[2];
const w = JSON.parse(readFileSync(join(dir, "walkthrough.json"), "utf8"));
const fail = (m) => { console.error(`UI ASSERT FAILED: ${m}`); process.exit(1); };
const r = (w.checkResults ?? []).find((x) => x.checkId === "ui-orders");
if (r?.status !== "fail") fail(`ui-orders should be fail (not needs-review), got ${r?.status}`);
if (!r.reasons.some((x) => /\/api\/orders → 500/.test(x))) fail("ui-orders not judged from HAR 500");
const ev = (id) => w.evidence.find((e) => e.id === id);
const f = (w.findings ?? []).find((x) => x.checkId === "ui-orders" && x.severity === "high");
if (!f) fail("no high finding for ui-orders");
const ids = f.evidenceIds.map(ev);
if (!ids.some((e) => e.type === "screenshot" && e.executedBy === "agent")) fail("finding does not cite the agent screenshot");
if (!ids.some((e) => e.type === "har" && e.executedBy === "core" && e.source.startsWith("replay:"))) fail("finding does not cite the core replay");
for (const l of f.root_cause_chain) {
  const evs = l.evidence_ids.map(ev);
  if (evs.length && evs.every((e) => e.executedBy === "agent" || e.type === "screenshot") && l.kind === "observed") fail(`step "${l.claim}" relies only on agent/screenshot evidence but is observed`);
}
if (!f.root_cause_chain.some((l) => l.kind === "observed" && l.evidence_ids.map(ev).some((e) => e.executedBy === "core"))) fail("no observed step backed by core evidence");
const log = readFileSync(join(dir, "commands.jsonl"), "utf8");
if (!/"type":"replay".*"status":500/.test(log)) fail("replay 500 not in command log");
const html = readFileSync(join(dir, "index.html"), "utf8");
if (!/class="evgrid ui-pair"/.test(html) || !/<figure data-type="screenshot" data-prov="agent">/.test(html) || !/<figure data-type="har" data-prov="core">/.test(html)) fail("audit view lacks screenshot + replay side by side");
const all = readdirSync(dir, { recursive: true }).filter((p) => /\.(har|json|jsonl|html|txt)$/.test(p)).map((p) => readFileSync(join(dir, p), "utf8")).join("\n");
if (all.includes("agent-session-cookie-SHOULD-NOT-LEAK")) fail("agent cookie leaked into artifacts");
console.log(`asserted: ui-orders=fail from HAR 500, finding ${f.id} cites screenshot + core replay`);
