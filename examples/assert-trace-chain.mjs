// Fail unless the trace run produced a HIGH finding whose root-cause chain spans
// HTTP 500 → Langfuse trace (imported, agent-reported) → Mongo doc (imported, agent-reported) → file:line (logs we captured).
// usage: node examples/assert-trace-chain.mjs <walkthrough.json>
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const w = JSON.parse(readFileSync(process.argv[2], "utf8"));
const fail = (m) => { console.error(`E2E ASSERT FAILED: ${m}`); process.exit(1); };
const ev = (id) => w.evidence.find((e) => e.id === id);
console.log("checks:", (w.checkResults ?? []).map((r) => `${r.checkId}=${r.status}`).join(" "));
const f = (w.findings ?? []).find((x) => x.severity === "high");
if (!f) fail("no high finding");
const steps = f.root_cause_chain.map((l) => ({ l, e: l.evidence_ids.map(ev) }));
for (const s of steps) console.log(" -", s.e.map((e) => `${e.id}:${e.kind}/${e.executedBy}${e.mcpCall ? `/${e.mcpCall.connector}.${e.mcpCall.tool}` : ""}`).join(","), "|", s.l.claim);
const idx = (pred) => steps.findIndex((s) => s.e.some(pred));
const iHttp = idx((e) => e.kind === "http" && /HTTP 500/.test(readFileSync(join(dirname(process.argv[2]), e.path), "utf8")));
const iTrace = idx((e) => e.kind === "mcp_result" && e.executedBy === "agent" && e.mcpCall?.connector === "langfuse");
const iDoc = idx((e) => e.kind === "mcp_result" && e.executedBy === "agent" && e.mcpCall?.connector === "mongodb");
const iMetric = idx((e) => e.kind === "metric" && e.executedBy === "core");
const mres = (w.checkResults ?? []).find((r) => /-5xx$/.test(r.checkId));
if (iMetric < 0 || !(iHttp < iMetric && iMetric < iTrace)) fail(`metric step missing or out of order (metric=${iMetric})`);
if (mres?.status !== "pass") fail(`metric check should pass on core evidence (not needs_review), got ${mres?.status}`);
const html = readFileSync(join(dirname(process.argv[2]), "index.html"), "utf8");
const first = html.slice(html.indexOf('id="verdict"'), html.indexOf("</section>", html.indexOf('id="verdict"')));
if (!/class="metric-confirm"[^>]*>📈[^<]*<code>[^<]*5\.\.[^<]*<\/code> = <b>0\.5<\/b>/.test(first)) fail("first screen does not show the metric confirming the issue");
const iAlert = idx((e) => e.kind === "alert" && e.executedBy === "core");
if (iAlert < 0 || !(iHttp < iAlert && iAlert < iTrace)) fail(`alert step missing or out of order (alert=${iAlert})`);
if (!/alert HighOrders5xx firing/.test(steps[iAlert].l.claim)) fail("alert step does not name HighOrders5xx");
const aw = (w.alertWatches ?? [])[0];
if (!aw?.matched.some((m) => m.alertname === "HighOrders5xx" && m.attached && m.findingId === f.id)) fail("HighOrders5xx not attached to the 500 finding");
if (!aw.unmatched.some((u) => u.alertname === "DiskAlmostFull") || aw.matched.some((m) => m.alertname === "DiskAlmostFull")) fail("DiskAlmostFull should be listed as unmatched");
if (aw.matched.concat(aw.unmatched).some((m) => m.alertname === "SlowCheckout")) fail("pending alert counted");
if (!/class="alert-confirm" data-alert="HighOrders5xx"/.test(first)) fail("first screen does not show the firing alert on the 500 finding");
if (!/class="unmatched-alerts" data-unmatched="1"[\s\S]*DiskAlmostFull/.test(first)) fail("first screen does not list the unmatched alert");
const iSrc = steps.findIndex((s) => s.l.source_ref && s.e.some((e) => e.executedBy === "core"));
if ([iHttp, iTrace, iDoc, iSrc].some((i) => i < 0)) fail(`chain incomplete http=${iHttp} langfuse=${iTrace} mongo=${iDoc} src=${iSrc}`);
if (!(iHttp < iTrace && iTrace < iDoc && iDoc < iSrc)) fail("chain steps out of order");
const t = steps[iTrace].e.find((e) => e.mcpCall), d = steps[iDoc].e.find((e) => e.mcpCall);
if (!t.links?.some((l) => steps[iHttp].e.some((e) => e.id === l.evidenceId))) fail("langfuse evidence not linked to the HTTP evidence");
if (!d.links?.some((l) => l.evidenceId === t.id)) fail("mongo evidence not linked to the langfuse evidence");
const src = w.sources.find((s) => s.id === steps[iSrc].l.source_ref);
if (!/pricing\.js$/.test(src.file)) fail(`root cause not in pricing.js: ${src.file}`);
console.log(`asserted cross-source chain: HTTP 500 → alert HighOrders5xx → prometheus 5xx ratio → langfuse.${t.mcpCall.tool} → mongodb.${d.mcpCall.tool} → ${src.file}:${src.line}`);
