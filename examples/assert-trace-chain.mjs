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
// 30-second first screen: one-sentence verdict, labelled root-cause chain, sign-off.
if (!/<div class="headline" data-findings="1">发现 <b>1<\/b> 个问题：<code>\/api\/orders\/ord-3\/total<\/code> 返回 <b>500<\/b>，根因在 <code class="loc">pricing\.js:3<\/code><\/div>/.test(first)) fail("first screen lacks the one-sentence verdict");
// The demo's failed checks share one root cause: ONE problem with all of them under it.
const failedChecks = (w.checkResults ?? []).filter((r) => r.status === "fail").map((r) => r.checkId);
if (failedChecks.length < 2) fail(`expected several failed checks in the demo, got ${failedChecks.length}`);
if (!first.includes(`<div class="headline-sub" data-failed="${failedChecks.length}" data-problems="1">${failedChecks.length} 项检查失败，归为 1 个问题</div>`)) fail("first screen does not say the failures are 1 problem");
if (!first.includes(`<h3 class="problem-title">问题 1 <span class="meta">（${failedChecks.length} 项失败检查，同一根因）</span></h3>`) || first.includes("问题 2")) fail("first screen lacks 「问题 1」 grouping");
for (const c of failedChecks) if (!new RegExp(`<ul class="problem-checks"[^]*data-check="${c}"`).test(first)) fail(`failed check ${c} not listed under 问题 1`);
const rc = [...first.matchAll(/<li class="rc-step" data-prov="(\w+)"><span class="prov \w+">([^<]+)<\/span>/g)].map((m) => `${m[1]}:${m[2]}`);
if (rc.length !== f.root_cause_chain.length || rc[0] !== "core:walkthrough 执行" || !rc.includes("core:walkthrough 执行") || rc.at(-1) !== "core:walkthrough 执行") fail(`first-screen root-cause chain wrong: ${rc.join(" | ")}`);
if (!/<div class="signoff"[\s\S]*name="signoff" value="accept"[\s\S]*name="signoff" value="reject"[\s\S]*id="export"/.test(first)) fail("sign-off area not on the first screen");
// Check counts: one source, sum = total, each bucket matches the stored statuses, each links to its list.
const total = Number(/class="check-counts" data-total="(\d+)"/.exec(first)?.[1]);
const cnt = Object.fromEntries([...first.matchAll(/href="#checks-([\w-]+)" data-status="[\w-]+" data-count="(\d+)"/g)].map((m) => [m[1], Number(m[2])]));
const st = (w.checks ?? []).map((c) => (w.checkResults ?? []).find((r) => r.checkId === c.id)?.status);
const want = { pass: st.filter((x) => x === "pass").length, fail: st.filter((x) => x === "fail").length, "needs-review": st.filter((x) => x === "pass_needs_review").length };
want.none = st.length - want.pass - want.fail - want["needs-review"];
if (total !== st.length || Object.values(cnt).reduce((a, b) => a + b, 0) !== total || JSON.stringify(cnt) !== JSON.stringify(want)) fail(`check counts inconsistent: total ${total}, ${JSON.stringify(cnt)} vs ${JSON.stringify(want)}`);
for (const k of Object.keys(want)) if (!new RegExp(`<details class="check-bucket" id="checks-${k}"`).test(first)) fail(`no list behind the ${k} count`);
if (/条结论/.test(html.slice(0, html.indexOf('id="verdict"')))) fail("contradictory header counts still present");
// Times: <time> with the UTC ISO in the tooltip.
if (!/<time datetime="[^"]+Z" title="[^"]+Z \(UTC\)">/.test(first)) fail("alert times not rendered as <time> with UTC tooltip");
if (!/<details class="alerts-more">/.test(first)) fail("alert watch details should be collapsed");
if (!/class="metric-confirm"[^>]*>📈[^<]*<code>[^<]*5\.\.[^<]*<\/code> = <b>0\.5<\/b>/.test(first)) fail("first screen does not show the metric confirming the issue");
// Alerts are corroborating signals, never causal steps.
if (idx((e) => e.kind === "alert") >= 0) fail("alert spliced into the root-cause chain");
const corr = (f.corroborating ?? []).find((c) => c.alertname === "HighOrders5xx");
if (!corr || !/alert HighOrders5xx firing/.test(corr.claim) || ev(corr.evidence_ids[0])?.executedBy !== "core") fail("HighOrders5xx not listed as a corroborating signal on the 500 finding");
const aw = (w.alertWatches ?? [])[0];
if (!aw?.matched.some((m) => m.alertname === "HighOrders5xx" && m.attached && m.findingId === f.id)) fail("HighOrders5xx not attached to the 500 finding");
if (!aw.unmatched.some((u) => u.alertname === "DiskAlmostFull") || aw.matched.some((m) => m.alertname === "DiskAlmostFull")) fail("DiskAlmostFull should be listed as unmatched");
if (aw.matched.concat(aw.unmatched).some((m) => m.alertname === "SlowCheckout")) fail("pending alert counted");
// Timing: the watch started before the action; the baseline poll saw no HighOrders5xx; it fired only after the 500.
const hi = aw.matched.find((m) => m.alertname === "HighOrders5xx");
const httpAt = w.evidence.find((e) => e.id === steps[iHttp].l.evidence_ids[0]).createdAt;
const wdoc = JSON.parse(readFileSync(join(dirname(process.argv[2]), w.evidence.find((e) => e.id === aw.evidenceId).path), "utf8"));
if (!(aw.start < httpAt)) fail(`watch did not start before the action (${aw.start} vs ${httpAt})`);
if (wdoc.polls[0].firing.includes("HighOrders5xx")) fail("HighOrders5xx already firing in the baseline poll");
if (!(hi.activeAt > aw.start && hi.firstSeenAt > aw.start && hi.firstSeenAt >= hi.activeAt.slice(0, 19))) fail(`alert not shown firing after the action (activeAt ${hi.activeAt}, first seen ${hi.firstSeenAt}, watch start ${aw.start})`);
if (!new RegExp(`data-alert="HighOrders5xx" data-first-seen="${hi.firstSeenAt}"`).test(first)) fail("first-seen time not on the first screen");
if (aw.outcome !== "stopped_early" || aw.finalizedBy !== "collect") fail(`unexpected watch outcome ${aw.outcome}/${aw.finalizedBy}`);
if (!/class="corroborating"[^>]*><b>同时观测到的信号[\s\S]*?class="alert-confirm" data-alert="HighOrders5xx"/.test(first)) fail("first screen does not show the firing alert on the 500 finding");
if (!/class="unmatched-alerts" data-unmatched="1"[\s\S]*DiskAlmostFull/.test(first)) fail("first screen does not list the unmatched alert");
const iSrc = steps.findIndex((s) => s.l.source_ref && s.e.some((e) => e.executedBy === "core"));
if ([iHttp, iTrace, iDoc, iSrc].some((i) => i < 0)) fail(`chain incomplete http=${iHttp} langfuse=${iTrace} mongo=${iDoc} src=${iSrc}`);
if (!(iHttp < iTrace && iTrace < iDoc && iDoc < iSrc)) fail("chain steps out of order");
const t = steps[iTrace].e.find((e) => e.mcpCall), d = steps[iDoc].e.find((e) => e.mcpCall);
if (!t.links?.some((l) => steps[iHttp].e.some((e) => e.id === l.evidenceId))) fail("langfuse evidence not linked to the HTTP evidence");
if (!d.links?.some((l) => l.evidenceId === t.id)) fail("mongo evidence not linked to the langfuse evidence");
const src = w.sources.find((s) => s.id === steps[iSrc].l.source_ref);
if (!/pricing\.js$/.test(src.file)) fail(`root cause not in pricing.js: ${src.file}`);
console.log(`asserted cross-source chain (+ corroborating alert HighOrders5xx fired after the action): HTTP 500 → prometheus 5xx ratio → langfuse.${t.mcpCall.tool} → mongodb.${d.mcpCall.tool} → ${src.file}:${src.line}`);
