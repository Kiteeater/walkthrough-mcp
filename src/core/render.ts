import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WalkthroughCore } from "./walkthrough.js";
import { harSummary, parseHar } from "./har.js";
import { metricSummary } from "./metrics.js";
import { ALERTS_EVIDENCE } from "./alerts.js";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** Render a static HTML walkthrough: one section per question. Returns the HTML path. */
export function renderWalkthrough(core: WalkthroughCore, id: string): string {
  const w = core.load(id);
  const local = w.sandbox.backend === "local";
  const localBadge = local ? `<span class="badge local" title="local run, not isolated">本地运行、未隔离</span> ` : "";
  const count = (f: (c: (typeof w.claims)[number]) => boolean) => w.claims.filter(f).length;
  const summary = `<div class="summary" id="summary">
<span>observed: <b data-count="observed">${count((c) => c.kind === "observed")}</b></span>
<span>inferred: <b data-count="inferred">${count((c) => c.kind === "inferred")}</b></span>
<span>agreed: <b data-count="agreed">${count((c) => c.review?.decision === "agree")}</b></span>
<span>flagged: <b data-count="flagged">${count((c) => c.review?.decision === "flag")}</b></span>
</div>`;
  const evidenceHtml = (ids: string[]) => ids.map((evId) => {
    const ev = w.evidence.find((e) => e.id === evId);
    if (!ev) return `<p class="missing">missing evidence ${esc(evId)}</p>`;
    const meta = `<div class="meta">${esc(ev.id)} · ${esc(ev.kind ?? ev.type)} · ${ev.executedBy === "agent" ? '<span class="prov agent">reported by agent · agent 自报</span>' : '<span class="prov core">executed by walkthrough · 我们执行</span>'} · ${esc(ev.source)}${ev.mcpCall ? ` · <code class="mcpcall">${esc(ev.mcpCall.server)}.${esc(ev.mcpCall.tool)}(${esc(JSON.stringify(ev.mcpCall.params))})</code>` : ""}${ev.links?.length ? ` · linked ${esc(ev.links.map((l) => `${l.evidenceId} by "${l.key}"`).join(", "))}` : ""} · sha256 ${esc(ev.sha256.slice(0, 12))}… · ${esc(ev.createdAt)}</div>`;
    const har = ev.type === "har" ? parseHar(core.readEvidenceText(w, ev)) : undefined;
    const alertDoc = ev.kind === "alert" ? (() => { try { const j = JSON.parse(core.readEvidenceText(w, ev)); return j.format === ALERTS_EVIDENCE ? j : undefined; } catch { return undefined; } })() : undefined;
    if (alertDoc) return `<figure data-type="alert" data-prov="core">${meta}<pre class="alert-summary">${esc(`${alertDoc.note} · window ${alertDoc.window.start} → ${alertDoc.window.end} · ${alertDoc.polls} poll(s)`)}${(alertDoc.firing as { labels: Record<string, string>; annotations: Record<string, string> }[]).map((a) => esc(`\n🔔 ${a.labels.alertname ?? "?"} ${JSON.stringify(a.labels)} ${a.annotations.summary ?? ""}`)).join("")}</pre><details><summary>alerts (redacted)</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details></figure>`;
    const met = ev.kind === "metric" ? metricSummary(core.readEvidenceText(w, ev)) : undefined;
    const body = met ? `<pre class="metric-summary">${esc(met.query)} = ${esc(String(met.value ?? (met.ok ? "(no single value)" : "(query failed)")))}</pre><details><summary>Prometheus response</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details>`
      : ev.type === "screenshot"
      ? `<details class="shot" open><summary>screenshot (for human audit only · 仅供人工核对，不参与判定)</summary><a href="${esc(ev.path)}"><img src="${esc(ev.path)}" alt="${esc(ev.id)}"></a></details>`
      : har ? `<pre class="har-summary">${esc(harSummary(har))}</pre><details><summary>HAR (redacted)</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details>`
      : `<pre>${esc(core.readEvidenceText(w, ev).slice(-8000)) || "<em>(empty)</em>"}</pre>`;
    return `<figure data-type="${esc(ev.type)}" data-prov="${ev.executedBy === "agent" ? "agent" : "core"}">${meta}${body}</figure>`;
  }).join("\n");
  const srcOf = (sid?: string) => (sid ? w.sources.find((x) => x.id === sid) : undefined);

  // ---- audit view: conclusions first ----
  const findings = w.findings ?? [];
  const results = w.checkResults ?? [];
  const SEV = ["critical", "high", "medium", "low"] as const;
  const sevCount = (s: string) => findings.filter((f) => f.severity === s).length;
  /** Deepest chain step with a source ref (else the last step) is the root cause shown on the first screen. */
  const rootStep = (f: (typeof findings)[number]) => [...f.root_cause_chain].reverse().find((l) => l.source_ref) ?? f.root_cause_chain.at(-1);
  const rootCauseLine = (f: (typeof findings)[number]) => {
    const step = rootStep(f);
    const src = srcOf(step?.source_ref);
    if (!src) return step ? esc(step.claim) : "<em>root cause not traced</em>";
    const code = core.sourceLine(src.file, src.line);
    return `<code class="loc">${esc(src.file)}:${src.line}</code> — ${esc(src.note ?? step?.claim ?? "")}${code ? `<div class="code"><code>${src.line} | ${esc(code)}</code></div>` : ""}`;
  };
  /** First-screen corroboration: core-executed Prometheus evidence cited by the finding. */
  const metricLine = (f: (typeof findings)[number]) => f.evidenceIds.map((e) => w.evidence.find((x) => x.id === e))
    .filter((e) => e && e.kind === "metric" && e.executedBy !== "agent")
    .map((e) => { const m = metricSummary(core.readEvidenceText(w, e!)); return m ? `<div class="metric-confirm" data-metric="${esc(e!.id)}">📈 指标佐证 · metric confirms: <code>${esc(m.query)}</code> = <b>${esc(String(m.value ?? "?"))}</b> <span class="meta">(Prometheus, executed by walkthrough, ${esc(e!.id)})</span></div>` : ""; }).join("");
  const alertLine = (f: (typeof findings)[number]) => (w.alertWatches ?? []).flatMap((aw) => aw.matched.filter((m) => m.findingId === f.id).map((m) =>
    `<div class="alert-confirm" data-alert="${esc(m.alertname)}">🔔 告警 · alert firing: <b>${esc(m.alertname)}</b> <span class="meta">(Prometheus, executed by walkthrough, ${esc(aw.evidenceId)}, related to ${esc(m.checkIds.join(", "))})</span></div>`)).join("");
  const watches = w.alertWatches ?? [];
  const unmatchedAlerts = watches.flatMap((aw) => aw.unmatched.map((u) => ({ ...u, ev: aw.evidenceId })));
  const alertsBlock = watches.length ? `<div class="alerts-sum">${watches.map((aw) => `<div class="alert-window" data-firing="${aw.matched.length + aw.unmatched.length}">🔔 alert watch ${esc(aw.start)} → ${esc(aw.end)} (${aw.polls} poll(s), ${esc(aw.evidenceId)}): ${aw.matched.length + aw.unmatched.length ? `${aw.matched.length} attached, ${aw.unmatched.length} unmatched` : "no alerts in window · 窗口内无告警"}</div>`).join("")}
${unmatchedAlerts.length ? `<div class="unmatched-alerts" data-unmatched="${unmatchedAlerts.length}"><b>未关联的告警 Unmatched firing alerts</b> (no check's matchers matched; not attached to any finding):<ul>${unmatchedAlerts.map((u) => `<li><span class="chip ${esc(u.severity)}">${esc(u.severity)}</span> ${esc(u.alertname)} <code>${esc(JSON.stringify(u.labels))}</code> <span class="meta">${esc(u.ev)}</span></li>`).join("")}</ul></div>` : ""}</div>` : "";
  const passed = results.filter((r) => r.status === "pass").length;
  const needsReview = results.filter((r) => r.status === "pass_needs_review");
  const verdict = `<section class="verdict" id="verdict">
<div class="headline" data-findings="${findings.length}">${findings.length
    ? `发现 <b>${findings.length}</b> 个问题 · ${findings.length} finding${findings.length > 1 ? "s" : ""}`
    : "未发现问题 · no findings"}</div>
<div class="sev">${SEV.map((s) => `<span class="chip ${s}" data-sev="${s}">${s} ${sevCount(s)}</span>`).join("")}
<span class="checks-sum">checks: ${passed + needsReview.length}/${results.length} passed</span>${needsReview.length ? ` <span class="chip needs-review" data-needs-review="${needsReview.length}" title="passed only on agent-reported evidence">⚠ ${needsReview.length} pass needs review（仅 agent 自报证据）: ${esc(needsReview.map((r) => r.checkId).join(", "))}</span>` : ""}</div>
${w.goal ? `<p class="goal">Goal: ${esc(w.goal)}</p>` : ""}
${alertsBlock}
<ol class="finding-list">${findings.map((f) => `<li data-finding="${esc(f.id)}"><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> <span class="badge ${esc(f.kind)}">${esc(f.kind)}</span> <b>${esc(f.title)}</b>
<div class="rc">Root cause: ${rootCauseLine(f)}</div>${metricLine(f)}${alertLine(f)}<a href="#${esc(f.id)}" onclick="document.getElementById('${esc(f.id)}').open=true">evidence chain ▸</a></li>`).join("\n")}</ol>
<div class="signoff" data-prior="${esc(w.signoff?.decision ?? "")}">
<b>报告签核 Sign-off:</b>
<label><input type="radio" name="signoff" value="accept"${w.signoff?.decision === "accept" ? " checked" : ""}> 认可</label>
<label><input type="radio" name="signoff" value="reject"${w.signoff?.decision === "reject" ? " checked" : ""}> 打回</label>
<textarea id="signoff-comment" placeholder="comment">${esc(w.signoff?.comment ?? "")}</textarea>
<button id="export">Export review.json</button>
${w.signoff ? `<div class="signed ${esc(w.signoff.decision)}">Signed: <b>${w.signoff.decision === "accept" ? "认可" : "打回"}</b>${w.signoff.comment ? ` — ${esc(w.signoff.comment)}` : ""}</div>` : ""}
</div>
</section>`;
  const findingDetails = findings.map((f) => {
    const steps = f.root_cause_chain.map((l, i) => {
      const src = srcOf(l.source_ref);
      const evs = l.evidence_ids.map((e) => w.evidence.find((x) => x.id === e)).filter(Boolean);
      const prov = !evs.length ? "none" : evs.some((e) => e!.executedBy !== "agent") ? "core" : "agent";
      const provTag = prov === "agent" ? '<span class="prov agent" title="backed only by evidence the agent reported">agent 自报 · lower trust</span> '
        : prov === "core" ? '<span class="prov core" title="backed by evidence walkthrough executed itself">我们执行</span> ' : "";
      return `<li class="step prov-${prov}" data-prov="${prov}">${provTag}<span class="badge ${esc(l.kind)}">${esc(l.kind)}</span> ${esc(l.claim)}${src ? ` → <code>${esc(src.file)}:${src.line}</code>` : ""}${l.evidence_ids.length ? ` <span class="meta">[${esc(l.evidence_ids.join(", "))}]</span>` : ""}${i < f.root_cause_chain.length - 1 ? " ↓" : ""}</li>`;
    }).join("");
    return `<details class="finding" id="${esc(f.id)}"><summary><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)}${f.checkId ? ' <span class="meta">(from ' + esc(f.checkId) + ")</span>" : ""}</summary>
<p><b>Symptom:</b> ${esc(f.symptom)}</p>
${f.repro_steps.length ? `<p><b>Repro:</b></p><ol>${f.repro_steps.map((r) => `<li><code>${esc(r)}</code></li>`).join("")}</ol>` : ""}
<p><b>Root-cause chain:</b></p><ol class="chain">${steps}</ol>
<p><b>Evidence:</b></p>${f.evidenceIds.some((e) => w.evidence.find((x) => x.id === e)?.type === "screenshot") ? `<div class="evgrid ui-pair">${evidenceHtml(f.evidenceIds)}</div>` : evidenceHtml(f.evidenceIds)}
</details>`;
  }).join("\n");
  const row = (c: NonNullable<typeof w.checks>[number]) => {
    const r = results.find((x) => x.checkId === c.id);
    return `<tr class="${esc(r?.status ?? "notrun")}"><td>${esc(c.id)} ${esc(c.intent)}<div class="meta">${esc(c.method)}: ${esc(c.target)}${c.appended ? ` · 追查中追加 after ${esc(c.appended.triggeringEvidenceId)} (log #${c.appended.logSeq}, ${esc(c.appended.at)})` : ""}</div></td><td><code>${esc(JSON.stringify(c.expect))}</code></td><td>${esc(r?.status ?? "not run")}${r?.reasons.length ? `: ${esc(r.reasons.join("; "))}` : ""}</td><td>${esc((r?.evidenceIds ?? []).join(", "))}</td></tr>`;
  };
  const head = "<tr><th>check</th><th>expected (judged by core)</th><th>result</th><th>evidence</th></tr>";
  const original = (w.checks ?? []).filter((c) => !c.appended), appended = (w.checks ?? []).filter((c) => c.appended);
  const checksTable = (w.checks ?? []).length ? `<details class="checks"><summary>Checks the agent ran (${results.length})</summary>
<h3>原始计划 Original plan (${original.length})</h3><table class="plan-original">${head}${original.map(row).join("")}</table>
${appended.length ? `<h3 class="appended">追查中追加 Appended while tracing (${appended.length})</h3><table class="plan-appended" data-appended="${appended.length}">${head}${appended.map(row).join("")}</table>` : ""}</details>` : "";

  const sections = w.claims.map((c, i) => {
    const evidence = evidenceHtml(c.evidenceIds);
    const sources = c.sourceIds.map((sid) => {
      const s = w.sources.find((x) => x.id === sid);
      return s ? `<li><code>${esc(s.file)}:${s.line}</code>${s.note ? ` — ${esc(s.note)}` : ""}</li>` : "";
    }).join("");
    const review = c.review
      ? `<div class="review ${esc(c.review.decision)}">Review: <strong>${esc(c.review.decision)}</strong>${c.review.note ? ` — <span class="review-note">${esc(c.review.note)}</span>` : ""}</div>`
      : `<div class="review none">Review: <em>pending</em></div>`;
    const prior = c.review ? ` data-prior="${esc(c.review.decision)}"` : "";
    return `<section class="claim" id="${esc(c.id)}" data-claim="${esc(c.id)}"${prior}>
<h2>Q${i + 1}. ${esc(c.question)}</h2>
<p>${localBadge}<span class="badge ${esc(c.kind)}">${esc(c.kind)}</span> ${esc(c.conclusion)}</p>
${sources ? `<ul class="sources">${sources}</ul>` : ""}
${review}
${evidence || `<p class="none">No evidence attached (inferred).</p>`}
<div class="actions"><button data-d="agree">Agree</button><button data-d="flag">Flag</button>
<input class="note" placeholder="note (optional)" value="${esc(c.review?.note ?? "")}"><span class="state"></span></div>
</section>`;
  }).join("\n");

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(w.title)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#222}
.claim{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1.5rem 0}
.badge{padding:2px 8px;border-radius:10px;font-size:.8rem;color:#fff}
.badge.local{background:#cf222e}.badge.observed{background:#1a7f37}.badge.inferred{background:#9a6700}
img{max-width:100%;border:1px solid #ccc}pre{background:#f6f8fa;padding:.5rem;overflow:auto;max-height:300px}
.meta{font-size:.75rem;color:#666}.summary{display:flex;gap:1.5rem;background:#f6f8fa;padding:.75rem 1rem;border-radius:8px}
.review{margin:.5rem 0;padding:.4rem .6rem;border-left:4px solid #999}.review.agree{border-color:#1a7f37}.review.flag{border-color:#cf222e;background:#fff5f5}
.state{margin-left:.5rem;font-weight:bold}
.verdict{border:2px solid #222;border-radius:10px;padding:1rem 1.25rem}.headline{font-size:1.6rem}
.chip{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.85rem;margin-right:.4rem;background:#eee;color:#222}
.chip.critical{background:#82071e;color:#fff}.chip.high{background:#cf222e;color:#fff}.chip.medium{background:#bf8700;color:#fff}.chip.low{background:#57606a;color:#fff}
.sev{margin:.5rem 0}.checks-sum{color:#555;margin-left:.5rem}.finding-list li{margin:.6rem 0}.rc{margin:.2rem 0}.loc{background:#fff8c5;padding:1px 4px}
.code code{display:block;background:#f6f8fa;padding:.3rem .5rem;margin-top:.2rem;white-space:pre-wrap}
.signoff{margin-top:1rem;padding-top:.75rem;border-top:1px solid #ddd}.signoff textarea{width:100%;height:3rem;margin:.4rem 0}
details{border:1px solid #ddd;border-radius:8px;padding:.5rem 1rem;margin:1rem 0}summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid #ddd;padding:4px}tr.fail td{background:#fff5f5}tr.inconclusive td{background:#fff8e1}tr.pass_needs_review td{background:#fff3cd}
.prov{padding:1px 6px;border-radius:8px;font-size:.75rem}.prov.agent{background:#fff3cd;color:#7a4d00;border:1px dashed #d4a72c}.prov.core{background:#dafbe1;color:#116329;border:1px solid #1a7f37}
li.step.prov-agent{border-left:4px dashed #d4a72c;padding-left:6px}li.step.prov-core{border-left:4px solid #1a7f37;padding-left:6px}.chip.needs-review{background:#fff3cd;color:#7a4d00}.mcpcall{font-size:.75rem}
.alert-confirm{margin:.2rem 0;padding:.2rem .5rem;background:#ffebe9;border-left:4px solid #cf222e}.unmatched-alerts{background:#fff8c5;padding:.4rem .6rem;margin:.4rem 0}.alert-window{font-size:.85rem;color:#444}
.metric-confirm{margin:.2rem 0;padding:.2rem .5rem;background:#ddf4ff;border-left:4px solid #0969da}
.evgrid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}.evgrid figure{margin:0;min-width:0}
</style></head><body>
<h1>${esc(w.title)}</h1>
${local ? `<p>${localBadge}Commands ran as host child processes without isolation.</p>` : ""}
<p class="meta">walkthrough ${esc(w.id)} · ${findings.length} findings · ${results.length} checks · ${w.claims.length} claims · ${w.evidence.length} evidence items</p>
${verdict}
${findingDetails ? `<h2>Findings — evidence chain</h2>\n${findingDetails}` : ""}
${checksTable}
<details class="claims"><summary>Per-claim review (optional, ${w.claims.length} claims)</summary>
${summary}
${sections}
</details>
<script>
const WID=${JSON.stringify(w.id)};const decisions={};
document.querySelectorAll(".claim").forEach(s=>{
  const st=s.querySelector(".state");if(s.dataset.prior){decisions[s.dataset.claim]=s.dataset.prior;st.textContent=s.dataset.prior;}
  s.querySelectorAll("button[data-d]").forEach(b=>b.onclick=()=>{decisions[s.dataset.claim]=b.dataset.d;st.textContent=b.dataset.d;});
});
document.getElementById("export").onclick=()=>{
  const out={walkthroughId:WID,decisions:Object.entries(decisions).map(([claimId,decision])=>{
    const note=document.querySelector('[data-claim="'+claimId+'"] .note').value;return note?{claimId,decision,note}:{claimId,decision};})};
  const so=document.querySelector('input[name="signoff"]:checked');const comment=document.getElementById("signoff-comment").value;
  if(so)out.signoff=comment?{decision:so.value,comment}:{decision:so.value};
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(out,null,2)],{type:"application/json"}));
  a.download="review.json";a.click();
};
</script></body></html>
`;
  const out = join(core.dir(id), "index.html");
  writeFileSync(out, core.redact(html));
  return out;
}
