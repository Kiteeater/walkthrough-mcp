import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WalkthroughCore } from "./walkthrough.js";

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
    const meta = `<div class="meta">${esc(ev.id)} · ${esc(ev.type)} · ${esc(ev.source)} · sha256 ${esc(ev.sha256.slice(0, 12))}… · ${esc(ev.createdAt)}</div>`;
    const body = ev.type === "screenshot"
      ? `<img src="${esc(ev.path)}" alt="${esc(ev.id)}">`
      : `<pre>${esc(core.readEvidenceText(w, ev).slice(-8000)) || "<em>(empty)</em>"}</pre>`;
    return `<figure>${meta}${body}</figure>`;
  }).join("\n");
  const srcOf = (sid?: string) => (sid ? w.sources.find((x) => x.id === sid) : undefined);

  // ---- audit view: conclusions first ----
  const findings = w.findings ?? [];
  const results = w.checkResults ?? [];
  const SEV = ["critical", "high", "medium", "low"] as const;
  const sevCount = (s: string) => findings.filter((f) => f.severity === s).length;
  const rootCauseLine = (f: (typeof findings)[number]) => {
    const src = srcOf(f.rootCause?.sourceId);
    if (!src) return f.rootCause?.summary ? esc(f.rootCause.summary) : "<em>root cause not traced</em>";
    const code = core.sourceLine(src.file, src.line);
    return `<code class="loc">${esc(src.file)}:${src.line}</code> — ${esc(f.rootCause?.summary ?? src.note ?? "")}${code ? `<div class="code"><code>${src.line} | ${esc(code)}</code></div>` : ""}`;
  };
  const passed = results.filter((r) => r.status === "pass").length;
  const verdict = `<section class="verdict" id="verdict">
<div class="headline" data-findings="${findings.length}">${findings.length
    ? `发现 <b>${findings.length}</b> 个问题 · ${findings.length} finding${findings.length > 1 ? "s" : ""}`
    : "未发现问题 · no findings"}</div>
<div class="sev">${SEV.map((s) => `<span class="chip ${s}" data-sev="${s}">${s} ${sevCount(s)}</span>`).join("")}
<span class="checks-sum">checks: ${passed}/${results.length} passed</span></div>
${w.goal ? `<p class="goal">Goal: ${esc(w.goal)}</p>` : ""}
<ol class="finding-list">${findings.map((f) => `<li data-finding="${esc(f.id)}"><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> <span class="badge ${esc(f.kind)}">${esc(f.kind)}</span> <b>${esc(f.title)}</b>
<div class="rc">Root cause: ${rootCauseLine(f)}</div><a href="#${esc(f.id)}" onclick="document.getElementById('${esc(f.id)}').open=true">evidence chain ▸</a></li>`).join("\n")}</ol>
<div class="signoff" data-prior="${esc(w.signoff?.decision ?? "")}">
<b>报告签核 Sign-off:</b>
<label><input type="radio" name="signoff" value="approve"${w.signoff?.decision === "approve" ? " checked" : ""}> 认可</label>
<label><input type="radio" name="signoff" value="reject"${w.signoff?.decision === "reject" ? " checked" : ""}> 打回</label>
<textarea id="signoff-comment" placeholder="comment">${esc(w.signoff?.comment ?? "")}</textarea>
<button id="export">Export review.json</button>
${w.signoff ? `<div class="signed ${esc(w.signoff.decision)}">Signed: <b>${w.signoff.decision === "approve" ? "认可" : "打回"}</b>${w.signoff.comment ? ` — ${esc(w.signoff.comment)}` : ""}</div>` : ""}
</div>
</section>`;
  const findingDetails = findings.map((f) => {
    const src = srcOf(f.rootCause?.sourceId);
    const chain = [...new Set([...(f.rootCause?.logEvidenceId ? [f.rootCause.logEvidenceId] : []), ...f.evidenceIds])];
    return `<details class="finding" id="${esc(f.id)}"><summary><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)}${f.draft ? ' <span class="meta">(auto-drafted from ' + esc(f.checkId ?? "check") + ")</span>" : ""}</summary>
<p><b>What happened:</b> ${esc(f.whatHappened)}</p>
${f.repro.length ? `<p><b>Repro:</b></p><ol>${f.repro.map((r) => `<li><code>${esc(r)}</code></li>`).join("")}</ol>` : ""}
<p><b>Root cause trace:</b> ${f.rootCause?.logEvidenceId ? `stack trace in ${esc(f.rootCause.logEvidenceId)}` : "no log evidence"}${src ? ` → <code>${esc(src.file)}:${src.line}</code> (${esc(src.id)})` : ""}</p>
<p><b>Evidence chain:</b></p>${evidenceHtml(chain)}
</details>`;
  }).join("\n");
  const checksTable = (w.checks ?? []).length ? `<details class="checks"><summary>Checks the agent ran (${results.length})</summary>
<table><tr><th>check</th><th>expected</th><th>result</th><th>evidence</th></tr>${(w.checks ?? []).map((c) => {
    const r = results.find((x) => x.checkId === c.id);
    return `<tr class="${esc(r?.status ?? "notrun")}"><td>${esc(c.id)} ${esc(c.name)}</td><td><code>${esc(JSON.stringify(c.expect))}</code></td><td>${esc(r?.status ?? "not run")}${r?.reasons.length ? `: ${esc(r.reasons.join("; "))}` : ""}</td><td>${esc((r?.evidenceIds ?? []).join(", "))}</td></tr>`;
  }).join("")}</table></details>` : "";

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
table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid #ddd;padding:4px}tr.fail td{background:#fff5f5}
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
