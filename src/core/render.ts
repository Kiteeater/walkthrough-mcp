import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WalkthroughCore } from "./walkthrough.js";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** Render a static HTML walkthrough: one section per question. Returns the HTML path. */
export function renderWalkthrough(core: WalkthroughCore, id: string): string {
  const w = core.load(id);
  const sections = w.claims.map((c, i) => {
    const evidence = c.evidenceIds.map((evId) => {
      const ev = w.evidence.find((e) => e.id === evId);
      if (!ev) return `<p class="missing">missing evidence ${esc(evId)}</p>`;
      const meta = `<div class="meta">${esc(ev.id)} · ${esc(ev.type)} · ${esc(ev.source)} · sha256 ${esc(ev.sha256.slice(0, 12))}… · ${esc(ev.createdAt)}</div>`;
      const body = ev.type === "screenshot"
        ? `<img src="${esc(ev.path)}" alt="${esc(ev.id)}">`
        : `<pre>${esc(core.readEvidenceText(w, ev).slice(-8000))}</pre>`;
      return `<figure>${meta}${body}</figure>`;
    }).join("\n");
    const sources = c.sourceIds.map((sid) => {
      const s = w.sources.find((x) => x.id === sid);
      return s ? `<li><code>${esc(s.file)}:${s.line}</code>${s.note ? ` — ${esc(s.note)}` : ""}</li>` : "";
    }).join("");
    const prior = c.review ? ` data-prior="${esc(c.review.decision)}"` : "";
    return `<section class="claim" id="${esc(c.id)}" data-claim="${esc(c.id)}"${prior}>
<h2>Q${i + 1}. ${esc(c.question)}</h2>
<p><span class="badge ${esc(c.kind)}">${esc(c.kind)}</span> ${esc(c.conclusion)}</p>
${sources ? `<ul class="sources">${sources}</ul>` : ""}
${evidence || `<p class="none">No evidence attached (inferred).</p>`}
<div class="actions"><button data-d="agree">Agree</button><button data-d="flag">Flag</button>
<input class="note" placeholder="note (optional)"><span class="state"></span></div>
</section>`;
  }).join("\n");

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(w.title)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#222}
.claim{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1.5rem 0}
.badge{padding:2px 8px;border-radius:10px;font-size:.8rem;color:#fff}
.badge.observed{background:#1a7f37}.badge.inferred{background:#9a6700}
img{max-width:100%;border:1px solid #ccc}pre{background:#f6f8fa;padding:.5rem;overflow:auto;max-height:300px}
.meta{font-size:.75rem;color:#666}.state{margin-left:.5rem;font-weight:bold}
</style></head><body>
<h1>${esc(w.title)}</h1>
<p class="meta">walkthrough ${esc(w.id)} · ${w.claims.length} questions · ${w.evidence.length} evidence items</p>
${sections}
<button id="export">Export review.json</button>
<script>
const WID=${JSON.stringify(w.id)};const decisions={};
document.querySelectorAll(".claim").forEach(s=>{
  const st=s.querySelector(".state");if(s.dataset.prior){decisions[s.dataset.claim]=s.dataset.prior;st.textContent=s.dataset.prior;}
  s.querySelectorAll("button[data-d]").forEach(b=>b.onclick=()=>{decisions[s.dataset.claim]=b.dataset.d;st.textContent=b.dataset.d;});
});
document.getElementById("export").onclick=()=>{
  const out={walkthroughId:WID,decisions:Object.entries(decisions).map(([claimId,decision])=>{
    const note=document.querySelector('[data-claim="'+claimId+'"] .note').value;return note?{claimId,decision,note}:{claimId,decision};})};
  const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(out,null,2)],{type:"application/json"}));
  a.download="review.json";a.click();
};
</script></body></html>
`;
  const out = join(core.dir(id), "index.html");
  writeFileSync(out, core.redact(html));
  return out;
}
