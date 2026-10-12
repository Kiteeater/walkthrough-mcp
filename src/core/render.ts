import type { Evidence } from "./types.js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WalkthroughCore } from "./walkthrough.js";
import { harSummary, parseHar } from "./har.js";
import { metricSummary } from "./metrics.js";
import { ALERTS_EVIDENCE } from "./alerts.js";

/** Zone for the static (no-JS) time text: explicit option, WALKTHROUGH_TZ, TZ, else the system zone. */
export function renderTimeZone(explicit?: string): string {
  for (const z of [explicit, process.env.WALKTHROUGH_TZ, process.env.TZ]) {
    if (!z) continue;
    try { new Intl.DateTimeFormat("en", { timeZone: z }); return z; } catch { /* invalid zone: try next */ }
  }
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}
export function fmtTime(d: Date, tz: string): string {
  const parts = new Intl.DateTimeFormat("sv-SE", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(d);
  return `${parts} (${tz})`;
}
const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** Render a static HTML walkthrough: one section per question. Returns the HTML path. */
const STATUS_ZH: Record<string, string> = { pass: "通过", fail: "失败", pass_needs_review: "需复核", inconclusive: "无结论" };
const OUTCOME_ZH: Record<string, string> = { completed: "窗口已走完", stopped_early: "提前收取", interrupted: "已中断" };

export function renderWalkthrough(core: WalkthroughCore, id: string, opts: { timeZone?: string } = {}): string {
  const w = core.load(id);
  const tz = renderTimeZone(opts.timeZone);
  /** No-JS fallback in the configured zone; the page script re-renders it in the viewer's zone. UTC ISO in the tooltip. */
  const t = (iso?: string) => {
    if (!iso) return "?";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return esc(iso);
    return `<time datetime="${esc(d.toISOString())}" title="${esc(d.toISOString())} (UTC)">${esc(fmtTime(d, tz))}</time>`;
  };
  const local = w.sandbox.backend === "local";
  const localBadge = local ? `<span class="badge local" title="本地运行，未隔离">本地运行、未隔离</span> ` : "";
  const count = (f: (c: (typeof w.claims)[number]) => boolean) => w.claims.filter(f).length;
  const summary = `<div class="summary" id="summary">
<span>直接观测：<b data-count="observed">${count((c) => c.kind === "observed")}</b></span>
<span>推断：<b data-count="inferred">${count((c) => c.kind === "inferred")}</b></span>
<span>已认可：<b data-count="agreed">${count((c) => c.review?.decision === "agree")}</b></span>
<span>已标记：<b data-count="flagged">${count((c) => c.review?.decision === "flag")}</b></span>
</div>`;
  const evidenceHtml = (ids: string[]) => ids.map((evId) => {
    const ev = w.evidence.find((e) => e.id === evId);
    if (!ev) return `<p class="missing">缺少证据 ${esc(evId)}</p>`;
    const meta = `<div class="meta">${esc(ev.id)} · ${esc(ev.kind ?? ev.type)} · ${ev.executedBy === "agent" ? '<span class="prov agent">agent 自报</span>' : '<span class="prov core">walkthrough 执行</span>'} · ${esc(ev.source)}${ev.mcpCall ? ` · <code class="mcpcall">${esc(ev.mcpCall.server)}.${esc(ev.mcpCall.tool)}(${esc(JSON.stringify(ev.mcpCall.params))})</code>` : ""}${ev.links?.length ? ` · linked ${esc(ev.links.map((l) => `${l.evidenceId} by "${l.key}"`).join(", "))}` : ""} · sha256 ${esc(ev.sha256.slice(0, 12))}… · ${t(ev.createdAt)}</div>`;
    const har = ev.type === "har" ? parseHar(core.readEvidenceText(w, ev)) : undefined;
    const alertDoc = ev.kind === "alert" ? (() => { try { const j = JSON.parse(core.readEvidenceText(w, ev)); return j.format === ALERTS_EVIDENCE ? j : undefined; } catch { return undefined; } })() : undefined;
    if (alertDoc) return `<figure data-type="alert" data-prov="core">${meta}<pre class="alert-summary">${esc(alertDoc.note)} · 窗口 ${t(alertDoc.window.start)} → ${t(alertDoc.window.end)}${esc(` · 轮询 ${Array.isArray(alertDoc.polls) ? alertDoc.polls.length : alertDoc.polls} 次`)}${(alertDoc.firing as { labels: Record<string, string>; annotations: Record<string, string> }[]).map((a) => esc(`\n🔔 ${a.labels.alertname ?? "?"} ${JSON.stringify(a.labels)} ${a.annotations.summary ?? ""}`)).join("")}</pre><details><summary>告警（已脱敏）</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details></figure>`;
    if (ev.kind === "blocked") { try { const j = JSON.parse(core.readEvidenceText(w, ev)); return `<figure data-type="blocked" data-prov="core">${meta}<table class="blocked-table" data-count="${Number(j.count)}"><tr><th>类型</th><th>请求（已脱敏）</th><th>原因</th></tr>${(j.blocked as { url: string; method: string; type: string; reason: string }[]).map((b) => `<tr><td>${esc(b.type)}</td><td><code>${esc(b.method)} ${esc(b.url)}</code></td><td>${esc(b.reason)}</td></tr>`).join("")}</table></figure>`; } catch { /* fall through */ } }
    const met = ev.kind === "metric" ? metricSummary(core.readEvidenceText(w, ev)) : undefined;
    const body = met ? `<pre class="metric-summary">${esc(met.query)} = ${esc(String(met.value ?? (met.ok ? "（无单一数值）" : "（查询失败）")))}</pre><details><summary>Prometheus 原始响应</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details>`
      : ev.type === "screenshot"
      ? `<details class="shot" open><summary>截图（仅供人工核对，不参与判定）</summary><a href="${esc(ev.path)}"><img src="${esc(ev.path)}" alt="${esc(ev.id)}"></a></details>`
      : har ? `<pre class="har-summary">${esc(harSummary(har))}</pre><details><summary>HAR（已脱敏）</summary><pre>${esc(core.readEvidenceText(w, ev).slice(0, 8000))}</pre></details>`
      : `<pre>${esc(core.readEvidenceText(w, ev).slice(-8000)) || "<em>（空）</em>"}</pre>`;
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
    if (!src) return step ? esc(step.claim) : "<em>根因未追到</em>";
    const code = core.sourceLine(src.file, src.line);
    return `<code class="loc">${esc(src.file)}:${src.line}</code> — ${esc(src.note ?? step?.claim ?? "")}${code ? `<div class="code"><code>${src.line} | ${esc(code)}</code></div>` : ""}`;
  };
  /** First-screen corroboration: core-executed Prometheus evidence cited by the finding. */
  const metricLine = (f: (typeof findings)[number]) => f.evidenceIds.map((e) => w.evidence.find((x) => x.id === e))
    .filter((e) => e && e.kind === "metric" && e.executedBy !== "agent")
    .map((e) => { const m = metricSummary(core.readEvidenceText(w, e!)); return m ? `<div class="metric-confirm" data-metric="${esc(e!.id)}">📈 指标佐证：<code>${esc(m.query)}</code> = <b>${esc(String(m.value ?? "?"))}</b> <span class="meta">（Prometheus，walkthrough 执行，${esc(e!.id)}）</span></div>` : ""; }).join("");
  const alertLine = (f: (typeof findings)[number]) => {
    const items = (w.alertWatches ?? []).flatMap((aw) => aw.matched.filter((m) => m.findingId === f.id).map((m) => {
      const also = m.checkIds.filter((c) => c !== f.checkId);
      return `<div class="alert-confirm" data-alert="${esc(m.alertname)}" data-first-seen="${esc(m.firstSeenAt ?? "")}">🔔 告警触发：<b>${esc(m.alertname)}</b> · 开始于 ${t(m.activeAt)} · walkthrough 首次看到 ${t(m.firstSeenAt)}${aw.outcome === "interrupted" ? ' <span class="chip interrupted">盯守中断</span>' : ""}${also.length ? ` <span class="also-matched" data-also="${esc(also.join(","))}">也匹配了 ${esc(also.join(", "))}</span>` : ""} <span class="meta">（Prometheus，walkthrough 执行，${esc(aw.evidenceId)}，关联 ${esc(m.checkIds.join(", "))}）</span></div>`;
    }));
    return items.length ? `<div class="corroborating" data-corroborating="${items.length}"><b>同时观测到的信号</b> <span class="meta">（佐证，不属于根因链）</span>${items.join("")}</div>` : "";
  };
  /** Hypotheses checked and excluded: shown next to the finding, outside the root-cause chain, with full sha256. */
  const ruledOutLine = (f: (typeof findings)[number]) => {
    const items = (f.ruled_out ?? []).map((r) => {
      const evs = r.evidence_ids.map((e) => w.evidence.find((x) => x.id === e)).filter(Boolean);
      const st = r.check_id ? results.find((x) => x.checkId === r.check_id)?.status : undefined;
      return `<div class="ruled-out-item"${r.check_id ? ` data-check="${esc(r.check_id)}"` : ""} data-evidence="${esc(evs.map((e) => e!.id).join(","))}">🚫 ${esc(r.claim)}${st ? ` <span class="meta">（检查 ${esc(r.check_id!)}：${esc(STATUS_ZH[st] ?? st)}）</span>` : ""}${evs.map((e) => `<div class="meta">${esc(e!.id)} · ${e!.executedBy === "agent" ? "agent 自报" : "walkthrough 执行"} · ${esc(e!.source)} · sha256 <code class="sha256" data-sha256="${esc(e!.sha256)}">${esc(e!.sha256)}</code></div>`).join("")}</div>`;
    });
    return items.length ? `<div class="ruled-out" data-ruled-out="${items.length}"><b>已排除</b> <span class="meta">（查过，不属于根因链）</span>${items.join("")}</div>` : "";
  };
  const watches = w.alertWatches ?? [];
  const unmatchedAlerts = watches.flatMap((aw) => aw.unmatched.map((u) => ({ ...u, ev: aw.evidenceId })));
  const outcomeTxt = (aw: (typeof watches)[number]) => aw.outcome === "interrupted" ? "⚠ 盯守中断（数据不完整，不代表窗口内无告警）" : aw.outcome === "stopped_early" ? "窗口结束前已收取" : "窗口已走完";
  const alertsBlock = watches.length ? `<div class="alerts-sum">${watches.map((aw) => `<div class="alert-window ${esc(aw.outcome)}" data-outcome="${esc(aw.outcome)}" data-firing="${aw.matched.length + aw.unmatched.length}">🔔 告警盯守 ${esc(aw.watchId)} ${t(aw.start)} → ${t(aw.end)} (${Array.isArray(aw.polls) ? aw.polls.length : aw.polls} 次轮询，${esc(aw.evidenceId)}, ${esc(outcomeTxt(aw))}${aw.finalizedBy === "sign_off" ? "，签核时自动结束" : ""}): ${aw.matched.length + aw.unmatched.length ? `已关联 ${aw.matched.length}，未关联 ${aw.unmatched.length}` : aw.errors?.length && aw.errors.length && aw.polls === 0 ? "无轮询" : aw.outcome === "interrupted" ? "中断前未见触发的告警" : aw.errors?.length ? `轮询出错：${esc(aw.errors.join("; "))}` : "窗口内无告警"}</div>`).join("")}
${unmatchedAlerts.length ? `<div class="unmatched-alerts" data-unmatched="${unmatchedAlerts.length}"><b>未关联的告警</b>（没有检查的匹配规则命中，未挂到任何问题上）：<ul>${unmatchedAlerts.map((u) => `<li><span class="chip ${esc(u.severity)}">${esc(u.severity)}</span> ${esc(u.alertname)} <code>${esc(JSON.stringify(u.labels))}</code> <span class="meta">${esc(u.ev)}</span></li>`).join("")}</ul></div>` : ""}</div>` : "";
  const autoFin = w.signoff?.autoFinalizedWatches ?? [];
  const autoFinNote = autoFin.length ? `<div class="auto-finalized" data-auto-finalized="${autoFin.length}">⚠ 签核时自动结束的告警盯守：${autoFin.map((a) => `<span class="aw ${esc(a.outcome)}" data-outcome="${esc(a.outcome)}">${esc(a.watchId)} (${a.outcome === "interrupted" ? "<b>已中断（interrupted）</b> — 数据不完整" : esc(OUTCOME_ZH[a.outcome] ?? a.outcome)})</span>`).join(", ")}</div>` : "";
  const sevRank = (x: string) => { const i = (SEV as readonly string[]).indexOf(x); return i < 0 ? 9 : i; };
  const ordered = [...findings].sort((x, y) => sevRank(x.severity) - sevRank(y.severity));
  const top = ordered[0];
  /** One sentence: what broke and where the root cause is. */
  const sentence = (f: (typeof findings)[number]) => {
    const target = (w.checks ?? []).find((c) => c.id === f.checkId)?.target ?? f.title;
    const path = /(?:https?:\/\/[^/\s]+)?(\/[^\s?#]*)/.exec(target)?.[1] ?? target;
    const status = /\b([45]\d\d)\b/.exec(`${f.symptom} ${f.title}`)?.[1];
    const src = srcOf(rootStep(f)?.source_ref);
    return `<code>${esc(path)}</code> ${status ? `返回 <b>${status}</b>` : esc(f.title)}${src ? `，根因在 <code class="loc">${esc(src.file.split("/").pop() ?? src.file)}:${src.line}</code>` : "，根因未追到"}`;
  };
  const provLabel = (p: string) => p === "core" ? '<span class="prov core">walkthrough 执行</span>' : p === "agent" ? '<span class="prov agent">agent 自报</span>' : '<span class="prov none">推断</span>';
  const firstChain = (f: (typeof findings)[number]) => `<ol class="rc-chain">${f.root_cause_chain.map((l) => {
    const evs = l.evidence_ids.map((e) => w.evidence.find((x) => x.id === e)).filter(Boolean);
    const prov = !evs.length ? "none" : evs.some((e) => e!.executedBy !== "agent") ? "core" : "agent";
    const src = srcOf(l.source_ref);
    return `<li class="rc-step" data-prov="${prov}">${provLabel(prov)} ${esc(l.claim)}${src ? ` → <code>${esc(src.file)}:${src.line}</code>` : ""}</li>`;
  }).join("")}</ol>`;
  const allChecks = w.checks ?? [];
  const statusOf = (cid: string) => results.find((r) => r.checkId === cid)?.status;
  const buckets: [string, string, (st?: string) => boolean][] = [
    ["pass", "通过", (st) => st === "pass"], ["fail", "失败", (st) => st === "fail"],
    ["needs-review", "需复核", (st) => st === "pass_needs_review"], ["none", "无结论", (st) => st !== "pass" && st !== "fail" && st !== "pass_needs_review"],
  ];
  const grouped = buckets.map(([key, label, f]) => ({ key, label, list: allChecks.filter((c) => f(statusOf(c.id))) }));
  // Failed checks sharing one root cause = ONE problem: a failed check belongs to finding f if it is f's check or its
  // result's evidence is part of f's evidence (the root-cause chain was built from it).
  const failedIds = allChecks.filter((c) => statusOf(c.id) === "fail").map((c) => c.id);
  const problems = ordered.map((f, i) => {
    const ev = new Set(f.evidenceIds);
    const ids = failedIds.filter((cid) => cid === f.checkId || (results.find((r) => r.checkId === cid)?.evidenceIds ?? []).some((e) => ev.has(e)));
    return { n: i + 1, f, checkIds: ids };
  });
  const claimed = new Set(problems.flatMap((p) => p.checkIds));
  const unattributed = failedIds.filter((cid) => !claimed.has(cid));
  const checkLi = (cid: string) => { const c = allChecks.find((x) => x.id === cid); const r = results.find((x) => x.checkId === cid); return `<li data-check="${esc(cid)}"${r?.reasons.length ? ` title="${esc(r.reasons.join("; "))}"` : ""}><code>${esc(cid)}</code> ${esc(c?.intent ?? "")} <span class="chip fail-chip">失败</span></li>`; };
  const problemHead = (p: (typeof problems)[number]) => `<h3 class="problem-title">问题 ${p.n} <span class="meta">（${p.checkIds.length} 项失败检查，同一根因）</span></h3>${p.checkIds.length ? `<ul class="problem-checks" data-checks="${p.checkIds.length}">${p.checkIds.map(checkLi).join("")}</ul>` : ""}`;
  const checkCounts = `<span class="check-counts" data-total="${allChecks.length}">检查 ${allChecks.length} 项：${grouped.map((g) => `<a class="cc cc-${g.key}" href="#checks-${g.key}" data-status="${g.key}" data-count="${g.list.length}"${g.key === "needs-review" ? ` data-needs-review="${g.list.length}"` : ""} onclick="var d=document.getElementById('checks-${g.key}');if(d)d.open=true">${g.list.length} ${g.label}</a>`).join(" · ")}</span>`;
  const checkLists = grouped.map((g) => `<details class="check-bucket" id="checks-${g.key}" data-status="${g.key}"><summary>${g.label}（${g.list.length}）</summary>${g.list.length ? `<ul>${g.list.map((c) => { const r = results.find((x) => x.checkId === c.id); return `<li data-check="${esc(c.id)}"><code>${esc(c.id)}</code> ${esc(c.intent)}${r?.reasons.length ? ` <span class="meta">— ${esc(r.reasons.join("; "))}</span>` : ""}</li>`; }).join("")}</ul>` : "<p class=\"meta\">无</p>"}</details>`).join("");
  const execRuns = w.runs.filter((r) => r.via);
  const execWarn = w.sandbox.allowExec ? `<div class="exec-enabled" data-exec-runs="${execRuns.length}">⚠ 沙箱任意命令已开启（sandbox.allowExec: true）：run_in_sandbox exec 可执行任意命令，结论可信度需人工核对。已执行 ${execRuns.length} 次${execRuns.length ? `：<ul>${execRuns.map((r) => `<li><code>${esc(r.command)}</code> → exit ${r.exitCode}${r.via === "run_cli" ? "（已转交 run_cli 白名单）" : ""} <span class="meta">${esc(r.id)} · ${t(r.createdAt)}</span></li>`).join("")}</ul>` : ""}</div>` : "";
  const blockedEvs = w.evidence.filter((e) => e.kind === "blocked");
  const blockedTable = (e: Evidence) => { try { const j = JSON.parse(core.readEvidenceText(w, e)); return `<table class="blocked-table" data-ev="${esc(e.id)}" data-count="${Number(j.count)}"><tr><th>类型</th><th>请求</th><th>原因</th></tr>${(j.blocked as { url: string; method: string; type: string; reason: string }[]).map((b) => `<tr><td>${esc(b.type)}</td><td><code>${esc(b.method)} ${esc(b.url)}</code></td><td>${esc(b.reason)}</td></tr>`).join("")}</table>`; } catch { return ""; } };
  const blockedTotal = blockedEvs.reduce((n, e) => { try { return n + Number(JSON.parse(core.readEvidenceText(w, e)).count ?? 0); } catch { return n; } }, 0);
  const blockedLine = blockedEvs.length ? `<div class="blocked-requests" data-blocked="${blockedTotal}">🛡 capture_page 已拦截 <b>${blockedTotal}</b> 个请求（不在白名单或 IP 规则不允许，均未发出）<details><summary>查看被拦截的请求（URL 已脱敏）</summary>${blockedEvs.map(blockedTable).join("")}</details></div>` : "";
  const verdict = `<section class="verdict" id="verdict">
${execWarn}
<div class="headline" data-findings="${findings.length}">${top
    ? `发现 <b>${findings.length}</b> 个问题：${sentence(top)}`
    : "未发现问题"}</div>
${top && failedIds.length ? `<div class="headline-sub" data-failed="${failedIds.length}" data-problems="${findings.length}">${failedIds.length} 项检查失败，归为 ${findings.length} 个问题${unattributed.length ? `（另有 ${unattributed.length} 项失败未归入问题）` : ""}</div>` : ""}
<div class="sev">${SEV.map((s) => `<span class="chip ${s}" data-sev="${s}">${s} ${sevCount(s)}</span>`).join("")}
${checkCounts}</div>
${blockedLine}
${top ? `<div class="top-finding problem" data-problem="1" data-finding="${esc(top.id)}" data-checks="${problems[0].checkIds.length}">${problemHead(problems[0])}<h4>根因链 <span class="meta">（${esc(top.title)}）</span></h4>
${firstChain(top)}
<div class="rc">根因：${rootCauseLine(top)}</div>${metricLine(top)}${alertLine(top)}${ruledOutLine(top)}</div>` : ""}
${ordered.length > 1 ? `<details class="other-findings"><summary>其余 ${ordered.length - 1} 个问题</summary><ol class="finding-list">${ordered.slice(1).map((f, i) => `<li class="problem" data-problem="${i + 2}" data-finding="${esc(f.id)}" data-checks="${problems[i + 1].checkIds.length}">${problemHead(problems[i + 1])}<span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> ${sentence(f)} <div class="rc">根因：${rootCauseLine(f)}</div>${metricLine(f)}${alertLine(f)}${ruledOutLine(f)}<a href="#${esc(f.id)}">证据链 ▸</a></li>`).join("\n")}</ol></details>` : ""}
${unattributed.length ? `<details class="unattributed" data-unattributed="${unattributed.length}"><summary>未归入任何问题的失败检查（${unattributed.length}）</summary><ul>${unattributed.map(checkLi).join("")}</ul></details>` : ""}
${alertsBlock ? `<details class="alerts-more"><summary>告警盯守详情</summary>${alertsBlock}</details>` : ""}
${w.goal ? `<p class="goal meta">目标：${esc(w.goal)}</p>` : ""}
<div class="signoff" data-prior="${esc(w.signoff?.decision ?? "")}">
${w.sandbox.allowExec ? `<div class="exec-enabled signoff-warn">⚠ 沙箱任意命令已开启 — 签核前请核对上面列出的 ${execRuns.length} 条命令</div>` : ""}
<b>签核：</b>
<label><input type="radio" name="signoff" value="accept"${w.signoff?.decision === "accept" ? " checked" : ""}> 认可</label>
<label><input type="radio" name="signoff" value="reject"${w.signoff?.decision === "reject" ? " checked" : ""}> 打回</label>
<textarea id="signoff-comment" placeholder="意见">${esc(w.signoff?.comment ?? "")}</textarea>
<button id="export">导出 review.json</button>
${autoFinNote}
${w.signoff ? `<div class="signed ${esc(w.signoff.decision)}">已签核：<b>${w.signoff.decision === "accept" ? "认可" : "打回"}</b>${w.signoff.comment ? ` — ${esc(w.signoff.comment)}` : ""}</div>` : ""}
</div>
<div class="check-lists">${checkLists}</div>
</section>`;
  const findingDetails = findings.map((f) => {
    const steps = f.root_cause_chain.map((l, i) => {
      const src = srcOf(l.source_ref);
      const evs = l.evidence_ids.map((e) => w.evidence.find((x) => x.id === e)).filter(Boolean);
      const prov = !evs.length ? "none" : evs.some((e) => e!.executedBy !== "agent") ? "core" : "agent";
      const provTag = prov === "agent" ? '<span class="prov agent" title="只有 agent 自报的证据">agent 自报（可信度较低）</span> '
        : prov === "core" ? '<span class="prov core" title="walkthrough 亲自执行得到的证据">walkthrough 执行</span> ' : "";
      return `<li class="step prov-${prov}" data-prov="${prov}">${provTag}<span class="badge ${esc(l.kind)}">${esc(l.kind)}</span> ${esc(l.claim)}${src ? ` → <code>${esc(src.file)}:${src.line}</code>` : ""}${l.evidence_ids.length ? ` <span class="meta">[${esc(l.evidence_ids.join(", "))}]</span>` : ""}${i < f.root_cause_chain.length - 1 ? " ↓" : ""}</li>`;
    }).join("");
    return `<details class="finding" id="${esc(f.id)}"><summary><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)}${f.checkId ? ' <span class="meta">（来自 ' + esc(f.checkId) + "）</span>" : ""}</summary>
<p><b>现象：</b> ${esc(f.symptom)}</p>
${f.repro_steps.length ? `<p><b>复现：</b></p><ol>${f.repro_steps.map((r) => `<li><code>${esc(r)}</code></li>`).join("")}</ol>` : ""}
<p><b>根因链：</b></p><ol class="chain">${steps}</ol>
<p><b>证据：</b></p>${f.evidenceIds.some((e) => w.evidence.find((x) => x.id === e)?.type === "screenshot") ? `<div class="evgrid ui-pair">${evidenceHtml(f.evidenceIds)}</div>` : evidenceHtml(f.evidenceIds)}
</details>`;
  }).join("\n");
  const row = (c: NonNullable<typeof w.checks>[number]) => {
    const r = results.find((x) => x.checkId === c.id);
    return `<tr class="${esc(r?.status ?? "notrun")}"><td>${esc(c.id)} ${esc(c.intent)}<div class="meta">${esc(c.method)}: ${esc(c.target)}${c.appended ? ` · 追查中追加，触发证据 ${esc(c.appended.triggeringEvidenceId)} (log #${c.appended.logSeq}, ${t(c.appended.at)})` : ""}</div></td><td><code>${esc(JSON.stringify(c.expect))}</code></td><td>${esc(r ? `${STATUS_ZH[r.status] ?? r.status}（${r.status}）` : "未执行")}${r?.reasons.length ? `: ${esc(r.reasons.join("; "))}` : ""}</td><td>${esc((r?.evidenceIds ?? []).join(", "))}</td></tr>`;
  };
  const head = "<tr><th>检查</th><th>期望（由 walkthrough 判定）</th><th>结果</th><th>证据</th></tr>";
  const original = (w.checks ?? []).filter((c) => !c.appended), appended = (w.checks ?? []).filter((c) => c.appended);
  const checksTable = (w.checks ?? []).length ? `<details class="checks"><summary>检查明细（${results.length}）</summary>
<h3>原始计划（${original.length})</h3><table class="plan-original">${head}${original.map(row).join("")}</table>
${appended.length ? `<h3 class="appended">追查中追加（${appended.length})</h3><table class="plan-appended" data-appended="${appended.length}">${head}${appended.map(row).join("")}</table>` : ""}</details>` : "";

  const sections = w.claims.map((c, i) => {
    const evidence = evidenceHtml(c.evidenceIds);
    const sources = c.sourceIds.map((sid) => {
      const s = w.sources.find((x) => x.id === sid);
      return s ? `<li><code>${esc(s.file)}:${s.line}</code>${s.note ? ` — ${esc(s.note)}` : ""}</li>` : "";
    }).join("");
    const review = c.review
      ? `<div class="review ${esc(c.review.decision)}">复核：<strong>${esc(c.review.decision)}</strong>${c.review.note ? ` — <span class="review-note">${esc(c.review.note)}</span>` : ""}</div>`
      : `<div class="review none">复核：<em>待复核</em></div>`;
    const prior = c.review ? ` data-prior="${esc(c.review.decision)}"` : "";
    return `<section class="claim" id="${esc(c.id)}" data-claim="${esc(c.id)}"${prior}>
<h2>Q${i + 1}. ${esc(c.question)}</h2>
<p>${localBadge}<span class="badge ${esc(c.kind)}">${esc(c.kind)}</span> ${esc(c.conclusion)}</p>
${sources ? `<ul class="sources">${sources}</ul>` : ""}
${review}
${evidence || `<p class="none">未附证据（推断）。</p>`}
<div class="actions"><button data-d="agree">认可</button><button data-d="flag">标记</button>
<input class="note" placeholder="备注（可选）" value="${esc(c.review?.note ?? "")}"><span class="state"></span></div>
</section>`;
  }).join("\n");

  const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>${esc(w.title)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#222}
.claim{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1.5rem 0}
.badge{padding:2px 8px;border-radius:10px;font-size:.8rem;color:#fff}
.badge.local{background:#cf222e}.badge.observed{background:#1a7f37}.badge.inferred{background:#9a6700}
img{max-width:100%;border:1px solid #ccc}pre{background:#f6f8fa;padding:.5rem;overflow:auto;max-height:300px}
.meta{font-size:.75rem;color:#666}.summary{display:flex;gap:1.5rem;background:#f6f8fa;padding:.75rem 1rem;border-radius:8px}
.review{margin:.5rem 0;padding:.4rem .6rem;border-left:4px solid #999}.review.agree{border-color:#1a7f37}.review.flag{border-color:#cf222e;background:#fff5f5}
.state{margin-left:.5rem;font-weight:bold}
.verdict{border:2px solid #222;border-radius:10px;padding:1rem 1.25rem}.headline{font-size:1.6rem}.headline-sub{font-size:.95rem;color:#555;margin-top:.2rem}.problem-title{margin:.6rem 0 .2rem}.problem-checks{margin:.2rem 0 .6rem;font-size:.92rem}.problem-checks li{margin:.1rem 0}.fail-chip{background:#cf222e;color:#fff;font-size:.75rem;padding:0 .4rem}.headline-sub{font-weight:600;color:#cf222e}
.chip{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.85rem;margin-right:.4rem;background:#eee;color:#222}
.chip.critical{background:#82071e;color:#fff}.chip.high{background:#cf222e;color:#fff}.chip.medium{background:#bf8700;color:#fff}.chip.low{background:#57606a;color:#fff}
.sev{margin:.5rem 0}.check-counts{color:#555;margin-left:.5rem}.cc{margin:0 .15rem}.cc-fail{color:#cf222e}.cc-needs-review{color:#7a4d00}.check-bucket{margin:.4rem 0;padding:.3rem .8rem}.finding-list li{margin:.6rem 0}.rc{margin:.2rem 0}.loc{background:#fff8c5;padding:1px 4px}
.code code{display:block;background:#f6f8fa;padding:.3rem .5rem;margin-top:.2rem;white-space:pre-wrap}
.signoff{margin-top:1rem;padding-top:.75rem;border-top:1px solid #ddd}.signoff textarea{width:100%;height:3rem;margin:.4rem 0}
details{border:1px solid #ddd;border-radius:8px;padding:.5rem 1rem;margin:1rem 0}summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid #ddd;padding:4px}tr.fail td{background:#fff5f5}tr.inconclusive td{background:#fff8e1}tr.pass_needs_review td{background:#fff3cd}
.prov{padding:1px 6px;border-radius:8px;font-size:.75rem}.prov.agent{background:#fff3cd;color:#7a4d00;border:1px dashed #d4a72c}.prov.core{background:#dafbe1;color:#116329;border:1px solid #1a7f37}
li.step.prov-agent{border-left:4px dashed #d4a72c;padding-left:6px}li.step.prov-core{border-left:4px solid #1a7f37;padding-left:6px}.chip.needs-review{background:#fff3cd;color:#7a4d00}.mcpcall{font-size:.75rem}
.chip.interrupted,.alert-window.interrupted{background:#82071e;color:#fff;padding:2px 6px}.auto-finalized{background:#fff8c5;border:1px solid #d4a72c;padding:.3rem .5rem;margin:.4rem 0}.aw.interrupted{color:#82071e}
.ruled-out{border-left:4px solid #57606a;background:#f6f8fa;padding:.3rem .6rem;margin:.4rem 0}.ruled-out code.sha256{font-size:.75em;word-break:break-all}
.corroborating{border-left:4px dashed #8250df;background:#fbefff;padding:.3rem .6rem;margin:.4rem 0}.also-matched{color:#8250df;font-style:italic}
.alert-confirm{margin:.2rem 0;padding:.2rem .5rem;background:#ffebe9;border-left:4px solid #cf222e}.unmatched-alerts{background:#fff8c5;padding:.4rem .6rem;margin:.4rem 0}.alert-window{font-size:.85rem;color:#444}
.rc-chain{margin:.3rem 0 .3rem 1.2rem;padding:0}.rc-step{margin:.25rem 0}.prov.none{background:#eee;color:#555}.top-finding h3{margin:.6rem 0 .2rem;font-size:1.05rem}.headline code{font-size:1.4rem}
.metric-confirm{margin:.2rem 0;padding:.2rem .5rem;background:#ddf4ff;border-left:4px solid #0969da}
.evgrid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}.evgrid figure{margin:0;min-width:0}
.exec-enabled{background:#cf222e;color:#fff;padding:.5rem .8rem;border-radius:6px;margin:.4rem 0;font-weight:600}.exec-enabled code{background:#fff;color:#82071e}
.blocked-requests{background:#fff8c5;border-left:4px solid #bf8700;padding:.25rem .6rem;margin:.3rem 0}
</style></head><body>
<h1>${esc(w.title)}</h1>
${local ? `<p>${localBadge}命令以宿主机子进程运行，没有隔离。</p>` : ""}
<p class="meta">walkthrough ${esc(w.id)}</p>
${verdict}
${findingDetails ? `<h2>问题详情（证据链）</h2>\n${findingDetails}` : ""}
${checksTable}
<details class="claims"><summary>逐条结论复核（可选，${w.claims.length} 条）</summary>
${summary}
${sections}
</details>
<script>
document.querySelectorAll("time[datetime]").forEach(function(el){var d=new Date(el.getAttribute("datetime"));if(!isNaN(d))el.textContent=d.toLocaleString(undefined,{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false,timeZoneName:"short"});});
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
