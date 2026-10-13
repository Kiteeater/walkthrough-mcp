/**
 * Judging `aliyun sls GetLogsV2` output for "no matching logs" (used to rule a hypothesis out).
 * GetLogsV2 (SLS OpenAPI 2020-12-30) returns `{ meta: { progress, … }, data: [ … ] }`; meta.progress is
 * "Complete" (the result is complete) or "Incomplete" (must be re-requested to get the full result).
 * Only `exit 0` + progress === "Complete" + `data: []` counts as "none found" (pass); matches → fail. Anything else
 * (non-zero exit, unparsable output, progress Incomplete / missing / unrecognised, data not an array) → inconclusive:
 * an empty page from an incomplete query proves nothing and must never become an exclusion.
 */
import type { Verdict } from "./types.js";

export const SLS_PROGRESS_COMPLETE = "Complete";
const KNOWN_PROGRESS = ["Complete", "Incomplete"];

export function judgeSlsEmpty(texts: string[]): { status: Verdict; reasons: string[] } {
  if (!texts.length) return { status: "inconclusive", reasons: ["没有 SLS 查询证据"] };
  const out = texts.map(judgeOne);
  const bad = out.filter((o) => o.status === "inconclusive");
  if (bad.length) return { status: "inconclusive", reasons: bad.flatMap((o) => o.reasons) };
  const hit = out.filter((o) => o.status === "fail");
  return hit.length ? { status: "fail", reasons: hit.flatMap((o) => o.reasons) } : { status: "pass", reasons: [] };
}

function judgeOne(text: string): { status: Verdict; reasons: string[] } {
  // run_cli evidence: "$ aliyun [...]\nexit <code>\n\n<stdout+stderr>"
  const m = /^exit (-?\d+)\n\n([\s\S]*)$/m.exec(text);
  if (!m) return { status: "inconclusive", reasons: ["证据不是 run_cli 输出"] };
  if (m[1] !== "0") return { status: "inconclusive", reasons: [`SLS 查询失败，aliyun 退出码 ${m[1]}`] };
  let j: { meta?: { progress?: unknown }; data?: unknown };
  try { j = JSON.parse(m[2]); } catch { return { status: "inconclusive", reasons: ["SLS 输出不是 JSON（需要 GetLogsV2 的 {meta, data} 响应）"] }; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return { status: "inconclusive", reasons: ["SLS 响应不是 {meta, data} 对象（没有 progress，无法确认查询已完成）"] };
  const p = j.meta?.progress;
  if (p === undefined) return { status: "inconclusive", reasons: ["SLS 响应缺少 meta.progress，无法确认查询已完成"] };
  if (typeof p !== "string" || !KNOWN_PROGRESS.includes(p)) return { status: "inconclusive", reasons: [`SLS 返回无法识别的 progress=${typeof p === "string" ? p : JSON.stringify(p)}，无法确认查询已完成`] };
  if (p !== SLS_PROGRESS_COMPLETE) return { status: "inconclusive", reasons: [`SLS 查询未完成，progress=${p}`] };
  if (!Array.isArray(j.data)) return { status: "inconclusive", reasons: ["SLS 响应缺少 data 数组"] };
  return j.data.length ? { status: "fail", reasons: [`查到 ${j.data.length} 条匹配日志`] } : { status: "pass", reasons: [] };
}
