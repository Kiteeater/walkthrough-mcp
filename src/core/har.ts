// HAR page evidence: redaction, summary, and the `ui` expectation judge. Screenshots are NEVER judged (human audit only).
import { MASK, type Redactor } from "./redact.js";
import { scrub } from "./imports.js";

export interface HarEntry {
  request: { method: string; url: string; headers?: { name: string; value: string }[]; cookies?: { name: string; value: string }[]; queryString?: { name: string; value: string }[]; postData?: { text?: string; params?: { name: string; value?: string }[] } };
  response: { status: number; redirectURL?: string; headers?: { name: string; value: string }[]; cookies?: { name: string; value: string }[]; content?: { text?: string; mimeType?: string } };
  [k: string]: unknown;
}
export interface Har { log: { entries: HarEntry[]; [k: string]: unknown } }

/** Max bytes accepted for one HAR (content or file). */
export const HAR_MAX_BYTES = 5 * 1024 * 1024;
/** Max bytes accepted for one screenshot. */
export const SCREENSHOT_MAX_BYTES = 10 * 1024 * 1024;

const SECRET_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-amz-security-token)$/i;
const SECRET_PARAM = /(token|key|secret|sig(nature)?|password|passwd|pwd|auth|session|credential|code)$/i;

export function parseHar(text: string): Har | undefined {
  try {
    const j = JSON.parse(text) as Har;
    return j && typeof j === "object" && j.log && Array.isArray(j.log.entries) ? j : undefined;
  } catch { return undefined; }
}

/** Mask secret-looking query params in a URL (token, key, secret, sig, access_token, api_key…), then generic scrub. */
export function redactUrl(u: string, redactor: Redactor): string {
  let out = u;
  try {
    const url = new URL(u);
    for (const k of [...url.searchParams.keys()]) if (SECRET_PARAM.test(k)) url.searchParams.set(k, MASK);
    if (url.username || url.password) { url.username = MASK; url.password = ""; }
    out = url.toString().replace(/%5BREDACTED%5D/g, MASK);
  } catch { /* not a parseable URL: regex fallback below */ }
  out = out.replace(/([?&;]([^=&#\s]*))=([^&#\s]*)/g, (m, pre: string, name: string) => SECRET_PARAM.test(decodeURIComponentSafe(name)) ? `${pre}=${MASK}` : m);
  return scrub(out, redactor);
}

/** Redact a HAR: secret headers/cookies masked, secret query params masked, bodies through generic + env secret scrubbing. */
export function redactHar(text: string, redactor: Redactor): string {
  const har = parseHar(text);
  if (!har) throw new Error("not a HAR file (expected JSON with log.entries[])");
  const hdrs = (h?: { name: string; value: string }[]) => h?.map((x) => ({ ...x, value: SECRET_HEADER.test(x.name) ? MASK : scrub(String(x.value), redactor) }));
  const cookies = (c?: { name: string; value: string }[]) => c?.map((x) => ({ ...x, value: MASK }));
  const qs = (q?: { name: string; value: string }[]) => q?.map((x) => ({ ...x, value: SECRET_PARAM.test(x.name) ? MASK : scrub(String(x.value), redactor) }));
  for (const e of har.log.entries) {
    const rq = e.request ?? ({} as HarEntry["request"]), rs = e.response ?? ({} as HarEntry["response"]);
    rq.url = redactUrl(String(rq.url ?? ""), redactor);
    rq.headers = hdrs(rq.headers); rq.cookies = cookies(rq.cookies); rq.queryString = qs(rq.queryString);
    if (rq.postData?.text) rq.postData.text = scrub(rq.postData.text, redactor);
    if (rq.postData?.params) rq.postData.params = rq.postData.params.map((p) => ({ ...p, value: SECRET_PARAM.test(p.name) ? MASK : scrub(String(p.value ?? ""), redactor) }));
    rs.headers = hdrs(rs.headers); rs.cookies = cookies(rs.cookies);
    if (rs.content?.text) rs.content.text = scrub(rs.content.text, redactor);
    if (typeof rs.redirectURL === "string") rs.redirectURL = redactUrl(rs.redirectURL as string, redactor);
  }
  // Final pass over every string value (not the serialised text, so JSON escaping stays valid) catches fields we
  // don't model (pages, _initiator, comments…).
  const walk = (v: unknown): unknown => typeof v === "string" ? scrub(v, redactor) : Array.isArray(v) ? v.map(walk)
    : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [scrub(k, redactor), walk(x)])) : v;
  return JSON.stringify(walk(har), null, 2);
}

/** One line per entry, for the audit view. */
export const harSummary = (har: Har) => har.log.entries.map((e) => `${e.request?.method} ${e.request?.url} → ${e.response?.status}`).join("\n");

export interface UiExpect { har?: { urlMatch: string; status: number | [number, number]; bodyMatch?: string; method?: string }; text?: { contains: string } }

export function uiExpectProblem(v: unknown): string | undefined {
  const o = v as UiExpect;
  if (!o || typeof o !== "object") return "ui value must be {har:{urlMatch,status}} or {text:{contains}}";
  if (!!o.har === !!o.text) return "ui value needs exactly one of har or text";
  if (o.har) {
    try { new RegExp(o.har.urlMatch); } catch { return "ui har.urlMatch is not a valid regex"; }
    if (typeof o.har.urlMatch !== "string" || !o.har.urlMatch) return "ui har.urlMatch is required";
    const s = o.har.status;
    if (!(typeof s === "number" || (Array.isArray(s) && s.length === 2 && s.every((x) => typeof x === "number")))) return "ui har.status must be a number or [min, max]";
    if (o.har.bodyMatch !== undefined) try { new RegExp(o.har.bodyMatch); } catch { return "ui har.bodyMatch is not a valid regex"; }
  } else if (typeof o.text?.contains !== "string" || !o.text.contains) return "ui text.contains must be a non-empty string";
  return undefined;
}

/**
 * Judge a `ui` expectation. `har` reads only HAR evidence (network status/body); `text` reads only non-HAR text
 * (DOM text). Screenshot bytes never reach this function. No applicable evidence → inconclusive.
 */
export function judgeUi(v: UiExpect, texts: string[]): { status: "pass" | "fail" | "inconclusive"; reasons: string[] } {
  const hars = texts.map(parseHar);
  if (v.har) {
    const re = new RegExp(v.har.urlMatch);
    const hits = hars.flatMap((h) => h?.log.entries ?? []).filter((e) => re.test(String(e.request?.url)) && (!v.har!.method || e.request?.method?.toUpperCase() === v.har!.method.toUpperCase()));
    if (!hits.length) return { status: "inconclusive", reasons: [`no HAR entry matching /${v.har.urlMatch}/`] };
    const [lo, hi] = Array.isArray(v.har.status) ? v.har.status : [v.har.status, v.har.status];
    const bad = hits.filter((e) => !(e.response?.status >= lo && e.response?.status <= hi) || (v.har!.bodyMatch && !new RegExp(v.har!.bodyMatch, "m").test(e.response?.content?.text ?? "")));
    return bad.length
      ? { status: "fail", reasons: bad.map((e) => `${e.request.method} ${e.request.url} → ${e.response?.status}, expected ${lo === hi ? lo : `${lo}-${hi}`}${v.har!.bodyMatch ? ` with body /${v.har!.bodyMatch}/` : ""}`) }
      : { status: "pass", reasons: [] };
  }
  const plain = texts.filter((_, i) => !hars[i]);
  if (!plain.length) return { status: "inconclusive", reasons: ["no DOM/text evidence (screenshots are not judged)"] };
  return plain.join("\n").includes(v.text!.contains) ? { status: "pass", reasons: [] } : { status: "fail", reasons: [`page text does not contain ${JSON.stringify(v.text!.contains)}`] };
}

function decodeURIComponentSafe(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }
