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

/** Header NAMES that carry credentials, by pattern (X-Access-Token, Api-Key, X-Goog-Api-Key, X-Session-Id, Set-Cookie…). */
export const SECRET_HEADER = /(authorization|cookie|token|api-?key|apikey|secret|session|auth|csrf|xsrf|signature|password|jwt|ticket|credential)/i;
/**
 * Query/form param NAMES, matched on the whole name or its last `-`/`_`/`.` segment, so `barcode`, `zipcode`, `monkey`
 * are kept but `access_token`, `api_key`, `X-Amz-Signature`, `sid`, `jwt`, `ticket`, `code` are masked.
 */
export const SECRET_PARAM = /^(?:.*[-_.])?(?:access[-_]?token|refresh[-_]?token|id[-_]?token|token|key|api[-_]?key|apikey|secret|client[-_]?secret|sig|signature|password|passwd|pwd|auth|session|session[-_]?id|sessionid|sid|jwt|ticket|code|credential|credentials|security[-_]?token)$/i;

/** Max length of an agent-supplied regex; longer patterns are rejected. */
export const MAX_REGEX_LEN = 200;
/**
 * Compile an agent-supplied regex with a ReDoS guard: length cap, no backreferences, and no quantified group that
 * itself contains a quantifier (`(a+)+`, `(a|aa)*`-style nesting). Throws on anything else.
 */
export function safeRegex(p: string, flags = ""): RegExp {
  if (typeof p !== "string" || !p) throw new Error("regex must be a non-empty string");
  if (p.length > MAX_REGEX_LEN) throw new Error(`regex longer than ${MAX_REGEX_LEN} chars`);
  if (/\\[1-9]|\\k</.test(p)) throw new Error("regex backreferences are not allowed");
  if (/\((?:[^()\\]|\\.)*(?:[+*]|\{\d+,?\d*\})(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,?\d*\})/.test(p)) throw new Error("nested quantifiers are not allowed (ReDoS guard)");
  if (/\((?:[^()]*\|[^()]*)\)\s*[+*]/.test(p)) throw new Error("quantified alternation is not allowed (ReDoS guard)");
  return new RegExp(p, flags);
}

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

/** Redact every http(s) URL inside free text (e.g. an error message that quotes the blocked URL). */
export function redactUrlsIn(text: string, redactor: Redactor): string {
  return text.replace(/\bhttps?:\/\/[^\s"'<>]+/g, (u) => redactUrl(u, redactor));
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
    if (rq.postData?.text) rq.postData.text = scrub(redactUrlsIn(rq.postData.text, redactor), redactor);
    if (rq.postData?.params) rq.postData.params = rq.postData.params.map((p) => ({ ...p, value: SECRET_PARAM.test(p.name) ? MASK : scrub(String(p.value ?? ""), redactor) }));
    rs.headers = hdrs(rs.headers); rs.cookies = cookies(rs.cookies);
    if (rs.content?.text) {
      // URLs embedded in bodies (e.g. page HTML with ?token=… links) go through redactUrl; base64 text bodies are
      // decoded first so the redaction actually sees them.
      const c = rs.content as { text: string; encoding?: string; mimeType?: string };
      if (c.encoding === "base64" && /^(text\/|application\/(json|javascript|xml|x-www-form-urlencoded)|image\/svg)/i.test(c.mimeType ?? "")) {
        c.text = Buffer.from(scrub(redactUrlsIn(Buffer.from(c.text, "base64").toString("utf8"), redactor), redactor), "utf8").toString("base64");
      } else if (c.encoding !== "base64") c.text = scrub(redactUrlsIn(c.text, redactor), redactor);
    }
    if (typeof rs.redirectURL === "string") rs.redirectURL = redactUrl(rs.redirectURL as string, redactor);
  }
  // Final pass over every string value (not the serialised text, so JSON escaping stays valid) catches fields we
  // don't model (pages, _initiator, comments…).
  const walk = (v: unknown): unknown => typeof v === "string" ? scrub(/https?:\/\//.test(v) && v.length < 1_000_000 ? redactUrlsIn(v, redactor) : v, redactor) : Array.isArray(v) ? v.map(walk)
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
    if (typeof o.har.urlMatch !== "string" || !o.har.urlMatch) return "ui har.urlMatch is required";
    try { safeRegex(o.har.urlMatch); } catch (e) { return `ui har.urlMatch: ${(e as Error).message}`; }
    const s = o.har.status;
    if (!(typeof s === "number" || (Array.isArray(s) && s.length === 2 && s.every((x) => typeof x === "number")))) return "ui har.status must be a number or [min, max]";
    if (o.har.bodyMatch !== undefined) try { safeRegex(o.har.bodyMatch); } catch (e) { return `ui har.bodyMatch: ${(e as Error).message}`; }
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
    const re = safeRegex(v.har.urlMatch);
    const hits = hars.flatMap((h) => h?.log.entries ?? []).filter((e) => re.test(String(e.request?.url).slice(0, 2048)) && (!v.har!.method || e.request?.method?.toUpperCase() === v.har!.method.toUpperCase()));
    if (!hits.length) return { status: "inconclusive", reasons: [`no HAR entry matching /${v.har.urlMatch}/`] };
    const [lo, hi] = Array.isArray(v.har.status) ? v.har.status : [v.har.status, v.har.status];
    const bad = hits.filter((e) => !(e.response?.status >= lo && e.response?.status <= hi) || (v.har!.bodyMatch && !safeRegex(v.har!.bodyMatch, "m").test((e.response?.content?.text ?? "").slice(0, 65536))));
    return bad.length
      ? { status: "fail", reasons: bad.map((e) => `${e.request.method} ${e.request.url} → ${e.response?.status}, expected ${lo === hi ? lo : `${lo}-${hi}`}${v.har!.bodyMatch ? ` with body /${v.har!.bodyMatch}/` : ""}`) }
      : { status: "pass", reasons: [] };
  }
  const plain = texts.filter((_, i) => !hars[i]);
  if (!plain.length) return { status: "inconclusive", reasons: ["no DOM/text evidence (screenshots are not judged)"] };
  return plain.join("\n").includes(v.text!.contains) ? { status: "pass", reasons: [] } : { status: "fail", reasons: [`page text does not contain ${JSON.stringify(v.text!.contains)}`] };
}

function decodeURIComponentSafe(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }
