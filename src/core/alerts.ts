// Prometheus alert watching (read-only GET /api/v1/alerts): redaction of labels/annotations and label matching.
import { MASK, type Redactor } from "./redact.js";
import { SECRET_HEADER, SECRET_PARAM, redactUrl, safeRegex } from "./har.js";
import { scrub } from "./imports.js";

export interface PromAlert { labels: Record<string, string>; annotations: Record<string, string>; state: string; activeAt?: string; value?: string }

/** Caps for watch_alerts: bounded window and poll interval. */
export const ALERT_WATCH_MAX_WINDOW_S = 900;
export const ALERT_WATCH_MIN_INTERVAL_S = 1;
export const ALERT_WATCH_MAX_INTERVAL_S = 60;
export const ALERT_WATCH_MAX_POLLS = 120;
export const ALERTS_EVIDENCE = "walkthrough.alerts/v1";

/** Label matcher: every label must match; a value `~<regex>` is a (ReDoS-guarded) regex, otherwise exact. */
export type AlertMatcher = Record<string, string>;

export function matcherProblem(m: unknown): string | undefined {
  if (!m || typeof m !== "object" || Array.isArray(m) || !Object.keys(m).length) return "alert matcher must be a non-empty {label: value} object";
  for (const [k, v] of Object.entries(m as Record<string, unknown>)) {
    if (typeof v !== "string") return `alert matcher ${k} must be a string`;
    if (v.startsWith("~")) try { safeRegex(`^(?:${v.slice(1)})$`); } catch (e) { return `alert matcher ${k}: ${(e as Error).message}`; }
  }
  return undefined;
}

export function alertMatches(a: PromAlert, m: AlertMatcher): boolean {
  return Object.entries(m).every(([k, v]) => {
    const got = a.labels?.[k];
    if (got === undefined) return false;
    return v.startsWith("~") ? safeRegex(`^(?:${v.slice(1)})$`).test(got.slice(0, 1024)) : got === v;
  });
}

/** Redact one label/annotation value: secret-looking key → MASK; URLs → query-param redaction; then generic scrub. */
function redactValue(key: string, v: string, red: Redactor): string {
  if (SECRET_PARAM.test(key) || SECRET_HEADER.test(key)) return MASK;
  const s = String(v).replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, (u) => redactUrl(u, red));
  return scrub(s, red);
}

/** Labels and annotations redacted (keys too) before they reach evidence, findings or HTML. */
export function redactAlert(a: PromAlert, red: Redactor): PromAlert {
  const map = (o: Record<string, string> = {}) => Object.fromEntries(Object.entries(o).map(([k, v]) => [scrub(k, red), redactValue(k, v, red)]));
  return { labels: map(a.labels), annotations: map(a.annotations), state: String(a.state), activeAt: a.activeAt, value: a.value === undefined ? undefined : scrub(String(a.value), red) };
}

/** Stable identity of an alert across polls. */
export const alertKey = (a: PromAlert) => JSON.stringify(Object.entries(a.labels ?? {}).sort(([x], [y]) => x.localeCompare(y)));

export const severityOf = (a: PromAlert): "critical" | "high" | "medium" | "low" => {
  const s = (a.labels?.severity ?? "").toLowerCase();
  return s === "critical" || s === "page" ? "critical" : s === "warning" || s === "warn" ? "medium" : s === "info" || s === "low" ? "low" : "high";
};
