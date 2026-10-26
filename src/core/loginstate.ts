// Issue #19: user-provided login state for capture_page. The file (Playwright storageState JSON, or a bare cookie
// array) is read from the path in config at capture time. Nothing from it is written anywhere: values become
// redactor secrets for the capture, the path never reaches evidence or the command log.
import { readFileSync } from "node:fs";
import type { LoginStorageState } from "./capture.js";
import { ReplayRejectedError, type ReplayConfig } from "./replay.js";

export interface LoadedLoginState {
  storageState: LoginStorageState;
  /** Every cookie / localStorage value: redacted from all evidence of the capture. */
  secrets: string[];
  /** Counts only (no names, no values, no path) for the command log. */
  summary: { cookies: number; origins: number; droppedCookies: number; droppedOrigins: number };
}

const SAME_SITE = new Set(["Strict", "Lax", "None"]);

function allowedHostnames(cfg: ReplayConfig): string[] {
  return cfg.allowHosts.map((h) => h.toLowerCase().replace(/:\d+$/, "").replace(/^\[|\]$/g, ""));
}

/** Cookie domain matches an allowlisted hostname (RFC 6265 domain-match, leading dot = that host and subdomains). */
function cookieDomainAllowed(domain: string, hosts: string[]): boolean {
  const d = domain.toLowerCase().replace(/^\./, "");
  return hosts.some((h) => h === d || h.endsWith(`.${d}`));
}

function originAllowed(origin: string, hosts: string[], cfg: ReplayConfig): boolean {
  try {
    const u = new URL(origin);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const host = u.hostname.replace(/^\[|\]$/g, "");
    return cfg.allowHosts.some((a) => { const x = a.toLowerCase(); return x === u.host.toLowerCase() || x === host.toLowerCase(); }) && hosts.length > 0;
  } catch { return false; }
}

export function loadLoginState(cfg: ReplayConfig, path: string, readFile: (p: string) => string = (p) => readFileSync(p, "utf8")): LoadedLoginState {
  let raw: unknown;
  // Errors never echo the file content (it holds session values).
  try { raw = JSON.parse(readFile(path)); } catch { throw new ReplayRejectedError("capture.storageStatePath: file could not be read as JSON (Playwright storageState or cookie array)"); }
  const obj = (Array.isArray(raw) ? { cookies: raw, origins: [] } : raw) as { cookies?: unknown; origins?: unknown };
  if (!obj || typeof obj !== "object" || (obj.cookies !== undefined && !Array.isArray(obj.cookies)) || (obj.origins !== undefined && !Array.isArray(obj.origins)))
    throw new ReplayRejectedError("capture.storageStatePath: expected {cookies: [...], origins: [...]} or a cookie array");
  const hosts = allowedHostnames(cfg);
  const secrets: string[] = [];
  const cookies: LoginStorageState["cookies"] = [];
  let droppedCookies = 0, droppedOrigins = 0;
  for (const c of (obj.cookies ?? []) as Record<string, unknown>[]) {
    if (!c || typeof c.name !== "string" || typeof c.value !== "string" || typeof c.domain !== "string")
      throw new ReplayRejectedError("capture.storageStatePath: every cookie needs string name, value and domain");
    if (c.value) secrets.push(c.value);
    if (!cookieDomainAllowed(c.domain, hosts)) { droppedCookies++; continue; } // never loaded for a non-allowlisted host
    cookies.push({
      name: c.name, value: c.value, domain: c.domain, path: typeof c.path === "string" ? c.path : "/",
      expires: typeof c.expires === "number" ? c.expires : -1, httpOnly: c.httpOnly === true, secure: c.secure === true,
      sameSite: SAME_SITE.has(String(c.sameSite)) ? (c.sameSite as "Strict" | "Lax" | "None") : "Lax",
    });
  }
  const origins: LoginStorageState["origins"] = [];
  for (const o of (obj.origins ?? []) as { origin?: unknown; localStorage?: unknown }[]) {
    const ls = Array.isArray(o?.localStorage) ? (o.localStorage as { name?: unknown; value?: unknown }[]).filter((x) => typeof x?.name === "string" && typeof x?.value === "string") as { name: string; value: string }[] : [];
    for (const x of ls) if (x.value) secrets.push(x.value);
    if (typeof o?.origin !== "string" || !originAllowed(o.origin, hosts, cfg)) { droppedOrigins++; continue; }
    origins.push({ origin: o.origin, localStorage: ls });
  }
  return { storageState: { cookies, origins }, secrets: [...new Set(secrets)], summary: { cookies: cookies.length, origins: origins.length, droppedCookies, droppedOrigins } };
}
