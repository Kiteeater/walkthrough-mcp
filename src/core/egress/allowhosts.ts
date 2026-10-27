// The one place replay.allowHosts entries are parsed and matched, plus the auth-header binding (authFor).
// Entry syntax: `host` (any port) or `host:port`; case-insensitive; no wildcards. Login state (issue #19) keeps a
// looser variant (see loginCookieHostnames / loginOriginAllowed): it is listed here so the differences sit side by side.
import type { ReplayConfig } from "../replay.js";

export interface AllowHostEntry { host: string; port?: string }

/** `Shop.Example:8080` → {host: "shop.example", port: "8080"}. Only a trailing `:<digits>` is a port. */
export function parseAllowHost(entry: string): AllowHostEntry {
  const value = entry.toLowerCase();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end > 0) {
      const host = value.slice(1, end);
      const suffix = value.slice(end + 1);
      return /^:\d+$/.test(suffix) ? { host, port: suffix.slice(1) } : { host };
    }
  }
  // A bare IPv6 literal has multiple colons and cannot safely carry a port;
  // callers must use the bracketed form when they need `host:port`.
  if (value.split(":").length > 2) return { host: value };
  const [host, port] = value.split(/:(?=\d+$)/);
  return port === undefined ? { host } : { host, port };
}

function defaultPort(u: URL): string { return u.port || (u.protocol === "https:" ? "443" : "80"); }

/** Hop host matches an entry exactly; an entry with a port also needs the hop's (default-filled) port. */
export function hostAllowed(u: URL, cfg: ReplayConfig): boolean {
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = defaultPort(u);
  return cfg.allowHosts.map(parseAllowHost).some((e) => e.host === host && (!e.port || e.port === port));
}

/** Distinct hostnames of the allowlist, ports dropped (capture_page pins each one for Chromium). */
export function allowedHostnames(cfg: ReplayConfig): string[] {
  return [...new Set(cfg.allowHosts.map((h) => parseAllowHost(h).host))];
}

/**
 * Login state only: hostnames for cookie domain-matching. Kept exactly as before the merge, so it differs from parseAllowHost:
 * IPv6 brackets are stripped (`[::1]:9` → `::1`), and any trailing `:<digits>` is cut first (so a bare `::1` → `:`).
 */
export function loginCookieHostnames(cfg: ReplayConfig): string[] {
  return cfg.allowHosts.map((h) => h.toLowerCase().replace(/:\d+$/, "").replace(/^\[|\]$/g, ""));
}

/**
 * Login state only: a storageState origin is kept when an entry equals the origin's `host` (port only if explicit in
 * the origin) or its bare hostname. Unlike hostAllowed, default ports are not filled in.
 */
export function loginOriginAllowed(origin: string, cfg: ReplayConfig): boolean {
  let u: URL;
  try { u = new URL(origin); } catch { return false; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const candidates = [u.host.toLowerCase(), u.hostname.replace(/^\[|\]$/g, "").toLowerCase()];
  return cfg.allowHosts.some((a) => candidates.includes(a.toLowerCase()));
}

/** Auth headers for one hop: only when the hop's origin is one the account is bound to. Never cookies. */
export function authFor(cfg: ReplayConfig, hop: URL, firstOrigin: string, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  if (!cfg.auth) return {};
  const allowed = (cfg.auth.origins?.length ? cfg.auth.origins : [firstOrigin]).map((o) => new URL(o).origin);
  if (!allowed.includes(hop.origin)) return {};
  const v = env[cfg.auth.valueEnv];
  return v ? { [cfg.auth.header.toLowerCase()]: v } : {};
}
