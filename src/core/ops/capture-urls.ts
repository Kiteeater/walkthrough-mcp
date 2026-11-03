// Capture URL helpers moved verbatim from walkthrough.ts (first ops/ split; no logic change).
// Used by capture_page / flow screenshots to treat blocked-request URLs and WebSocket hosts.

/** Query values (any name) and userinfo of the given URLs, as extra secrets. */
export function blockedUrlSecrets(urls: string[]): string[] {
  const out = new Set<string>();
  for (const u of urls) {
    try {
      const x = new URL(u);
      for (const v of x.searchParams.values()) if (v.length >= 3) { out.add(v); out.add(encodeURIComponent(v)); }
      if (x.username.length >= 3) out.add(decodeURIComponent(x.username));
      if (x.password.length >= 3) out.add(decodeURIComponent(x.password));
      if (x.search.length > 4) out.add(x.search.slice(1));
    } catch { /* unparseable: regex fallback in maskAllQuery */ }
  }
  return [...out];
}

/** Mask every query parameter value (not only known secret names) and any userinfo. */
export function maskAllQuery(u: string): string {
  try {
    const x = new URL(u);
    for (const k of [...new Set(x.searchParams.keys())]) x.searchParams.set(k, "[REDACTED]");
    if (x.username || x.password) { x.username = "[REDACTED]"; x.password = ""; }
    return x.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
  } catch { return u.replace(/([?&;][^=&#\s]*)=[^&#\s]*/g, "$1=[REDACTED]"); }
}

/** Matching key in capture.allowWebSocketHosts for a ws(s) URL: exact host:port, or bare host (any port). */
export function wsHostKey(list: string[], url: URL): string | undefined {
  const host = url.hostname.toLowerCase(), port = url.port || (url.protocol === "wss:" ? "443" : "80");
  return list.find((h) => h.toLowerCase() === `${host}:${port}`) ?? list.find((h) => h.toLowerCase() === host);
}
