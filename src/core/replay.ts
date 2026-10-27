// Core-executed replay of one GET/HEAD request taken from a HAR. SSRF-hardened:
// host allowlist, IP policy checked on the address we actually connect to (DNS resolved once per hop and pinned),
// no automatic redirects (each hop re-checked), HAR cookies/auth never forwarded.
// The guarded network code lives in ./egress/ (policy, fetch, ws, targets); this file keeps the config type.
// allowHosts parsing and authFor live in ./egress/allowhosts.ts.

export interface ReplayConfig {
  /** Hostnames (optionally host:port) the replay may contact. Anything else is rejected. */
  allowHosts: string[];
  /**
   * CIDRs explicitly allowed even though they are private / loopback / link-local, e.g. "127.0.0.1/32" for a local demo.
   * Cloud metadata addresses are denied regardless.
   */
  allowCidrs?: string[];
  /**
   * Test-account auth, taken from config/env only (never from the HAR): header name + env var holding the value.
   * Bound to origins (scheme://host:port): `origins` if given, else only the origin of the replayed URL. It is never
   * sent to any other origin, so a redirect to another host, port or scheme (incl. https→http) drops it.
   */
  auth?: { header: string; valueEnv: string; origins?: string[] };
  /**
   * capture_page only (issue #19): path to a user-provided Playwright storageState JSON (`{cookies, origins}`) or a
   * bare cookie array, loaded into the capture's browser context so pages behind a login render. Cookies/origins
   * outside allowHosts are dropped; every cookie / localStorage value is redacted from all evidence; the path is never
   * written to evidence or the command log. Browsing stays read-only (GET/HEAD; no click/type/submit).
   */
  capture?: {
    storageStatePath?: string;
    /**
     * Issue #18: WebSockets are OFF unless the host (or host:port) is listed here. Separate from allowHosts; a listed
     * host must ALSO pass allowHosts + the IP rules. Connected sockets are receive-only by default.
     */
    allowWebSocketHosts?: string[];
    /** Per host (same keys as allowWebSocketHosts): exact text messages the page may send (e.g. a subscribe frame). */
    webSocketOutbound?: Record<string, string[]>;
  };
  maxRedirects?: number;
  timeoutMs?: number;
  maxBodyBytes?: number;
}

