// Core-executed replay of one GET/HEAD request taken from a HAR. SSRF-hardened:
// host allowlist, IP policy checked on the address we actually connect to (DNS resolved once per hop and pinned),
// no automatic redirects (each hop re-checked), HAR cookies/auth never forwarded.
import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";

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
  maxRedirects?: number;
  timeoutMs?: number;
  maxBodyBytes?: number;
}

export class ReplayRejectedError extends Error {
  constructor(message: string) { super(message); this.name = "ReplayRejectedError"; }
}

export type Resolver = (host: string) => Promise<string>;
export const defaultResolver: Resolver = async (h) => (await dnsLookup(h)).address;

const METADATA = new Set(["169.254.169.254", "fd00:ec2::254", "100.100.100.200"]);
const DENY = new BlockList(); // + IPv4-mapped forms via norm()
DENY.addSubnet("10.0.0.0", 8); DENY.addSubnet("172.16.0.0", 12); DENY.addSubnet("192.168.0.0", 16);
DENY.addSubnet("127.0.0.0", 8); DENY.addSubnet("169.254.0.0", 16); DENY.addSubnet("100.64.0.0", 10); DENY.addSubnet("0.0.0.0", 8);
DENY.addSubnet("224.0.0.0", 4); DENY.addSubnet("240.0.0.0", 4); DENY.addSubnet("198.18.0.0", 15);
// Teredo, NAT64 local-use and multicast are denied outright.
DENY.addSubnet("2001::", 32, "ipv6"); DENY.addSubnet("64:ff9b:1::", 48, "ipv6"); DENY.addSubnet("ff00::", 8, "ipv6");
DENY.addSubnet("::1", 128, "ipv6"); DENY.addSubnet("fc00::", 7, "ipv6"); DENY.addSubnet("fe80::", 10, "ipv6"); DENY.addSubnet("::", 128, "ipv6");

/** Expand an IPv6 address (incl. a dotted IPv4 tail) to 8 hextets, or undefined. */
function hextets(ip: string): number[] | undefined {
  if (isIP(ip) !== 6) return undefined;
  let s = ip;
  const dq = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (dq) { const o = dq[1].split(".").map(Number); s = s.slice(0, -dq[1].length) + `${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`; }
  const [l, r] = s.split("::");
  const L = l ? l.split(":") : [], R = r !== undefined ? (r ? r.split(":") : []) : [];
  const parts = r !== undefined ? [...L, ...Array(8 - L.length - R.length).fill("0"), ...R] : L;
  return parts.length === 8 ? parts.map((x) => parseInt(x, 16)) : undefined;
}
const v4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/**
 * Normalise an address so IPv6 forms that embed an IPv4 address are judged by the IPv4 rules:
 * IPv4-mapped ::ffff:0:0/96, IPv4-compatible ::/96 (e.g. ::127.0.0.1), NAT64 64:ff9b::/96, 6to4 2002::/16 (bits 16-47).
 * Other IPv6 addresses come back in canonical form.
 */
export function norm(ipRaw: string): string {
  const ip = ipRaw.toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const h = hextets(ip);
  if (!h) return ip;
  const zero = (n: number) => h.slice(0, n).every((x) => x === 0);
  if (zero(5) && h[5] === 0xffff) return v4(h[6], h[7]);
  if (zero(6) && !(h[6] === 0 && h[7] <= 1)) return v4(h[6], h[7]);
  if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) return v4(h[6], h[7]);
  if (h[0] === 0x2002) return v4(h[1], h[2]);
  try { return new URL(`http://[${ip}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { return ip; }
}

/** Why connecting to `ip` is forbidden, or undefined. */
export function ipProblem(ipRaw: string, allowCidrs: string[] = []): string | undefined {
  const ip = norm(ipRaw);
  const fam = isIP(ip) === 6 ? "ipv6" : "ipv4";
  if (!isIP(ip)) return `not an IP: ${ip}`;
  if (METADATA.has(ip)) return `cloud metadata address ${ip} is always denied`;
  if (!DENY.check(ip, fam)) return undefined;
  const allow = new BlockList();
  for (const c of allowCidrs) {
    const [net, bits] = c.split("/");
    const f = isIP(net) === 6 ? "ipv6" : "ipv4";
    const n = Number(bits ?? (f === "ipv6" ? 128 : 32));
    if (!isIP(net) || METADATA.has(norm(net))) continue;
    if (f === "ipv6" && isIP(norm(net)) === 4) continue; // embedded-IPv4 CIDRs are ignored: list the IPv4 form
    // Loopback exceptions must be exact hosts (127.0.0.1/32, ::1/128); a wider loopback range is ignored.
    const loop = f === "ipv4" ? net.startsWith("127.") : norm(net) === "::1";
    if (loop && n !== (f === "ipv4" ? 32 : 128)) continue;
    allow.addSubnet(net, n, f);
  }
  return allow.check(ip, fam) ? undefined : `private/loopback/link-local/reserved address ${ip} is denied (not in allowCidrs)`;
}

export interface ReplayHop { url: string; ip: string; status: number }
export interface ReplayResult {
  method: string; url: string; status: number; headers: Record<string, string>; body: string; hops: ReplayHop[];
  /** Credential values actually sent (callers must redact them from anything they store). */
  sentSecrets: string[];
}

/** Auth headers for one hop: only when the hop's origin is one the account is bound to. Never cookies. */
export function authFor(cfg: ReplayConfig, hop: URL, firstOrigin: string, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  if (!cfg.auth) return {};
  const allowed = (cfg.auth.origins?.length ? cfg.auth.origins : [firstOrigin]).map((o) => new URL(o).origin);
  if (!allowed.includes(hop.origin)) return {};
  const v = env[cfg.auth.valueEnv];
  return v ? { [cfg.auth.header.toLowerCase()]: v } : {};
}

function hostAllowed(u: URL, cfg: ReplayConfig): boolean {
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return cfg.allowHosts.some((h) => { const [hh, hp] = h.toLowerCase().split(/:(?=\d+$)/); return hh === host && (!hp || hp === port); });
}

/**
 * Policy check for one hop: scheme, no userinfo, host allowlist, then resolve ONCE and judge that address.
 * Returns the address to pin the connection to. Throws ReplayRejectedError.
 */
export async function checkHop(cfg: ReplayConfig, url: URL, resolver: Resolver = defaultResolver): Promise<string> {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new ReplayRejectedError(`unsupported scheme ${url.protocol}`);
  if (url.username || url.password) throw new ReplayRejectedError("URLs with userinfo are not allowed");
  if (!hostAllowed(url, cfg)) throw new ReplayRejectedError(`host ${url.host} is not in the replay allowlist`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const raw = (isIP(host) ? host : await resolver(host)).toLowerCase().replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, "$1");
  const bad = ipProblem(raw, cfg.allowCidrs);
  if (bad) throw new ReplayRejectedError(`${url.host}: ${bad}`);
  return raw;
}

/** One policy-checked, IP-pinned GET with no redirect following (used for capture_page main-frame navigations). */
export async function guardedGet(cfg: ReplayConfig, url: string, opts: { resolver?: Resolver; headers?: Record<string, string> } = {}): Promise<{ status: number; headers: Record<string, string>; body: string; ip: string }> {
  const u = new URL(url);
  const ip = await checkHop(cfg, u, opts.resolver);
  const r = await send(u, "GET", { "user-agent": "walkthrough-page/1", accept: "text/html,*/*", ...(opts.headers ?? {}) }, ip, cfg);
  return { ...r, ip };
}

/** Replay one request. Throws ReplayRejectedError on any policy violation; nothing is sent in that case. */
export async function replayRequest(
  cfg: ReplayConfig, input: { method: string; url: string },
  opts: { resolver?: Resolver; env?: NodeJS.ProcessEnv } = {},
): Promise<ReplayResult> {
  const method = input.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") throw new ReplayRejectedError(`only GET/HEAD can be replayed, got ${method}`);
  const resolver = opts.resolver ?? defaultResolver;
  const max = cfg.maxRedirects ?? 3;
  const hops: ReplayHop[] = [];
  let url = new URL(input.url);
  const first = url.origin;
  const sent: string[] = [];
  for (let i = 0; ; i++) {
    const ip = await checkHop(cfg, url, resolver);
    // Fresh headers per hop: nothing carries over; the account is attached only for its own origin(s).
    const auth = authFor(cfg, url, first, opts.env);
    sent.push(...Object.values(auth));
    const headers: Record<string, string> = { "user-agent": "walkthrough-replay/1", accept: "*/*", ...auth };
    const r = await send(url, method, headers, ip, cfg);
    hops.push({ url: url.toString(), ip, status: r.status });
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      if (i >= max) throw new ReplayRejectedError(`too many redirects (> ${max})`);
      url = new URL(loc, url); // next hop goes through the same allowlist + IP checks
      continue;
    }
    return { method, url: input.url, status: r.status, headers: r.headers, body: r.body, hops, sentSecrets: [...new Set(sent)] };
  }
}

function send(url: URL, method: string, headers: Record<string, string>, ip: string, cfg: ReplayConfig): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const mod = url.protocol === "https:" ? https : http;
  const fam = isIP(ip);
  return new Promise((resolveP, reject) => {
    const req = mod.request({
      method, protocol: url.protocol, hostname: url.hostname.replace(/^\[|\]$/g, ""), port: url.port || undefined, path: url.pathname + url.search,
      headers: { ...headers, host: url.host }, servername: isIP(url.hostname) ? undefined : url.hostname,
      // Pin the connection to the address we validated: no second DNS lookup inside http (defeats rebinding).
      lookup: ((_h: string, o: { all?: boolean }, cb: (...a: unknown[]) => void) => o?.all ? cb(null, [{ address: ip, family: fam }]) : cb(null, ip, fam)) as never,
      agent: false, timeout: cfg.timeoutMs ?? 10_000,
    }, (res) => {
      const remote = norm(res.socket.remoteAddress ?? "");
      if (remote && remote !== norm(ip)) { res.destroy(); return reject(new ReplayRejectedError(`connected to ${remote}, expected ${ip}`)); }
      const chunks: Buffer[] = []; let n = 0; const cap = cfg.maxBodyBytes ?? 256 * 1024;
      res.on("data", (c: Buffer) => { if (n < cap) chunks.push(c.subarray(0, cap - n)); n += c.length; });
      res.on("end", () => {
        const h: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) h[k] = Array.isArray(v) ? v.join(", ") : v;
        resolveP({ status: res.statusCode ?? 0, headers: h, body: Buffer.concat(chunks).toString("utf8") });
      });
      res.on("error", reject);
    });
    // Re-check the actual peer before any byte is written.
    req.on("socket", (s) => s.once("connect", () => { const r = norm(s.remoteAddress ?? ""); if (r !== norm(ip)) req.destroy(new ReplayRejectedError(`connected to ${r}, expected ${ip}`)); }));
    req.on("timeout", () => req.destroy(new Error("replay timed out")));
    req.on("error", reject);
    req.end();
  });
}
