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
  /** Test-account auth, taken from config/env only (never from the HAR): header name + env var holding the value. */
  auth?: { header: string; valueEnv: string };
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
DENY.addSubnet("::1", 128, "ipv6"); DENY.addSubnet("fc00::", 7, "ipv6"); DENY.addSubnet("fe80::", 10, "ipv6"); DENY.addSubnet("::", 128, "ipv6");

/** IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:XXXX:XXXX) → plain IPv4, so mapped addresses get the IPv4 rules. */
export function norm(ipRaw: string): string {
  const ip = ipRaw.toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const d = /^(?:0{0,4}:){0,4}:?(?:0{0,4}:)?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (d) return d[1];
  const h = /^(?:0{0,4}:){0,4}:?(?:0{0,4}:)?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip);
  if (h) { const a = parseInt(h[1], 16), b = parseInt(h[2], 16); return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`; }
  if (isIP(ip) === 6) { try { return new URL(`http://[${ip}]/`).hostname.replace(/^\[|\]$/g, ""); } catch { /* keep */ } }
  return ip;
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
    // Loopback exceptions must be exact hosts (127.0.0.1/32, ::1/128); a wider loopback range is ignored.
    const loop = f === "ipv4" ? net.startsWith("127.") : norm(net) === "::1";
    if (loop && n !== (f === "ipv4" ? 32 : 128)) continue;
    allow.addSubnet(net, n, f);
  }
  return allow.check(ip, fam) ? undefined : `private/loopback/link-local address ${ip} is denied (not in allowCidrs)`;
}

export interface ReplayHop { url: string; ip: string; status: number }
export interface ReplayResult {
  method: string; url: string; status: number; headers: Record<string, string>; body: string; hops: ReplayHop[];
}

function hostAllowed(u: URL, cfg: ReplayConfig): boolean {
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return cfg.allowHosts.some((h) => { const [hh, hp] = h.toLowerCase().split(/:(?=\d+$)/); return hh === host && (!hp || hp === port); });
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
  for (let i = 0; ; i++) {
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new ReplayRejectedError(`unsupported scheme ${url.protocol}`);
    if (url.username || url.password) throw new ReplayRejectedError("URLs with userinfo are not replayed");
    if (!hostAllowed(url, cfg)) throw new ReplayRejectedError(`host ${url.host} is not in the replay allowlist`);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const ip = norm(isIP(host) ? host : await resolver(host)); // resolved ONCE for this hop, then pinned
    const bad = ipProblem(ip, cfg.allowCidrs);
    if (bad) throw new ReplayRejectedError(`${url.host}: ${bad}`);
    const headers: Record<string, string> = { "user-agent": "walkthrough-replay/1", accept: "*/*" };
    if (cfg.auth) { const v = (opts.env ?? process.env)[cfg.auth.valueEnv]; if (v) headers[cfg.auth.header.toLowerCase()] = v; }
    const r = await send(url, method, headers, ip, cfg);
    hops.push({ url: url.toString(), ip, status: r.status });
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      if (i >= max) throw new ReplayRejectedError(`too many redirects (> ${max})`);
      url = new URL(loc, url); // next hop goes through the same allowlist + IP checks
      continue;
    }
    return { method, url: input.url, status: r.status, headers: r.headers, body: r.body, hops };
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
      if (remote && remote !== ip) { res.destroy(); return reject(new ReplayRejectedError(`connected to ${remote}, expected ${ip}`)); }
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
    req.on("socket", (s) => s.once("connect", () => { const r = norm(s.remoteAddress ?? ""); if (r !== ip) req.destroy(new ReplayRejectedError(`connected to ${r}, expected ${ip}`)); }));
    req.on("timeout", () => req.destroy(new Error("replay timed out")));
    req.on("error", reject);
    req.end();
  });
}
