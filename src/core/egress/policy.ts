// Egress policy (moved from replay.ts): core blocklist, IP rules, host allowlist check, per-hop check, flow policy.
import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import type { ReplayConfig } from "../replay.js";
import { hostAllowed } from "./allowhosts.js";

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

/**
 * Core blocklist: always refused on every outbound path (HTTP, WebSocket, capture_page, replay, metrics, run_cli
 * targets, mongo URIs, flow http/readiness), whatever allowHosts / allowCidrs / allowWebSocketHosts say. Not
 * configurable on purpose. Judged after norm(), so IPv4-mapped / NAT64 / 6to4 forms are caught too.
 */
export const CORE_BLOCKED_IPS: readonly string[] = Object.freeze(["34.142.135.39"]);
const CORE_BLOCKED = new Set<string>(CORE_BLOCKED_IPS);
/**
 * TEST ONLY (refused outside vitest): add a stand-in address (e.g. 127.0.0.2, where a test server can count
 * connections) that is treated exactly like a core-blocked one. Returns an undo function.
 */
export function addTestCoreBlocked(ip: string): () => void {
  if (!process.env.VITEST) throw new Error("addTestCoreBlocked is only available under vitest");
  const n = norm(ip); CORE_BLOCKED.add(n);
  return () => { if (!CORE_BLOCKED_IPS.includes(n)) CORE_BLOCKED.delete(n); };
}
export function coreBlocked(ipRaw: string): boolean { return CORE_BLOCKED.has(norm(ipRaw)); }

/** Why connecting to `ip` is forbidden, or undefined. */
export function ipProblem(ipRaw: string, allowCidrs: string[] = []): string | undefined {
  const ip = norm(ipRaw);
  const fam = isIP(ip) === 6 ? "ipv6" : "ipv4";
  if (!isIP(ip)) return `not an IP: ${ip}`;
  if (CORE_BLOCKED.has(ip)) return `${ip} is on the core blocklist (always refused)`;
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

/**
 * Policy for flow-config URLs (http actions, waitFor readiness): the configured URL's own host:port is the only
 * allowlisted host, and its first resolved address is the only private/loopback exception. Redirects to anything
 * else fail the allowlist; the core blocklist and metadata rules apply as everywhere.
 */
export async function flowPolicy(url: string, resolver: Resolver = defaultResolver, timeoutMs = 10_000): Promise<ReplayConfig> {
  const u = new URL(url);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const ip = norm(isIP(host) ? host : await resolver(host));
  const cidr = isIP(ip) ? [`${ip}/${isIP(ip) === 6 ? 128 : 32}`] : [];
  return { allowHosts: [u.host], allowCidrs: cidr, timeoutMs, maxBodyBytes: 1024 * 1024 };
}
