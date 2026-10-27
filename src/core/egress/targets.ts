// Core blocklist enforcement for outbound paths that do not go through checkHop (run_cli argv / connector targets,
// mongo URIs, flow http actions and readiness polling). checkHop itself refuses blocked IPs via ipProblem.
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { CORE_BLOCKED_IPS, coreBlocked } from "./policy.js";

export class CoreBlockedError extends Error {
  constructor(message: string) { super(message); this.name = "CoreBlockedError"; }
}

/** Resolve a hostname to ALL its addresses (default: system DNS). */
export type ResolveAll = (host: string) => Promise<string[]>;
export const defaultResolveAll: ResolveAll = async (h) => (await lookup(h, { all: true })).map((a) => a.address);

const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/i;

/** Host-like candidates inside one argv token / URI: URL hosts, mongo host lists, host:port, bare IPs/hostnames. */
export function hostCandidates(token: string): string[] {
  const out = new Set<string>();
  const add = (h: string) => { const x = h.trim().replace(/^\[|\]$/g, "").replace(/\.$/, ""); if (x) out.add(x.toLowerCase()); };
  for (const part of token.split(/[\s;=]+/)) {
    if (!part) continue;
    const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]*)/i.exec(part); // scheme://[userinfo@]host[,host…]
    const hosts = (m ? m[1] : part).split(",");
    for (const h of hosts) {
      const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(h);
      if (v6) { add(v6[1]); continue; }
      if (isIP(h)) { add(h); continue; }
      const hp = /^([^:]+):\d+$/.exec(h);
      add(hp ? hp[1] : h);
    }
  }
  // Any IPv4 literal anywhere in the token, even glued to other text.
  for (const ip of token.match(/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g) ?? []) add(ip);
  // Normalise like a URL parser / resolver would (579766055, 0x228e8727, 34.142.34599 → 34.142.135.39).
  const normed = [...out].map((h) => { try { return new URL(`http://${isIP(h) === 6 ? `[${h}]` : h}`).hostname.replace(/^\[|\]$/g, ""); } catch { return h; } });
  return [...new Set(normed)].filter((h) => isIP(h) || HOSTNAME.test(h));
}

/** Throw CoreBlockedError if any token names, or resolves to, a core-blocked address. Unresolvable names are ignored. */
export async function assertNoCoreBlockedTargets(tokens: string[], resolveAll: ResolveAll = defaultResolveAll, timeoutMs = 3_000): Promise<void> {
  for (const t of tokens) for (const ip of CORE_BLOCKED_IPS) if (t.includes(ip)) throw new CoreBlockedError(`target ${ip} is on the core blocklist (always refused)`);
  const hosts = [...new Set(tokens.flatMap(hostCandidates))];
  for (const h of hosts) {
    if (isIP(h)) { if (coreBlocked(h)) throw new CoreBlockedError(`target ${h} is on the core blocklist (always refused)`); continue; }
    let ips: string[] = [];
    try {
      ips = await Promise.race([resolveAll(h), new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs).unref())]);
    } catch { continue; }
    const bad = ips.find(coreBlocked);
    if (bad) throw new CoreBlockedError(`target ${h} resolves to ${bad}, which is on the core blocklist (always refused)`);
  }
}

/** Same check for one URL (flow http actions, readiness polling). */
export function assertUrlNotCoreBlocked(url: string, resolveAll: ResolveAll = defaultResolveAll): Promise<void> {
  let host: string;
  try { host = new URL(url).hostname; } catch { return Promise.resolve(); }
  return assertNoCoreBlockedTargets([host], resolveAll);
}
