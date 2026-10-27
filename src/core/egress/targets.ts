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

/** Throw CoreBlockedError if any token names, or resolves to, a core-blocked address. Unresolvable names (error, timeout, no address) are refused too. */
export async function assertNoCoreBlockedTargets(tokens: string[], resolveAll: ResolveAll = defaultResolveAll, timeoutMs = 3_000): Promise<Map<string, string[]>> {
  const checked = new Map<string, string[]>();
  for (const t of tokens) for (const ip of CORE_BLOCKED_IPS) if (t.includes(ip)) throw new CoreBlockedError(`target ${ip} is on the core blocklist (always refused)`);
  const hosts = [...new Set(tokens.flatMap(hostCandidates))];
  for (const h of hosts) await resolveChecked(h, checked, resolveAll, timeoutMs);
  return checked;
}

/**
 * Resolve `h` once (cached in `checked`) and refuse it if it cannot be resolved in time, resolves to nothing, or any
 * address is core-blocked. Fail closed: the connector CLI connects by itself (no guardedFetch / checkHop afterwards),
 * so this is the only check.
 */
async function resolveChecked(h: string, checked: Map<string, string[]>, resolveAll: ResolveAll, timeoutMs: number): Promise<string[]> {
  const hit = checked.get(h);
  if (hit) return hit;
  if (isIP(h)) {
    if (coreBlocked(h)) throw new CoreBlockedError(`target ${h} is on the core blocklist (always refused)`);
    checked.set(h, [h]);
    return [h];
  }
  let ips: string[];
  try {
    ips = await Promise.race([resolveAll(h), new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error(`timed out after ${timeoutMs} ms`)), timeoutMs).unref())]);
  } catch (e) {
    throw new CoreBlockedError(`target ${h} could not be resolved to check it against the core blocklist (${(e as Error).message}); refused`);
  }
  if (!ips.length) throw new CoreBlockedError(`target ${h} resolved to no address; cannot check it against the core blocklist; refused`);
  const bad = ips.find(coreBlocked);
  if (bad) throw new CoreBlockedError(`target ${h} resolves to ${bad}, which is on the core blocklist (always refused)`);
  checked.set(h, ips);
  return ips;
}

/**
 * Name server pinning (connectors with `namesrvs`, i.e. plain `host:port` TCP targets): replace the host of every
 * `-n` value with the address resolved and checked by assertNoCoreBlockedTargets, so the CLI never resolves the name
 * itself and a second DNS answer (rebinding) cannot reach the CLI.
 */
export async function pinNamesrvArgv(argv: string[], checked: Map<string, string[]>, resolveAll: ResolveAll = defaultResolveAll, timeoutMs = 3_000): Promise<string[]> {
  const pin = async (v: string): Promise<string> => {
    const m = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(v);
    if (!m) throw new CoreBlockedError(`name server ${JSON.stringify(v)} is not host:port; cannot pin it to a checked address`);
    const host = m[1].replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
    const [ip] = await resolveChecked(host, checked, resolveAll, timeoutMs); // reuses the answer already checked, if any
    return `${isIP(ip) === 6 ? `[${ip}]` : ip}:${m[2]}`;
  };
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    out.push(argv[i - 1] === "-n" ? await pin(a) : a.startsWith("-n=") ? `-n=${await pin(a.slice(3))}` : a);
  }
  return out;
}
