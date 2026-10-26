// Core-executed replay of one GET/HEAD request taken from a HAR. SSRF-hardened:
// host allowlist, IP policy checked on the address we actually connect to (DNS resolved once per hop and pinned),
// no automatic redirects (each hop re-checked), HAR cookies/auth never forwarded.
import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { createHash, randomBytes } from "node:crypto";

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
const CORE_BLOCKED = new Set(CORE_BLOCKED_IPS);
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

export interface ReplayHop { url: string; ip: string; status: number }
export interface ReplayResult {
  method: string; url: string; status: number; headers: Record<string, string>; body: string; hops: ReplayHop[];
  /** Credential values actually sent (callers must redact them from anything they store). */
  sentSecrets: string[];
  /** The body exceeded maxBodyBytes and was cut. */
  truncated: boolean;
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
  opts: { resolver?: Resolver; env?: NodeJS.ProcessEnv; hopCheck?: (url: URL) => void } = {},
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
    opts.hopCheck?.(url);
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
    return { method, url: input.url, status: r.status, headers: r.headers, body: r.body, hops, sentSecrets: [...new Set(sent)], truncated: r.truncated };
  }
}

async function send(url: URL, method: string, headers: Record<string, string>, ip: string, cfg: ReplayConfig): Promise<{ status: number; headers: Record<string, string>; body: string; truncated: boolean }> {
  const r = await sendRaw(url, method, headers, ip, cfg);
  return { status: r.status, headers: r.headers, body: r.body.toString("utf8"), truncated: r.truncated };
}

/**
 * One policy-checked, IP-pinned request of any method with a raw body (capture_page sub-resources). No redirect
 * following; the caller re-checks each hop. Throws ReplayRejectedError on a policy violation (nothing sent).
 */
export async function guardedRequest(cfg: ReplayConfig, url: string, o: { method?: string; headers?: Record<string, string>; body?: Buffer; resolver?: Resolver; maxBodyBytes?: number } = {}): Promise<{ status: number; headers: Record<string, string>; body: Buffer; ip: string; truncated: boolean }> {
  const u = new URL(url);
  const ip = await checkHop(cfg, u, o.resolver);
  const r = await sendRaw(u, (o.method ?? "GET").toUpperCase(), o.headers ?? {}, ip, { ...cfg, maxBodyBytes: o.maxBodyBytes ?? cfg.maxBodyBytes }, o.body);
  return { ...r, ip };
}

function sendRaw(url: URL, method: string, headers: Record<string, string>, ip: string, cfg: ReplayConfig, reqBody?: Buffer): Promise<{ status: number; headers: Record<string, string>; body: Buffer; truncated: boolean }> {
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
        clearTimeout(deadline);
        resolveP({ status: res.statusCode ?? 0, headers: h, body: Buffer.concat(chunks), truncated: n > cap });
      });
      res.on("error", reject);
    });
    // Re-check the actual peer before any byte is written.
    req.on("socket", (s) => s.once("connect", () => { const r = norm(s.remoteAddress ?? ""); if (r !== norm(ip)) req.destroy(new ReplayRejectedError(`connected to ${r}, expected ${ip}`)); }));
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    // Overall deadline (the socket timeout above only covers idle periods).
    const deadline = setTimeout(() => req.destroy(new Error(`request timed out after ${cfg.timeoutMs ?? 10_000} ms`)), cfg.timeoutMs ?? 10_000);
    req.on("close", () => clearTimeout(deadline));
    req.on("error", reject);
    req.end(reqBody);
  });
}

/** One open WebSocket made by walkthrough itself (issue #18): policy-checked + IP-pinned like guardedRequest. */
export interface GuardedWebSocket {
  ip: string;
  send(data: string | Buffer): void;
  onMessage(cb: (data: string | Buffer) => void): void;
  onClose(cb: (code: number) => void): void;
  close(code?: number): void;
}

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_WS_FRAME = 16 * 1024 * 1024;

function wsEncode(op: number, payload: Buffer): Buffer {
  const mask = randomBytes(4), n = payload.length;
  const head = n < 126 ? Buffer.from([0x80 | op, 0x80 | n]) : n < 65536 ? Buffer.from([0x80 | op, 0x80 | 126, n >> 8, n & 0xff]) : (() => { const b = Buffer.alloc(10); b[0] = 0x80 | op; b[1] = 0x80 | 127; b.writeBigUInt64BE(BigInt(n), 2); return b; })();
  const body = Buffer.alloc(n); for (let i = 0; i < n; i++) body[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([head, mask, body]);
}

/**
 * ws:// or wss:// URL judged exactly like http(s) (scheme mapped, allowlist, IP rules, ONE resolution, pinned
 * connection, peer re-checked). Minimal RFC 6455 client: text/binary, fragmentation, ping/pong, close.
 */
export async function guardedWebSocket(cfg: ReplayConfig, url: string, o: { resolver?: Resolver; headers?: Record<string, string> } = {}): Promise<GuardedWebSocket> {
  const u = new URL(url);
  if (u.protocol !== "ws:" && u.protocol !== "wss:") throw new ReplayRejectedError(`unsupported websocket scheme ${u.protocol}`);
  const hu = new URL(url); hu.protocol = u.protocol === "wss:" ? "https:" : "http:";
  const ip = await checkHop(cfg, hu, o.resolver);
  const key = randomBytes(16).toString("base64");
  const mod = hu.protocol === "https:" ? https : http;
  const fam = isIP(ip);
  const sock = await new Promise<import("node:net").Socket>((resolveP, reject) => {
    const req = mod.request({
      method: "GET", protocol: hu.protocol, hostname: hu.hostname.replace(/^\[|\]$/g, ""), port: hu.port || undefined, path: hu.pathname + hu.search,
      headers: { ...(o.headers ?? {}), host: hu.host, connection: "Upgrade", upgrade: "websocket", "sec-websocket-version": "13", "sec-websocket-key": key, "user-agent": "walkthrough-page/1" },
      servername: isIP(hu.hostname) ? undefined : hu.hostname,
      lookup: ((_h: string, lo: { all?: boolean }, cb: (...a: unknown[]) => void) => lo?.all ? cb(null, [{ address: ip, family: fam }]) : cb(null, ip, fam)) as never,
      agent: false, timeout: cfg.timeoutMs ?? 10_000,
    });
    req.on("socket", (s) => s.once("connect", () => { const r = norm(s.remoteAddress ?? ""); if (r !== norm(ip)) req.destroy(new ReplayRejectedError(`connected to ${r}, expected ${ip}`)); }));
    req.on("upgrade", (res, s, head) => {
      const want = createHash("sha1").update(key + WS_GUID).digest("base64");
      if (res.headers["sec-websocket-accept"] !== want) { s.destroy(); return reject(new Error("websocket handshake failed (bad Sec-WebSocket-Accept)")); }
      if (head?.length) s.unshift(head);
      resolveP(s);
    });
    req.on("response", (res) => { res.resume(); reject(new Error(`websocket handshake refused (HTTP ${res.statusCode})`)); });
    req.on("timeout", () => req.destroy(new Error("websocket handshake timed out")));
    req.on("error", reject);
    req.end();
  });
  sock.setTimeout(0);
  const msgCbs: ((d: string | Buffer) => void)[] = [], closeCbs: ((c: number) => void)[] = [];
  let buf = Buffer.alloc(0), frag: Buffer[] = [], fragOp = 0, closed = false;
  const finish = (code: number) => { if (closed) return; closed = true; for (const cb of closeCbs) cb(code); sock.destroy(); };
  sock.on("data", (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0, op = buf[0] & 0x0f, masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; const big = buf.readBigUInt64BE(2); if (big > BigInt(MAX_WS_FRAME)) return finish(1009); len = Number(big); off = 10; }
      if (len > MAX_WS_FRAME) return finish(1009);
      const mk = masked ? buf.subarray(off, off + 4) : undefined; if (masked) off += 4;
      if (buf.length < off + len) return;
      let p = Buffer.from(buf.subarray(off, off + len)); buf = buf.subarray(off + len);
      if (mk) p = Buffer.from(p.map((x, i) => x ^ mk[i % 4]));
      if (op === 0x8) { if (!closed) sock.write(wsEncode(0x8, p.subarray(0, 2))); return finish(p.length >= 2 ? p.readUInt16BE(0) : 1005); }
      if (op === 0x9) { sock.write(wsEncode(0xa, p)); continue; }
      if (op === 0xa) continue;
      if (op === 0x1 || op === 0x2) { fragOp = op; frag = [p]; } else if (op === 0x0) frag.push(p); else return finish(1002);
      if (fin) { const all = Buffer.concat(frag); frag = []; const m = fragOp === 0x1 ? all.toString("utf8") : all; for (const cb of msgCbs) cb(m); }
    }
  });
  sock.on("close", () => finish(1006));
  sock.on("error", () => finish(1006));
  return {
    ip,
    send: (data) => { if (!closed) sock.write(wsEncode(typeof data === "string" ? 0x1 : 0x2, typeof data === "string" ? Buffer.from(data) : data)); },
    onMessage: (cb) => { msgCbs.push(cb); },
    onClose: (cb) => { closeCbs.push(cb); },
    close: (code = 1000) => { if (closed) return; const b = Buffer.alloc(2); b.writeUInt16BE(code); sock.write(wsEncode(0x8, b)); finish(code); },
  };
}
