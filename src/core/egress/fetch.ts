// Guarded HTTP (moved from replay.ts): every request policy-checked via checkHop, IP-pinned, redirects manual.
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";
import { authFor, type ReplayConfig } from "../replay.js";
import { checkHop, defaultResolver, norm, ReplayRejectedError, type Resolver } from "./policy.js";

export interface ReplayHop { url: string; ip: string; status: number }
export interface ReplayResult {
  method: string; url: string; status: number; headers: Record<string, string>; body: string; hops: ReplayHop[];
  /** Credential values actually sent (callers must redact them from anything they store). */
  sentSecrets: string[];
  /** The body exceeded maxBodyBytes and was cut. */
  truncated: boolean;
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

/**
 * Same guarded path as replay for any method: checkHop + pinned IP per hop, redirects handled manually (never by
 * the HTTP client) and every hop re-checked. Throws ReplayRejectedError on a policy violation (nothing sent).
 */
export async function guardedFetch(cfg: ReplayConfig, url: string, o: { method?: string; headers?: Record<string, string>; body?: string; resolver?: Resolver; maxRedirects?: number } = {}): Promise<{ status: number; headers: Record<string, string>; body: string; hops: ReplayHop[] }> {
  let u = url, method = (o.method ?? "GET").toUpperCase(), body = o.body === undefined ? undefined : Buffer.from(o.body);
  const hops: ReplayHop[] = [];
  const max = o.maxRedirects ?? cfg.maxRedirects ?? 5;
  for (let i = 0; ; i++) {
    const r = await guardedRequest(cfg, u, { method, headers: o.headers, body, resolver: o.resolver });
    hops.push({ url: u, ip: r.ip, status: r.status });
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      if (i >= max) throw new ReplayRejectedError(`too many redirects (> ${max})`);
      u = new URL(r.headers.location, u).toString();
      if (r.status === 303 || ((r.status === 301 || r.status === 302) && method === "POST")) { method = "GET"; body = undefined; }
      continue;
    }
    return { status: r.status, headers: r.headers, body: r.body.toString("utf8"), hops };
  }
}
