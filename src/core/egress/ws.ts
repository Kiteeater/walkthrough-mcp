// Guarded WebSocket client (moved from replay.ts): same checkHop + IP pinning as HTTP.
import { isIP } from "node:net";
import http from "node:http";
import https from "node:https";
import { createHash, randomBytes } from "node:crypto";
import type { ReplayConfig } from "../replay.js";
import { checkHop, norm, ReplayRejectedError, type Resolver } from "./policy.js";

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
