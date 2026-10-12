// Cross-process lock for walkthrough writes (MCP server, one-shot CLI, detached pollers).
import { closeSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";

export const LOCK_STALE_MS = 10 * 60_000;
export interface LockInfo { pid: number; host: string; ts: number }

const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; } };
/** Stale = owner on this host is dead, or the lock is older than staleMs (covers other hosts / garbage). */
export function lockIsStale(raw: string, now = Date.now(), staleMs = LOCK_STALE_MS): boolean {
  let info: LockInfo;
  try { info = JSON.parse(raw) as LockInfo; } catch { return false; } // half-written by a live creator: wait
  if (info.host === hostname() && Number.isInteger(info.pid) && info.pid > 0 && !alive(info.pid)) return true;
  return !(now - Number(info.ts) < staleMs);
}

/**
 * Acquire: atomic O_EXCL create holding {pid, host, ts}. A stale lock is reclaimed atomically: rename it to a unique
 * name (only one waiter's rename can succeed), re-check that what we moved is the stale content we judged; if a fresh
 * lock was moved by mistake it is put back with link() (fails rather than clobbering). Bounded wait, clear error.
 */
export async function acquireFileLock(file: string, o: { timeoutMs?: number; staleMs?: number } = {}): Promise<() => void> {
  mkdirSync(dirname(file), { recursive: true });
  const end = Date.now() + (o.timeoutMs ?? 30_000);
  const mine = JSON.stringify({ pid: process.pid, host: hostname(), ts: Date.now() } satisfies LockInfo);
  for (;;) {
    try {
      const fd = openSync(file, "wx");
      try { writeSync(fd, mine); } finally { closeSync(fd); }
      return () => { try { if (readFileSync(file, "utf8") === mine) unlinkSync(file); } catch { /* gone */ } };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    let raw = "";
    try { raw = readFileSync(file, "utf8"); } catch { continue; } // released meanwhile
    if (lockIsStale(raw, Date.now(), o.staleMs)) {
      const moved = `${file}.stale-${randomBytes(6).toString("hex")}`;
      try { renameSync(file, moved); } catch { continue; } // another waiter reclaimed first
      const got = (() => { try { return readFileSync(moved, "utf8"); } catch { return ""; } })();
      if (got !== raw) { try { linkSync(moved, file); } catch { /* a new lock exists; the moved one is lost but was fresh only if just created */ } }
      try { unlinkSync(moved); } catch { /* ignore */ }
      continue;
    }
    if (Date.now() > end) {
      let who = raw; try { const i = JSON.parse(raw) as LockInfo; who = `pid ${i.pid} on ${i.host} since ${new Date(i.ts).toISOString()}`; } catch { /* raw */ }
      throw new Error(`timed out after ${o.timeoutMs ?? 30_000} ms waiting for walkthrough lock ${file} (held by ${who})`);
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}
