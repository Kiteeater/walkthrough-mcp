// Where the trace demo's MongoDB comes from, and the guard that keeps it from wiping somebody else's data.
//   default            in-process mongodb-memory-server
//   --docker           a throwaway container we start ourselves (random host port on 127.0.0.1, removed on exit)
//   MONGO_URL=…        an external Mongo you point at explicitly: only the demo database may be wiped
// The demo only ever uses the database `walkthrough_demo`.
import { execFileSync } from "node:child_process";

export const DEMO_DB = "walkthrough_demo";
export const MONGO_IMAGE = "mongo:7";

export class DemoMongoRefused extends Error { constructor(m) { super(m); this.name = "DemoMongoRefused"; } }

/** Database the demo would write to: URL path, else WALKTHROUGH_DEMO_DB, else walkthrough_demo. */
export function demoDbName(env, url) {
  let fromUrl = "";
  if (url) { try { fromUrl = decodeURIComponent(new URL(url).pathname.replace(/^\//, "")); } catch { throw new DemoMongoRefused(`MONGO_URL is not a valid URL`); } }
  return fromUrl || env.WALKTHROUGH_DEMO_DB || DEMO_DB;
}

/**
 * Decide the mode and check the wipe guard BEFORE anything connects or writes.
 * External Mongo: wiping is allowed only for the walkthrough_demo database or with WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE=1.
 */
export function planDemoMongo(args, env) {
  const url = env.MONGO_URL;
  if (url) {
    const db = demoDbName(env, url);
    if (db !== DEMO_DB && env.WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE !== "1")
      throw new DemoMongoRefused(`refusing to wipe database "${db}" on MONGO_URL: the demo only wipes "${DEMO_DB}" (set WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE=1 to override)`);
    return { mode: "external", url, db };
  }
  const db = demoDbName(env);
  if (db !== DEMO_DB && env.WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE !== "1") throw new DemoMongoRefused(`refusing to use database "${db}": the demo only uses "${DEMO_DB}"`);
  return { mode: args.includes("--docker") ? "docker" : "memory", db };
}

/** docker run args: detached, --rm, published to a RANDOM host port on loopback only (never a fixed 27017). */
export function dockerRunArgs(name) {
  return ["run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::27017", MONGO_IMAGE];
}

/** Wait until the server answers a ping (real MongoClient by default). */
export async function pingMongo(url, timeoutMs) {
  const { MongoClient } = await import("mongodb");
  const end = Date.now() + timeoutMs;
  let last;
  while (Date.now() < end) {
    const c = new MongoClient(url, { serverSelectionTimeoutMS: 2000 });
    try { await c.db("admin").command({ ping: 1 }); return; } catch (e) { last = e; } finally { await c.close().catch(() => undefined); }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(String(last?.message ?? "timeout"));
}

/**
 * Start a throwaway container, register its removal (exit + SIGINT/SIGTERM) and wait until it is ready.
 * Any failure → DemoMongoRefused with what is missing; there is NO fallback to localhost:27017 or any default.
 * `exec`, `ping` and `onCleanup` are injectable for tests.
 */
export async function startDockerMongo({ exec = (cmd, a) => execFileSync(cmd, a, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), ping = pingMongo, onCleanup, waitMs = 60_000 } = {}) {
  const name = `walkthrough-demo-mongo-${process.pid}-${Date.now().toString(36)}`;
  const why = (e) => String(e?.stderr || e?.message || e).trim().split("\n")[0];
  try { exec("docker", ["version", "--format", "{{.Server.Version}}"]); } catch (e) {
    if (e?.code === "ENOENT") throw new DemoMongoRefused("docker not found: install Docker, or run the demo without --docker (in-process MongoDB)");
    throw new DemoMongoRefused(`docker is not usable (is the daemon running?): ${why(e)}`);
  }
  let id;
  try { id = exec("docker", dockerRunArgs(name)).trim(); } catch (e) { throw new DemoMongoRefused(`container failed to start: ${why(e)}`); }
  let removed = false;
  const remove = () => { if (removed) return; removed = true; try { exec("docker", ["rm", "-f", id]); } catch { /* already gone */ } };
  onCleanup(remove);
  let out = "";
  try { out = exec("docker", ["port", id, "27017/tcp"]).trim().split("\n")[0]; } catch (e) { remove(); throw new DemoMongoRefused(`container failed to start: ${why(e)}`); }
  const m = /:(\d+)$/.exec(out);
  if (!m) { remove(); throw new DemoMongoRefused(`container failed to start: no published port (${out || "empty"})`); }
  const url = `mongodb://127.0.0.1:${m[1]}`;
  try { await ping(url, waitMs); } catch (e) { remove(); throw new DemoMongoRefused(`container failed to become ready on ${url}: ${why(e)}`); }
  return { url, id, name, remove };
}
