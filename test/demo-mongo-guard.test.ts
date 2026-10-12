import { spawnSync } from "node:child_process";
import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error plain .mjs helper
import { DEMO_DB, DemoMongoRefused, dockerRunArgs, planDemoMongo, startDockerMongo } from "../examples/trace-demo/mongo-demo.mjs";

const RUN = "examples/trace-demo/run.mjs";
/** PATH with only node in it: no docker binary. */
function nodeOnlyPath(): string {
  const d = mkdtempSync(join(tmpdir(), "wt-path-"));
  symlinkSync(process.execPath, join(d, "node"));
  return d;
}
const runDemo = (args: string[], env: Record<string, string>) =>
  spawnSync(process.execPath, [RUN, ".", ...args], { encoding: "utf8", timeout: 20_000, env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env } });

describe("trace demo Mongo guard", () => {
  it("default db is walkthrough_demo; in-process default unchanged; --docker means our own container", () => {
    expect(DEMO_DB).toBe("walkthrough_demo");
    expect(planDemoMongo([], {})).toEqual({ mode: "memory", db: DEMO_DB });
    expect(planDemoMongo(["--docker"], {})).toEqual({ mode: "docker", db: DEMO_DB });
    expect(planDemoMongo(["--docker"], { MONGO_URL: "mongodb://h:1" })).toEqual({ mode: "external", url: "mongodb://h:1", db: DEMO_DB });
    expect(planDemoMongo([], { MONGO_URL: "mongodb://h:1/walkthrough_demo" }).db).toBe(DEMO_DB);
  });

  it("external Mongo with another db name is refused (URL path or WALKTHROUGH_DEMO_DB) unless explicitly allowed", () => {
    expect(() => planDemoMongo([], { MONGO_URL: "mongodb://h:1/shop" })).toThrow(/refusing to wipe database "shop"/);
    expect(() => planDemoMongo(["--docker"], { MONGO_URL: "mongodb://h:1", WALKTHROUGH_DEMO_DB: "prod" })).toThrow(DemoMongoRefused);
    expect(planDemoMongo([], { MONGO_URL: "mongodb://h:1/shop", WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE: "1" }).db).toBe("shop");
    expect(() => planDemoMongo([], { WALKTHROUGH_DEMO_DB: "shop" })).toThrow(/refusing to use database "shop"/);
  });

  it("run.mjs exits non-zero before any connection or write: wrong db name on MONGO_URL", () => {
    // Port 9 (discard) on loopback: a connection attempt would hang/fail slowly; the guard must exit first.
    const r = runDemo([], { MONGO_URL: "mongodb://127.0.0.1:9/shop" });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/refusing to wipe database "shop"/);
    expect(r.stderr).not.toMatch(/MongoServerSelectionError|ECONNREFUSED|started throwaway/);
  });

  it("run.mjs exits non-zero for WALKTHROUGH_DEMO_DB=shop with an external MONGO_URL (missing explicit allow)", () => {
    const r = runDemo(["--docker"], { MONGO_URL: "mongodb://127.0.0.1:9", WALKTHROUGH_DEMO_DB: "shop" });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/WALKTHROUGH_DEMO_ALLOW_MONGO_WIPE=1/);
  });

  it("--docker publishes to a random loopback port, never a fixed 27017, and registers cleanup before waiting", async () => {
    const args = dockerRunArgs("n");
    expect(args).toEqual(expect.arrayContaining(["run", "-d", "--rm", "-p", "127.0.0.1::27017"]));
    expect(args.join(" ")).not.toMatch(/(^|[\s:])27017:27017|0\.0\.0\.0|-p 27017/);
    const calls: string[][] = [], cleanups: (() => void)[] = [];
    let pinged = "";
    const r = await startDockerMongo({
      exec: (cmd: string, a: string[]) => { calls.push([cmd, ...a]); return a[0] === "run" ? "cid123\n" : a[0] === "port" ? "127.0.0.1:49321\n" : "24.0\n"; },
      ping: async (url: string) => { expect(cleanups).toHaveLength(1); pinged = url; },
      onCleanup: (f: () => void) => cleanups.push(f),
    });
    expect(r.url).toBe("mongodb://127.0.0.1:49321");
    expect(pinged).toBe("mongodb://127.0.0.1:49321");
    expect(r.url).not.toContain(":27017");
    cleanups[0]();
    expect(calls.at(-1)).toEqual(["docker", "rm", "-f", "cid123"]);
  });

  it("docker binary missing → non-zero exit, 'docker not found', no Mongo connection, no fallback", async () => {
    const pings: string[] = [];
    const enoent = Object.assign(new Error("spawn docker ENOENT"), { code: "ENOENT" });
    await expect(startDockerMongo({ exec: () => { throw enoent; }, ping: async (u: string) => { pings.push(u); }, onCleanup: () => undefined })).rejects.toThrow(/^docker not found/);
    expect(pings).toEqual([]);
    const r = runDemo(["--docker"], { PATH: nodeOnlyPath() });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/docker not found/);
    expect(r.stderr).not.toMatch(/27017|MongoServerSelectionError|ECONNREFUSED/);
  });

  it("container start failure → non-zero exit, 'container failed to start: <reason>', no connection, cleanup run", async () => {
    const pings: string[] = [], cleanups: (() => void)[] = [];
    const exec = (_c: string, a: string[]) => { if (a[0] === "run") throw Object.assign(new Error("exit 125"), { stderr: "docker: Error response from daemon: pull access denied\n" }); return "24.0\n"; };
    await expect(startDockerMongo({ exec, ping: async (u: string) => { pings.push(u); }, onCleanup: (f: () => void) => cleanups.push(f) }))
      .rejects.toThrow(/^container failed to start: docker: Error response from daemon: pull access denied$/);
    expect(pings).toEqual([]);
    // Not ready → container removed, clear message, still no fallback.
    const calls: string[][] = [];
    const exec2 = (c: string, a: string[]) => { calls.push([c, ...a]); return a[0] === "run" ? "cid9\n" : a[0] === "port" ? "127.0.0.1:50000\n" : "24.0\n"; };
    await expect(startDockerMongo({ exec: exec2, ping: async () => { throw new Error("server selection timed out"); }, onCleanup: () => undefined }))
      .rejects.toThrow(/container failed to become ready on mongodb:\/\/127\.0\.0\.1:50000: server selection timed out/);
    expect(calls.at(-1)).toEqual(["docker", "rm", "-f", "cid9"]);
    // End to end with a fake docker whose `run` fails.
    const bin = mkdtempSync(join(tmpdir(), "wt-fakedocker-"));
    const { writeFileSync, chmodSync } = await import("node:fs");
    writeFileSync(join(bin, "docker"), `#!/bin/sh\nif [ "$1" = run ]; then echo "Error: port is already allocated" >&2; exit 125; fi\necho 24.0\n`);
    chmodSync(join(bin, "docker"), 0o755);
    symlinkSync(process.execPath, join(bin, "node"));
    const r = runDemo(["--docker"], { PATH: `${bin}:${dirname("/bin/sh")}` });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/container failed to start: Error: port is already allocated/);
    expect(r.stderr).not.toMatch(/MongoServerSelectionError|ECONNREFUSED/);
  });
});
