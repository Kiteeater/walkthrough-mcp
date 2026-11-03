import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { hostname, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, WalkthroughCore, type Check, type Sandbox } from "../src/core/index.js";
import { acquireFileLock } from "../src/core/lockfile.js";
import { SB } from "./helpers.js";

let srv: http.Server, port = 0;
beforeAll(async () => {
  srv = http.createServer((req, res) => {
    res.writeHead(req.url === "/api/v1/alerts" ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "success", data: { alerts: [{ labels: { alertname: "HighOrders5xx", route: "/api/orders" }, annotations: {}, state: "firing", activeAt: "2026-10-12T20:00:00Z" }] } }));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const orders: Check = { id: "orders", intent: "GET /api/orders 2xx", method: "http", target: "GET /api/orders", expect: { type: "status", value: 200 }, severity_if_fail: "high", alertMatchers: [{ alertname: "HighOrders5xx" }] };
function mk(root = mkdtempSync(join(tmpdir(), "wt-life-"))) {
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, out) => writeFileSync(out, "png") }, redactor: Redactor.fromEnv(process.env),
    replay: { allowHosts: [`127.0.0.1:${port}`], allowCidrs: ["127.0.0.1/32"] }, prometheus: { url: `http://127.0.0.1:${port}`, timeoutMs: 2000 }, env: {},
  });
  return { core, root };
}
const sha = (f: string) => createHash("sha256").update(readFileSync(f)).digest("hex");
const tail = (core: WalkthroughCore, id: string) => { const f = join(core.dir(id), "commands.jsonl"); return existsSync(f) ? readFileSync(f, "utf8") : ""; };


// importReview carrying a sign-off must close open watches exactly like signOff does (same order, same fields).
const signedWith = async (how: "signOff" | "importReview") => {
  const { core } = mk();
  const id = core.startWalkthrough({ title: "t", sandbox: SB }).id;
  await core.planChecks(id, { goal: "g", checks: [orders] });
  const watch = await core.startWatch(id, { windowS: 30, intervalS: 1 }); // in-process poller
  expect(core.pollers.has(watch.id)).toBe(true);
  if (how === "signOff") await core.signOff(id, { decision: "reject", comment: "c" });
  else await core.importReview({ walkthroughId: id, signoff: { decision: "reject", comment: "c" } });
  const w = core.load(id);
  return { core, id, watch, w, state: core.readWatch(watch.id) };
};
const shape = (r: Awaited<ReturnType<typeof signedWith>>) => ({
  pollerRunning: r.core.pollers.has(r.watch.id),
  watchStatus: r.state.status,
  alertWatches: (r.w.alertWatches ?? []).map((a) => ({ watchId: a.watchId === r.watch.id ? "<watch>" : a.watchId, finalizedBy: a.finalizedBy, outcome: a.outcome })),
  signoff: { ...r.w.signoff, autoFinalizedWatches: r.w.signoff?.autoFinalizedWatches?.map((a) => ({ ...a, watchId: a.watchId === r.watch.id ? "<watch>" : a.watchId })) },
});

describe("sign-off via review import closes open watches", () => {
  it("importReview sign-off stops the poller and finalizes the watch exactly like signOff", async () => {
    const viaCli = shape(await signedWith("signOff"));
    expect(viaCli.pollerRunning).toBe(false);
    expect(viaCli.watchStatus).toBe("finalized");
    expect(viaCli.alertWatches).toEqual([{ watchId: "<watch>", finalizedBy: "sign_off", outcome: "stopped_early" }]);
    expect(shape(await signedWith("importReview"))).toEqual(viaCli);
  }, 20_000);
});

describe("save() refuses to overwrite any signed-off file", () => {
  it("a signed-off v2 walkthrough.json is not rewritten by a direct save; bytes unchanged", async () => {
    const { core } = mk();
    const id = core.startWalkthrough({ title: "t", sandbox: SB }).id;
    await core.signOff(id, { decision: "accept" });
    const file = join(core.dir(id), "walkthrough.json");
    expect(JSON.parse(readFileSync(file, "utf8")).schemaVersion).toBe(2);
    const before = sha(file);
    const w = core.load(id);
    w.title = "tampered";
    expect(() => core.save(w)).toThrow(/signed off; it is read-only/);
    expect(sha(file)).toBe(before);
  });
});
