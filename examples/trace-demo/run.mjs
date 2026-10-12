#!/usr/bin/env node
// Brings up a real MongoDB (in-process by default, a throwaway container with --docker, or an explicit $MONGO_URL —
// see mongo-demo.mjs for the wipe guard; only db walkthrough_demo is used) and a mock Langfuse,
// seeds data, then runs the trace demo agent. Prints the walkthrough result JSON on the last line.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MongoClient } from "mongodb";
import { startMockLangfuse } from "./mock-langfuse.mjs";
import { startMockPrometheus } from "./mock-prometheus.mjs";
import { DemoMongoRefused, planDemoMongo, startDockerMongo } from "./mongo-demo.mjs";

const args = process.argv.slice(2);
const root = args.find((a) => !a.startsWith("--")) ?? ".";
let plan;
try { plan = planDemoMongo(args, process.env); } catch (e) {
  if (e instanceof DemoMongoRefused) { console.error(e.message); process.exit(2); } // before any connection or write
  throw e;
}
const cleanups = [];
const runCleanups = async () => { for (const f of cleanups.splice(0).reverse()) { try { await f(); } catch { /* best effort */ } } };
for (const sig of ["SIGINT", "SIGTERM"]) process.once(sig, async () => { await runCleanups(); process.exit(130); });
process.once("exit", () => { for (const f of cleanups.splice(0).reverse()) { try { f(); } catch { /* sync best effort */ } } });
let url = plan.url;
if (plan.mode === "memory") { const { MongoMemoryServer } = await import("mongodb-memory-server"); const mms = await MongoMemoryServer.create(); cleanups.push(() => mms.stop()); url = mms.getUri(); }
if (plan.mode === "docker") {
  try { const d = await startDockerMongo({ onCleanup: (f) => cleanups.push(f) }); url = d.url; console.error(`started throwaway mongo container ${d.name} on ${url}`); }
  catch (e) { await runCleanups(); console.error(e instanceof DemoMongoRefused ? e.message : `container failed to start: ${e.message}`); process.exit(2); }
}
const c = new MongoClient(url, { serverSelectionTimeoutMS: 30_000 });
const orders = c.db(plan.db).collection("orders");
await orders.deleteMany({});
await orders.insertMany([
  { _id: "ord-1", customer: "ada", items: [{ sku: "pen", price: 2.5, qty: 4 }] },
  { _id: "ord-3", customer: "kai", legacyTotal: 12 },
]);
await c.close();
const pk = "pk-lf-demo", sk = process.env.LANGFUSE_SECRET_KEY ?? `sk-lf-demo-${Math.random().toString(36).slice(2)}`;
// No fixed ports: mocks listen on 0 (the OS picks a free port), the service gets a free port found the same way.
const freePort = () => new Promise((res, rej) => { const s = createServer(); s.once("error", rej); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const svcPort = Number(process.env.DEMO_SERVICE_PORT) || await freePort();
const serviceUrl = `http://127.0.0.1:${svcPort}`;
const lf = await startMockLangfuse(0, pk, sk);
const lfUrl = `http://127.0.0.1:${lf.address().port}`;
const promToken = process.env.WALKTHROUGH_PROMETHEUS_TOKEN ?? `prom-${Math.random().toString(36).slice(2)}`;
const prom = await startMockPrometheus(0, promToken, serviceUrl);
const promUrl = `http://127.0.0.1:${prom.address().port}`;
// The committed flow config has a ${SERVICE_URL} placeholder; the run uses a generated copy next to it (gitignored).
const here = dirname(fileURLToPath(import.meta.url));
const flowPath = join(here, "walkthrough.trace.generated.json");
writeFileSync(flowPath, readFileSync(join(here, "walkthrough.trace.json"), "utf8").replaceAll("${SERVICE_URL}", serviceUrl));
cleanups.push(() => { /* keep the generated config for inspection; it holds no secrets */ });
const env = { ...process.env, PORT: String(svcPort), MONGO_URL: url, MONGO_DB: plan.db, LANGFUSE_URL: lfUrl, LANGFUSE_PUBLIC_KEY: pk, LANGFUSE_SECRET_KEY: sk,
  WALKTHROUGH_PROMETHEUS_URL: promUrl, WALKTHROUGH_PROMETHEUS_TOKEN: promToken };
let child;
cleanups.push(() => lf.close(), () => prom.close(), () => { try { child?.kill("SIGTERM"); } catch { /* gone */ } });
child = spawn(process.execPath, ["dist/demo-agent/trace-run.js", flowPath, "--root", root], { env, stdio: ["ignore", "inherit", "inherit"] });
const code = await new Promise((r) => child.on("exit", (c) => r(c ?? 1)));
await runCleanups(); // finally: container removed / in-process server stopped
process.exit(code);
