#!/usr/bin/env node
// Brings up a real MongoDB (mongodb-memory-server, or $MONGO_URL if set, e.g. a CI docker mongo) and a mock Langfuse,
// seeds data, then runs the trace demo agent. Prints the walkthrough result JSON on the last line.
import { spawn } from "node:child_process";
import { MongoClient } from "mongodb";
import { startMockLangfuse } from "./mock-langfuse.mjs";
import { startMockPrometheus } from "./mock-prometheus.mjs";

const args = process.argv.slice(2);
const docker = args.includes("--docker"); // use an already running Mongo container instead of the in-process one
const root = args.find((a) => !a.startsWith("--")) ?? ".";
let mms;
let url = process.env.MONGO_URL ?? (docker ? "mongodb://127.0.0.1:27017" : undefined);
if (!url) { const { MongoMemoryServer } = await import("mongodb-memory-server"); mms = await MongoMemoryServer.create(); url = mms.getUri(); }
const c = new MongoClient(url);
await c.db("shop").collection("orders").deleteMany({});
await c.db("shop").collection("orders").insertMany([
  { _id: "ord-1", customer: "ada", items: [{ sku: "pen", price: 2.5, qty: 4 }] },
  { _id: "ord-3", customer: "kai", legacyTotal: 12 },
]);
await c.close();
const pk = "pk-lf-demo", sk = process.env.LANGFUSE_SECRET_KEY ?? `sk-lf-demo-${Math.random().toString(36).slice(2)}`;
const lf = await startMockLangfuse(3100, pk, sk);
const promToken = process.env.WALKTHROUGH_PROMETHEUS_TOKEN ?? `prom-${Math.random().toString(36).slice(2)}`;
const prom = await startMockPrometheus(3102, promToken);
const env = { ...process.env, MONGO_URL: url, LANGFUSE_URL: "http://127.0.0.1:3100", LANGFUSE_PUBLIC_KEY: pk, LANGFUSE_SECRET_KEY: sk,
  WALKTHROUGH_PROMETHEUS_URL: "http://127.0.0.1:3102", WALKTHROUGH_PROMETHEUS_TOKEN: promToken };
let child;
const cleanup = async () => { try { child?.kill("SIGTERM"); } catch { /* gone */ } lf.close(); prom.close(); if (mms) await mms.stop(); };
for (const sig of ["SIGINT", "SIGTERM"]) process.once(sig, async () => { await cleanup(); process.exit(130); });
child = spawn(process.execPath, ["dist/demo-agent/trace-run.js", "examples/trace-demo/walkthrough.trace.json", "--root", root], { env, stdio: ["ignore", "inherit", "inherit"] });
const code = await new Promise((r) => child.on("exit", (c) => r(c ?? 1)));
await cleanup();
process.exit(code);
