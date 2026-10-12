#!/usr/bin/env node
// Brings up a real MongoDB (mongodb-memory-server, or $MONGO_URL if set, e.g. a CI docker mongo) and a mock Langfuse,
// seeds data, then runs the trace demo agent. Prints the walkthrough result JSON on the last line.
import { spawn } from "node:child_process";
import { MongoClient } from "mongodb";
import { startMockLangfuse } from "./mock-langfuse.mjs";

const root = process.argv[2] ?? ".";
let mms;
let url = process.env.MONGO_URL;
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
const env = { ...process.env, MONGO_URL: url, LANGFUSE_URL: "http://127.0.0.1:3100", LANGFUSE_PUBLIC_KEY: pk, LANGFUSE_SECRET_KEY: sk };
const child = spawn(process.execPath, ["dist/demo-agent/trace-run.js", "examples/trace-demo/walkthrough.trace.json", "--root", root], { env, stdio: ["ignore", "inherit", "inherit"] });
const code = await new Promise((r) => child.on("exit", (c) => r(c ?? 1)));
lf.close(); if (mms) await mms.stop();
process.exit(code);
