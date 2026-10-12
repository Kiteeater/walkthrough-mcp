#!/usr/bin/env node
// `npm run demo`: from zero — in-process MongoDB (mongodb-memory-server; `--docker` uses a running container on
// 27017 or $MONGO_URL), mock Langfuse, mock Prometheus and the buggy orders service. The trace agent runs the whole
// flow (plan_checks → start_watch → trigger → evidence → evaluate_check → collect_watch → report) and this prints
// where the audit page is. Everything shuts down at the end (or on Ctrl-C).
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
console.log(`walkthrough demo: starting ${args.includes("--docker") ? "MongoDB (docker / MONGO_URL)" : "in-process MongoDB"}, mock Langfuse, mock Prometheus, orders service…`);
const child = spawn(process.execPath, ["examples/trace-demo/run.mjs", ".", ...args], { stdio: ["ignore", "pipe", "inherit"] });
let out = "";
child.stdout.on("data", (d) => { out += d; });
for (const sig of ["SIGINT", "SIGTERM"]) process.once(sig, () => child.kill(sig));
const code = await new Promise((r) => child.on("exit", (c) => r(c ?? 1)));
if (code !== 0) { process.stderr.write(out); console.error(`demo failed (exit ${code})`); process.exit(code); }
const last = out.trim().split("\n").at(-1);
const { id, html } = JSON.parse(last);
const w = JSON.parse(readFileSync(html.replace(/index\.html$/, "walkthrough.json"), "utf8"));
const page = readFileSync(html, "utf8");
const headline = /<div class="headline"[^>]*>([\s\S]*?)<\/div>/.exec(page)?.[1].replace(/<[^>]+>/g, "") ?? "";
console.log(`\n${headline}`);
console.log(`checks: ${(w.checkResults ?? []).length}, findings: ${(w.findings ?? []).length}, walkthrough ${id}`);
console.log(`audit page: ${html}`);
