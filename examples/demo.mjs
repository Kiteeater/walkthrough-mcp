#!/usr/bin/env node
// `npm run demo`: from zero — in-process MongoDB (mongodb-memory-server; `--docker` starts a throwaway container on a
// random loopback port; an explicit $MONGO_URL is guarded: only db walkthrough_demo is wiped), mock Langfuse, mock Prometheus and the buggy orders service. The trace agent runs the whole
// flow (plan_checks → start_watch → trigger → evidence → evaluate_check → collect_watch → report) and this prints
// where the audit page is. Everything shuts down at the end (or on Ctrl-C).
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { relative } from "node:path";

const args = process.argv.slice(2);
console.log(`walkthrough 演示：正在启动${args.includes("--docker") || process.env.MONGO_URL ? (process.env.MONGO_URL ? "外部 MongoDB（MONGO_URL）" : "一次性 MongoDB 容器") : "进程内 MongoDB"}、模拟 Langfuse、模拟 Prometheus 和订单服务（端口随机分配）…`);
const child = spawn(process.execPath, ["examples/trace-demo/run.mjs", ".", ...args], { stdio: ["ignore", "pipe", "inherit"] });
let out = "";
child.stdout.on("data", (d) => { out += d; });
for (const sig of ["SIGINT", "SIGTERM"]) process.once(sig, () => child.kill(sig));
const code = await new Promise((r) => child.on("exit", (c) => r(c ?? 1)));
if (code !== 0) { process.stderr.write(out); console.error(`演示失败（退出码 ${code}）`); process.exit(code); }
const last = out.trim().split("\n").at(-1);
const { id, html } = JSON.parse(last);
const w = JSON.parse(readFileSync(html.replace(/index\.html$/, "walkthrough.json"), "utf8"));
const page = readFileSync(html, "utf8");
const headline = /<div class="headline"[^>]*>([\s\S]*?)<\/div>/.exec(page)?.[1].replace(/<[^>]+>/g, "") ?? "";
const sub = /<div class="headline-sub"[^>]*>([\s\S]*?)<\/div>/.exec(page)?.[1].replace(/<[^>]+>/g, "");
console.log(`\n${headline}`);
if (sub) console.log(sub);
console.log(`检查 ${(w.checkResults ?? []).length} 项，问题 ${(w.findings ?? []).length} 个，walkthrough ${id}`);
console.log(`完整报告（浏览器打开）：${relative(process.cwd(), html) || html}`);
