#!/usr/bin/env node
// Checks the aliyun run_cli preset against the REAL aliyun CLI's help output (no credentials needed).
// For every allowed command prefix it runs `aliyun <prefix> --help --profile walkthrough-nonexistent` and asserts
// that the command exists (exit 0, no "unknown command"/"not a valid api") and that every allowlisted flag appears
// as a parameter in that help. Exit 1 on any mismatch. Used by the `aliyun-cli` CI job (versions pinned there).
//   node scripts/check-aliyun-preset.mjs            # uses dist/core/runcli.js (run `npm run build` first)
//   ALIYUN_BIN=/path/to/aliyun node scripts/check-aliyun-preset.mjs
//   ALIYUN_PRESET_JSON=file.json  # optional override {allow, args}: used to prove the check fails on a bad name
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const bin = process.env.ALIYUN_BIN || "aliyun";
let preset;
if (process.env.ALIYUN_PRESET_JSON) preset = JSON.parse(readFileSync(process.env.ALIYUN_PRESET_JSON, "utf8"));
else preset = (await import("../dist/core/runcli.js")).PRESET_CONNECTORS.find((c) => c.name === "aliyun");

/** Parameter flags listed by a help page: plugin text help ("Parameters:" section) or built-in JSON help (parameterSets). */
export function helpFlags(out) {
  const t = out.trim();
  if (t.startsWith("{")) {
    const j = JSON.parse(t);
    const set = j.parameterSets?.[j.activeParameterSet] ?? [];
    return new Set(set.filter((p) => p.location !== "body" && p.location !== "header").map((p) => `--${p.name}`));
  }
  const m = t.match(/\nParameters:\n([\s\S]*?)\n\s*\n?(?:Global Parameters:|Examples:|$)/);
  if (!m) return new Set();
  return new Set([...m[1].matchAll(/^ {2}(--[A-Za-z][\w-]*)/gm)].map((x) => x[1]));
}

const ver = spawnSync(bin, ["version"], { encoding: "utf8" });
console.log(`aliyun CLI: ${ver.stdout.trim() || ver.error}`);
let bad = 0;
for (const prefix of preset.allow) {
  const key = prefix.join(" ");
  const r = spawnSync(bin, [...prefix, "--help", "--profile", "walkthrough-nonexistent"], { encoding: "utf8" });
  const out = `${r.stdout}${r.stderr}`;
  if (r.status !== 0 || /unknown command|not a valid api/i.test(out)) {
    console.log(`FAIL ${key}: command not found in the real CLI (exit ${r.status}): ${out.trim().split("\n")[0]}`);
    bad++; continue;
  }
  let flags;
  try { flags = helpFlags(out); } catch (e) { console.log(`FAIL ${key}: cannot parse help: ${e.message}`); bad++; continue; }
  const missing = (preset.args?.[key] ?? []).filter((a) => !flags.has(a));
  if (missing.length) { console.log(`FAIL ${key}: allowlisted flag(s) not in help: ${missing.join(" ")} (help lists: ${[...flags].join(" ")})`); bad++; }
  else console.log(`ok   ${key}: ${(preset.args?.[key] ?? []).join(" ") || "(no args)"}`);
}
if (bad) { console.log(`\n${bad} mismatch(es) between the aliyun preset and the real CLI`); process.exit(1); }
console.log(`\nall ${preset.allow.length} aliyun preset commands match the real CLI`);
