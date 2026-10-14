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

// Minimal env so help output does not depend on the caller (the CLI switches to JSON help when it detects an agent
// environment). No credentials are ever passed.
const env = { HOME: process.env.HOME, PATH: process.env.PATH, LANG: "C" };

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
  // Text help: plugin commands use "Parameters:", built-in commands "Required Parameters:" / "Optional Parameters:".
  // Flags are the 2-space-indented "--Name" lines inside those sections (not "Global Parameters:").
  const flags = new Set();
  let inParams = false;
  for (const line of t.split("\n")) {
    if (/^\S/.test(line)) inParams = /^(Required |Optional )?Parameters:$/.test(line.trim());
    else if (inParams) { const m = line.match(/^ {2}(--[A-Za-z][\w-]*)/); if (m) flags.add(m[1]); }
  }
  return flags;
}

const ver = spawnSync(bin, ["version"], { encoding: "utf8", env });
console.log(`aliyun CLI: ${ver.stdout.trim() || ver.error}`);
let bad = 0;
for (const prefix of preset.allow) {
  const key = prefix.join(" ");
  const r = spawnSync(bin, [...prefix, "--help", "--profile", "walkthrough-nonexistent"], { encoding: "utf8", env });
  const out = `${r.stdout}${r.stderr}`;
  if (r.status !== 0 || /unknown command|not a valid api/i.test(out)) {
    console.log(`FAIL command "aliyun ${key}": not found in the real CLI (exit ${r.status}): ${out.trim().split("\n")[0]}`);
    bad++; continue;
  }
  let flags;
  try { flags = helpFlags(out); } catch (e) { console.log(`FAIL command "aliyun ${key}": cannot parse help: ${e.message}`); bad++; continue; }
  const args = preset.args?.[key] ?? [];
  for (const a of args.filter((x) => x === "--body")) { console.log(`FAIL command "aliyun ${key}": flag ${a} must never be allowlisted (raw JSON body)`); bad++; }
  const missing = args.filter((a) => !flags.has(a));
  for (const a of missing) console.log(`FAIL command "aliyun ${key}": flag ${a} is allowlisted but not in the real CLI's help`);
  if (missing.length) { console.log(`     (help for "aliyun ${key}" lists: ${[...flags].join(" ")})`); bad += missing.length; }
  else console.log(`ok   aliyun ${key}: ${args.join(" ") || "(no args)"}`);
}
if (bad) { console.log(`\n${bad} problem(s) between the aliyun preset and the real CLI (each listed above with its command and flag)`); process.exit(1); }
console.log(`\nall ${preset.allow.length} aliyun preset commands match the real CLI`);
