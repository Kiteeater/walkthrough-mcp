// Static scan: outbound network, browser launch and child processes may only appear in the files that own them.
// Scope: src/** (core, mcp, cli AND demo-agent, which ships in dist) and examples/** (demo/dev scripts; scanned so
// new ones are noticed). scripts/ (CI tooling: test-gate, aliyun preset check) and test/ are NOT scanned.
// Every exception is ONE exact file path + rule, with a reason. No globs, no directory exemptions.
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

type Rule = "net" | "browser" | "process";
const RULES: { rule: Rule; re: RegExp }[] = [
  // bare fetch( (not .fetch( / a typed method signature `fetch(url: string`), node http/https/net/tls calls
  { rule: "net", re: /(?<![\w.$])fetch\s*\((?!\s*\w+\s*\??:)|\b(?:http2?|https|mod|net|tls|dgram)\.(?:request|get|connect|createConnection|createSocket)\s*\(|from\s+["'](?:node:)?(?:https?|http2|tls|dgram|undici)["']|require\(\s*["'](?:node:)?(?:https?|http2|tls|dgram|undici)["']\s*\)/ },
  { rule: "browser", re: /\b(?:chromium|firefox|webkit)\s*\.\s*(?:launch|launchPersistentContext|connect|connectOverCDP)\s*\(/ },
  { rule: "process", re: /\b(?:spawn|spawnSync|execFile|execFileSync|execSync|fork)\s*\(|from\s+["'](?:node:)?child_process["']|require\(\s*["'](?:node:)?child_process["']\s*\)/ },
];

/** Files allowed to contain a rule's pattern, by design. */
const OWNERS: Record<string, { rules: Rule[]; why: string }> = {
  "src/core/egress/fetch.ts": { rules: ["net"], why: "guarded HTTP: checkHop + IP pinning + manual redirects" },
  "src/core/egress/ws.ts": { rules: ["net"], why: "guarded WebSocket client: same checkHop + IP pinning" },
  "src/core/capture.ts": { rules: ["browser"], why: "browser launch; only called via WalkthroughCore.guardedPage, every request routed through the guard (not moved into egress/ in this PR)" },
  "src/core/sandbox.ts": { rules: ["process"], why: "sandbox up/down/exec: spawn(file,args), no shell, allowlisted env" },
  "src/core/runcli.ts": { rules: ["process"], why: "run_cli: allowlisted read-only CLIs (spawns through sandbox.run today)" },
};

/** KNOWN violations that exist today. Not fixed in this PR (move-only); new ones fail the test. */
const KNOWN: Record<string, { rules: Rule[]; why: string }> = {
  "src/core/alerts.ts": { rules: ["process"], why: "KNOWN: spawnDetachedPoller spawns `walkthrough watch _poll` with the full process.env (review: should go through sandbox/allowlistEnv)" },
  "src/demo-agent/trace-run.ts": { rules: ["net"], why: "KNOWN: direct fetch to LANGFUSE_URL, not through egress guard (fix later)" },
  "examples/demo.mjs": { rules: ["process"], why: "example launcher: spawns examples/trace-demo/run.mjs" },
  "examples/regen-output-trace.mjs": { rules: ["process"], why: "dev script: regenerates example output" },
  "examples/screenshot.mjs": { rules: ["browser"], why: "dev script: screenshots a local generated HTML report" },
  "examples/run-local-e2e.sh": { rules: ["browser"], why: "e2e script: screenshots the local report file" },
  "examples/ui-demo/run.mjs": { rules: ["process", "browser"], why: "demo: starts the local orders service and a browser on it" },
  "examples/trace-demo/run.mjs": { rules: ["process"], why: "demo: runs dist/demo-agent/trace-run.js" },
  "examples/trace-demo/mongo-demo.mjs": { rules: ["process"], why: "demo: docker for a throwaway local MongoDB" },
  "examples/trace-demo/mock-langfuse.mjs": { rules: ["net"], why: "local mock server (node:http server only)" },
  "examples/trace-demo/mock-prometheus.mjs": { rules: ["net"], why: "local mock server; fetches the demo service's local /metrics.json" },
  "examples/trace-demo/service/server.js": { rules: ["net"], why: "demo service: local http server, posts to the local mock Langfuse" },
  "examples/orders-service/server.js": { rules: ["net"], why: "demo service: local http server (browser fetch in served page)" },
};

const EXT = /\.(?:ts|mts|js|mjs|cjs|sh)$/;
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1").replace(/^\s*#(?!!).*$/gm, "");

/** Every (file, rule, line) hit under `dirs` of `root` that is not covered by `allowed`. */
export function scan(root: string, dirs: string[], allowed: Record<string, { rules: Rule[] }>): { file: string; rule: Rule; line: number; text: string }[] {
  const files: string[] = [];
  const walk = (d: string) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) { if (f !== "node_modules" && f !== "output" && f !== "output-trace") walk(p); } else if (EXT.test(f)) files.push(p); } };
  for (const d of dirs) walk(join(root, d));
  const out: { file: string; rule: Rule; line: number; text: string }[] = [];
  for (const p of files) {
    const file = relative(root, p).split("\\").join("/");
    const lines = stripComments(readFileSync(p, "utf8")).split("\n");
    for (const { rule, re } of RULES) {
      if (allowed[file]?.rules.includes(rule)) continue;
      lines.forEach((l, i) => { if (re.test(l)) out.push({ file, rule, line: i + 1, text: l.trim().slice(0, 120) }); });
    }
  }
  return out;
}

describe("egress static scan", () => {
  it("network / browser / child-process calls appear only in their owner files or the explicit known list", () => {
    expect(scan(process.cwd(), ["src", "examples"], { ...OWNERS, ...KNOWN })).toEqual([]);
  });
  it("every listed exception is still needed (no stale entries)", () => {
    const hits = scan(process.cwd(), ["src", "examples"], {});
    for (const [file, { rules }] of Object.entries({ ...OWNERS, ...KNOWN })) for (const r of rules) {
      if (file === "src/core/runcli.ts") continue; // owner by design even while it spawns via sandbox.run
      expect(hits.some((h) => h.file === file && h.rule === r), `${file} ${r}`).toBe(true);
    }
  });
  it("negative: a new fetch( / spawn( / chromium.launch( in scanned scope is reported", () => {
    const root = mkdtempSync(join(tmpdir(), "wt-scan-"));
    mkdirSync(join(root, "src", "core"), { recursive: true });
    writeFileSync(join(root, "src", "core", "leak.ts"), 'export const a = () => fetch("http://x/");\nimport { spawn } from "node:child_process";\nspawn("ls", []);\n// fetch( in a comment is ignored\nawait chromium.launch();\n');
    writeFileSync(join(root, "src", "core", "egress-like.ts"), "export const ok = (g: { fetch(u: string): void }) => g.fetch('x');\n");
    const hits = scan(root, ["src"], { ...OWNERS, ...KNOWN });
    expect(hits.map((h) => `${h.file}:${h.rule}:${h.line}`).sort()).toEqual(["src/core/leak.ts:browser:5", "src/core/leak.ts:net:1", "src/core/leak.ts:process:2", "src/core/leak.ts:process:3"]);
  });
});
