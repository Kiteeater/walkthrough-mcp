// Static scan: outbound network, browser and child processes may only appear in the files that own them.
// Scope: src/** (core, mcp, cli AND demo-agent, which ships in dist) and examples/** (demo/dev scripts; scanned so
// new ones are noticed). scripts/ (CI tooling: test-gate, aliyun preset check) and test/ are NOT scanned.
// Every exception is ONE exact file path + rule, with a reason. No globs, no directory exemptions.
//
// JS/TS files are parsed with the TypeScript compiler (AST), so comments and string contents can never hide or fake
// a hit, and #private members are scanned like any other code. A file is a hit when it:
//  - references a banned module (static import / export-from / import x = require / dynamic import() / require()),
//    with or without the node: prefix: http https http2 net tls dgram undici ws (net); child_process (process);
//    playwright playwright-core @playwright/test (browser: importing playwright at all is a hit, so renamed
//    destructuring `const { chromium: c } = ...; c.launch()` and `pw["chromium"].launch()` are caught);
//  - uses the identifier `fetch` or `WebSocket` as a value or type: bare calls, aliases (`const f = fetch`),
//    `new WebSocket(...)`, and `globalThis.` / `window.` / `self.` / `global.` member access.
//    Not hits: a member of some other object (`guard.fetch(...)`) or a declared member name (`fetch(url: string)`).
// Only exemption by shape: `import { isIP, isIPv4, isIPv6, BlockList, SocketAddress } from "node:net"` (pure address
// helpers, no sockets). A default/namespace import, any other name, or require/import() of net is a hit.
// Suspicious (rule "suspicious"): import()/require() with a non-literal argument, createRequire / node:module /
// node:vm / worker_threads, eval / Function / new Function, process.binding / process._linkedBinding,
// Reflect.get(<global>, ...), <global>[<non-literal key>], destructuring fetch/WebSocket out of a global object
// (counted as "net"), and assigning a global object to a variable (`const g = globalThis`).
// .sh files: `#` comments removed (shell only), then the same module names / identifiers are matched as text,
// since the scripts embed node code in heredocs.
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

type Rule = "net" | "browser" | "process" | "suspicious";
const MODULES: Record<string, Rule> = {
  http: "net", https: "net", http2: "net", net: "net", tls: "net", dgram: "net", undici: "net", ws: "net",
  child_process: "process",
  worker_threads: "suspicious", module: "suspicious", vm: "suspicious",
  playwright: "browser", "playwright-core": "browser", "@playwright/test": "browser",
};
const GLOBALS = new Set(["globalThis", "window", "self", "global"]);
const IDENTS = new Set(["fetch", "WebSocket"]);

/** Files allowed to contain a rule, by design. */
const OWNERS: Record<string, { rules: Rule[]; why: string }> = {
  "src/core/egress/fetch.ts": { rules: ["net"], why: "guarded HTTP: checkHop + IP pinning + manual redirects" },
  "src/core/egress/ws.ts": { rules: ["net"], why: "guarded WebSocket client: same checkHop + IP pinning" },
  "src/core/capture.ts": { rules: ["browser"], why: "Playwright browser; only driven via WalkthroughCore.guardedPage, every request routed to the guard (route.fulfill from guard.fetch / guard.websocket). Not moved into egress/ in this PR" },
  "src/core/sandbox.ts": { rules: ["process"], why: "sandbox up/down/exec: spawn(file,args), no shell, allowlisted env" },
};

/** KNOWN violations that exist today. Not fixed in this PR (move-only); new ones fail the test. */
const KNOWN: Record<string, { rules: Rule[]; why: string }> = {
  "src/core/alerts.ts": { rules: ["process"], why: "KNOWN ISSUE_ALERTS: spawnDetachedPoller spawns `walkthrough watch _poll` with the full process.env (should go through sandbox/allowlistEnv)" },
  "src/demo-agent/trace-run.ts": { rules: ["net"], why: "KNOWN ISSUE_TRACE: direct fetch to LANGFUSE_URL, not through the egress guard" },
  "examples/demo.mjs": { rules: ["process"], why: "ISSUE_EXAMPLES example launcher: spawns examples/trace-demo/run.mjs" },
  "examples/regen-output-trace.mjs": { rules: ["process"], why: "ISSUE_EXAMPLES dev script: regenerates example output" },
  "examples/screenshot.mjs": { rules: ["browser"], why: "ISSUE_EXAMPLES dev script: screenshots a local generated HTML report" },
  "examples/run-local-e2e.sh": { rules: ["browser", "net"], why: "ISSUE_EXAMPLES e2e script: screenshots the local report file; picks a free local port with net.createServer" },
  "examples/run-e2e.sh": { rules: ["net"], why: "ISSUE_EXAMPLES e2e script: picks a free local port with net.createServer" },
  "examples/ui-demo/run.mjs": { rules: ["process", "browser"], why: "ISSUE_EXAMPLES demo: starts the local orders service and a browser on it" },
  "examples/trace-demo/run.mjs": { rules: ["process", "net"], why: "ISSUE_EXAMPLES demo: spawns dist/demo-agent/trace-run.js with local mock env; net.createServer for a free local port" },
  "examples/trace-demo/mongo-demo.mjs": { rules: ["process"], why: "ISSUE_EXAMPLES demo: docker for a throwaway local MongoDB" },
  "examples/trace-demo/mock-langfuse.mjs": { rules: ["net"], why: "ISSUE_EXAMPLES local mock server (node:http server only)" },
  "examples/trace-demo/mock-prometheus.mjs": { rules: ["net"], why: "ISSUE_EXAMPLES local mock server; fetches the demo service's local /metrics.json" },
  "examples/trace-demo/service/server.js": { rules: ["net"], why: "ISSUE_EXAMPLES demo service: local http server, posts to the local mock Langfuse" },
  "examples/orders-service/server.js": { rules: ["net"], why: "ISSUE_EXAMPLES demo service: local http server (browser fetch in served page)" },
};

type Hit = { file: string; rule: Rule; line: number; text: string };
const moduleRule = (spec: string): Rule | undefined => {
  const s = spec.replace(/^node:/, "");
  const root = s.startsWith("@") ? s.split("/").slice(0, 2).join("/") : s.split("/")[0];
  return MODULES[root];
};

/** `import { isIP, BlockList } from "node:net"`: only pure address helpers (no sockets), named, static. Anything else from net is a hit. */
const NET_PURE = new Set(["isIP", "isIPv4", "isIPv6", "BlockList", "SocketAddress"]);
function pureNetImport(n: ts.Node, spec: string): boolean {
  if (spec.replace(/^node:/, "") !== "net" || !ts.isImportDeclaration(n)) return false;
  const c = n.importClause;
  if (!c || c.name || !c.namedBindings || !ts.isNamedImports(c.namedBindings)) return false;
  return c.namedBindings.elements.every((e) => NET_PURE.has((e.propertyName ?? e.name).text));
}

function isDeclaredName(id: ts.Identifier): boolean {
  const p = id.parent;
  if ((ts.isPropertyAccessExpression(p) || ts.isPropertyAccessChain(p)) && p.name === id) return true; // handled by caller
  if ((ts.isMethodSignature(p) || ts.isMethodDeclaration(p) || ts.isPropertySignature(p) || ts.isPropertyDeclaration(p) ||
    ts.isPropertyAssignment(p) || ts.isGetAccessor(p) || ts.isSetAccessor(p) || ts.isEnumMember(p)) && p.name === id) return true;
  if (ts.isBindingElement(p) && p.propertyName === id) return true;
  if (ts.isQualifiedName(p) && p.right === id) return true;
  return false;
}

/** AST hits for one JS/TS source. */
export function scanSource(file: string, text: string): Hit[] {
  const kind = file.endsWith(".tsx") ? ts.ScriptKind.TSX : file.endsWith(".jsx") ? ts.ScriptKind.JSX : /\.(?:ts|mts|cts)$/.test(file) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind);
  const hits: Hit[] = [];
  const add = (node: ts.Node, rule: Rule) => {
    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    hits.push({ file, rule, line, text: node.getText(sf).slice(0, 120) });
  };
  const visit = (n: ts.Node): void => {
    let spec: ts.Expression | undefined;
    if ((ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) && n.moduleSpecifier) spec = n.moduleSpecifier;
    else if (ts.isImportEqualsDeclaration(n) && ts.isExternalModuleReference(n.moduleReference)) spec = n.moduleReference.expression;
    else if (ts.isCallExpression(n) && (n.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(n.expression) && n.expression.text === "require")) && n.arguments[0]) spec = n.arguments[0];
    else if (ts.isImportTypeNode(n) && ts.isLiteralTypeNode(n.argument)) spec = n.argument.literal as ts.Expression;
    const isLit = (e: ts.Expression) => ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e);
    if (ts.isCallExpression(n) && (n.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(n.expression) && n.expression.text === "require")) && (!n.arguments[0] || !isLit(n.arguments[0]))) add(n, "suspicious");
    if (ts.isIdentifier(n) && GLOBALS.has(n.text)) {
      const p = n.parent;
      if ((ts.isVariableDeclaration(p) && p.initializer === n) || (ts.isBinaryExpression(p) && p.right === n && p.operatorToken.kind === ts.SyntaxKind.EqualsToken)) {
        add(p, "suspicious");
        if (ts.isVariableDeclaration(p) && ts.isObjectBindingPattern(p.name) && p.name.elements.some((e) => IDENTS.has(((e.propertyName ?? e.name) as ts.Identifier).text ?? ""))) add(p, "net");
      }
    }
    if (ts.isIdentifier(n) && (n.text === "eval" || n.text === "Function" || n.text === "createRequire") && !isDeclaredName(n) &&
      !((ts.isPropertyAccessExpression(n.parent)) && n.parent.name === n && !(ts.isIdentifier(n.parent.expression) && GLOBALS.has(n.parent.expression.text)))) add(n, "suspicious");
    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "process" && (n.name.text === "binding" || n.name.text === "_linkedBinding")) add(n, "suspicious");
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) && n.expression.expression.text === "Reflect" &&
      n.expression.name.text === "get" && n.arguments[0] && ts.isIdentifier(n.arguments[0]) && GLOBALS.has(n.arguments[0].text)) add(n, "suspicious");
    if (ts.isElementAccessExpression(n) && ts.isIdentifier(n.expression) && GLOBALS.has(n.expression.text) && !ts.isStringLiteralLike(n.argumentExpression)) add(n, "suspicious");
    if (spec && (ts.isStringLiteral(spec) || ts.isNoSubstitutionTemplateLiteral(spec)) && !pureNetImport(n, spec.text)) { const r = moduleRule(spec.text); if (r) add(n, r); }
    if (ts.isIdentifier(n) && IDENTS.has(n.text)) {
      const p = n.parent;
      if ((ts.isPropertyAccessExpression(p) || ts.isPropertyAccessChain(p)) && p.name === n) {
        if (ts.isIdentifier(p.expression) && GLOBALS.has(p.expression.text)) add(p, "net");
      } else if (!isDeclaredName(n)) add(n, "net");
    }
    if (ts.isElementAccessExpression(n) && ts.isIdentifier(n.expression) && GLOBALS.has(n.expression.text) &&
      ts.isStringLiteralLike(n.argumentExpression) && IDENTS.has(n.argumentExpression.text)) add(n, "net");
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return hits;
}

/** Drop a shell `#` comment: only an unquoted `#` at the start of a word; `#` inside '...' / "..." is kept. */
export function stripShellComment(line: string): string {
  let q = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === "\\" && q === '"') i++; else if (c === q) q = ""; continue; }
    if (c === "\\") { i++; continue; }
    if (c === "'" || c === '"') q = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1])) && line[i + 1] !== "!") return line.slice(0, i);
  }
  return line;
}

/** Shell scripts: drop `#` comments, then match module names / identifiers as text (node code lives in heredocs). */
export function scanShell(file: string, text: string): Hit[] {
  const hits: Hit[] = [];
  const mod = Object.keys(MODULES).map((m) => m.replace(/[/@-]/g, "\\$&")).join("|");
  const modRe = new RegExp(`["'\`](?:node:)?(${mod})(?:/[^"'\`]*)?["'\`]`);
  text.split("\n").forEach((raw, i) => {
    const l = stripShellComment(raw);
    if (/(?:^|[\s;|&(`$])(?:curl|wget|nc|ncat|socat|telnet)(?=\s|$)/.test(l)) hits.push({ file, rule: "net", line: i + 1, text: l.trim().slice(0, 120) });
    const m = modRe.exec(l);
    if (m) hits.push({ file, rule: moduleRule(m[1])!, line: i + 1, text: l.trim().slice(0, 120) });
    if (/(?<![\w.$#])(?:fetch|WebSocket)\b|\b(?:globalThis|window|self|global)\.(?:fetch|WebSocket)\b/.test(l)) hits.push({ file, rule: "net", line: i + 1, text: l.trim().slice(0, 120) });
  });
  return hits;
}

const EXT = /\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs|sh)$/;
/** Every hit under `dirs` of `root` that is not covered by `allowed`. */
export function scan(root: string, dirs: string[], allowed: Record<string, { rules: Rule[] }>): Hit[] {
  const files: string[] = [];
  const walk = (d: string) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) { if (f !== "node_modules" && f !== "output" && f !== "output-trace") walk(p); } else if (EXT.test(f) && !f.endsWith(".d.ts")) files.push(p); } };
  for (const d of dirs) walk(join(root, d));
  const out: Hit[] = [];
  for (const p of files) {
    const file = relative(root, p).split("\\").join("/");
    const text = readFileSync(p, "utf8");
    for (const h of file.endsWith(".sh") ? scanShell(file, text) : scanSource(file, text)) if (!allowed[file]?.rules.includes(h.rule)) out.push(h);
  }
  return out;
}

describe("egress static scan", () => {
  it("network / browser / child-process use appears only in owner files or the explicit known list", () => {
    expect(scan(process.cwd(), ["src", "examples"], { ...OWNERS, ...KNOWN })).toEqual([]);
  });
  it("every listed exception is still needed (no stale entries, none skipped)", () => {
    const hits = scan(process.cwd(), ["src", "examples"], {});
    for (const [file, { rules }] of Object.entries({ ...OWNERS, ...KNOWN })) for (const r of rules)
      expect(hits.some((h) => h.file === file && h.rule === r), `${file} ${r}`).toBe(true);
  });

  const CASES: [string, string, Rule][] = [
    ["globalThis-fetch", 'export const a = () => globalThis.fetch("http://x/");', "net"],
    ["window-fetch", 'export const a = () => window.fetch("http://x/");', "net"],
    ["fetch-alias", 'const f = fetch;\nexport const a = () => f("http://x/");', "net"],
    ["dyn-child-process", 'export const a = async () => (await import("node:child_process")).spawn("ls");', "process"],
    ["dyn-http", 'export const a = async () => (await import("node:http")).get("http://x/");', "net"],
    ["net-socket", 'import { Socket } from "node:net";\nexport const a = () => new Socket().connect(80, "x");', "net"],
    ["new-websocket", 'export const a = () => new WebSocket("ws://x/");', "net"],
    ["ws-package", 'import WS from "ws";\nexport const a = () => new WS("ws://x/");', "net"],
    ["playwright-rename", 'import * as pwmod from "playwright";\nconst { chromium: c } = pwmod;\nexport const a = () => c.launch();', "browser"],
    ["playwright-index", 'const pw = require("playwright");\nexport const a = () => pw["chromium"].launch();', "browser"],
    ["string-comment-markers", 'const s = " //"; const t = "/*";\nexport const a = () => fetch("http://x/");', "net"],
    ["private-field", 'export class C { #f = () => fetch("http://x/"); run() { return this.#f(); } }', "net"],
    ["require-https", 'const h = require("https");\nexport const a = () => h.get("https://x/");', "net"],
    ["undici", 'import { request } from "undici";\nexport const a = () => request("http://x/");', "net"],
    ["dgram-tls", 'import dgram from "node:dgram";\nimport tls from "node:tls";\nexport const a = () => [dgram.createSocket("udp4"), tls.connect(443, "x")];', "net"],
  ];
  it("negative: each of the 15 bypass forms is reported", () => {
    expect(CASES).toHaveLength(15);
    const root = mkdtempSync(join(tmpdir(), "wt-scan-"));
    mkdirSync(join(root, "src", "core"), { recursive: true });
    for (const [name, code] of CASES) writeFileSync(join(root, "src", "core", `${name}.ts`), code + "\n");
    const hits = scan(root, ["src"], { ...OWNERS, ...KNOWN });
    for (const [name, , rule] of CASES) expect(hits.some((h) => h.file === `src/core/${name}.ts` && h.rule === rule), name).toBe(true);
  });
  const SUSPICIOUS: [string, string, Rule][] = [
    ["destructure-globalThis", "const { fetch: f } = globalThis;\nexport const a = () => f('x');", "net"],
    ["destructure-window-ws", "const { WebSocket: W } = window;\nexport const a = () => new W('ws://x');", "net"],
    ["global-alias", "const g = globalThis;\nexport const a = () => g.fetch('x');", "suspicious"],
    ["global-assign", "let g; g = self;\nexport const a = () => g;", "suspicious"],
    ["import-nonliteral", "const m = 'node:' + 'http';\nexport const a = () => import(m);", "suspicious"],
    ["require-nonliteral", "const m = ['ht', 'tp'].join('');\nexport const a = () => require(m);", "suspicious"],
    ["require-template", "const x = 'http';\nexport const a = () => require(`node:${x}`);", "suspicious"],
    ["create-require", "import { createRequire } from 'node:module';\nconst r = createRequire(import.meta.url);\nexport const a = () => r('http');", "suspicious"],
    ["module-namespace", "import * as m from 'module';\nexport const a = m;", "suspicious"],
    ["eval", "export const a = () => eval('fet' + 'ch')('x');", "suspicious"],
    ["new-function", "export const a = () => new Function('return fe' + 'tch')();", "suspicious"],
    ["reflect-get", "export const a = () => Reflect.get(globalThis, 'fe' + 'tch')('x');", "suspicious"],
    ["concat-key", "export const a = () => globalThis['fe' + 'tch']('x');", "suspicious"],
    ["process-binding", "export const a = () => process.binding('tcp_wrap');", "suspicious"],
    ["worker-threads", "import { Worker } from 'node:worker_threads';\nexport const a = () => new Worker('x.js');", "suspicious"],
  ];
  it("negative: suspicious / indirect forms are reported", () => {
    const root = mkdtempSync(join(tmpdir(), "wt-scan-s-"));
    mkdirSync(join(root, "src", "core"), { recursive: true });
    for (const [name, code] of SUSPICIOUS) writeFileSync(join(root, "src", "core", `${name}.ts`), code + "\n");
    writeFileSync(join(root, "src", "core", "comp.tsx"), "export const C = () => <button onClick={() => fetch('x')}>x</button>;\n");
    writeFileSync(join(root, "src", "core", "comp.jsx"), "export const C = () => <a onClick={() => new WebSocket('ws://x')}>x</a>;\n");
    const hits = scan(root, ["src"], { ...OWNERS, ...KNOWN });
    for (const [name, , rule] of SUSPICIOUS) expect(hits.some((h) => h.file === `src/core/${name}.ts` && h.rule === rule), name).toBe(true);
    expect(hits.some((h) => h.file === "src/core/comp.tsx" && h.rule === "net"), ".tsx").toBe(true);
    expect(hits.some((h) => h.file === "src/core/comp.jsx" && h.rule === "net"), ".jsx").toBe(true);
  });
  it("negative: .sh curl / wget / nc are net; quoted # is not a comment", () => {
    for (const cmd of ["curl -s http://x/", "x=$(wget -qO- http://x/)", "echo hi | nc x 80", "ok && curl http://x/"]) expect(scanShell("x.sh", cmd + "\n").map((h) => h.rule), cmd).toContain("net");
    expect(scanShell("x.sh", "echo curl-free # curl http://x/\n")).toEqual([]);
    expect(scanShell("x.sh", "echo \"#\"; curl http://x/\n").map((h) => h.rule)).toEqual(["net"]);
    expect(scanShell("x.sh", "node -e 'const a=\"#\"; fetch(a)'\n").map((h) => h.rule)).toEqual(["net"]);
    expect(stripShellComment("echo 'a # b' # c")).toBe("echo 'a # b' ");
  });
  it("negative: no false hits from comments, strings, other objects' .fetch, or declared member names", () => {
    const src = '// fetch("x") import("node:http")\n/* new WebSocket() */\nconst s = "fetch( require(\\"https\\") //";\nexport interface G { fetch(u: string): void; WebSocket?: number }\nexport const a = (g: G) => g.fetch(s);\n';
    expect(scanSource("src/core/clean.ts", src)).toEqual([]);
  });
  it("negative: net is a hit unless it is a named import of pure address helpers only", () => {
    expect(scanSource("a.ts", 'import { isIP, BlockList } from "node:net";\n')).toEqual([]);
    expect(scanSource("a.ts", 'import { isIP, connect } from "node:net";\n')).toHaveLength(1);
    expect(scanSource("a.ts", 'import * as net from "net";\n')).toHaveLength(1);
    expect(scanSource("a.ts", 'const { isIP } = require("node:net");\n')).toHaveLength(1);
  });
  it(".sh: # comments ignored, code lines scanned", () => {
    expect(scanShell("x.sh", "# fetch and chromium.launch\necho ok\n")).toEqual([]);
    expect(scanShell("x.sh", "node -e 'import(\"playwright\")' # x\n").map((h) => h.rule)).toEqual(["browser"]);
  });
});
