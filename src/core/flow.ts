import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { renderWalkthrough } from "./render.js";
import { withDeadline } from "./settle.js";
import type { ClaimKind, SandboxConfig } from "./types.js";
import type { WalkthroughCore } from "./walkthrough.js";

/** Declarative plan for `walkthrough run`. Captures are named with `as`; claims refer to those names, resolved to evidence ids. */
export interface FlowConfig {
  title: string;
  sandbox: SandboxConfig;
  waitFor?: { url: string; timeoutMs?: number; attemptTimeoutMs?: number; /** only count a 2xx that also carries this header value (proves it is OUR service, not whatever else holds the port) */ header?: { name: string; value: string } };
  exec?: string[];
  captures: ({ as: string; type: "screenshot"; url: string } | { as: string; type: "logs"; service: string })[];
  sources?: { as: string; file: string; line: number; note?: string }[];
  claims: { question: string; conclusion: string; kind: ClaimKind; evidence?: string[]; sources?: string[] }[];
  keepRunning?: boolean;
}

export function loadFlowConfig(path: string, overrides: Partial<Pick<SandboxConfig, "up" | "down" | "backend">> = {}): FlowConfig {
  const cfg = JSON.parse(readFileSync(path, "utf8")) as FlowConfig;
  cfg.sandbox.cwd = resolve(dirname(path), cfg.sandbox.cwd ?? ".");
  if (overrides.up) cfg.sandbox.up = overrides.up;
  if (overrides.down) cfg.sandbox.down = overrides.down;
  if (overrides.backend) {
    if (overrides.backend !== "local" && overrides.backend !== "compose") throw new Error(`unknown sandbox backend: ${overrides.backend}`);
    cfg.sandbox.backend = overrides.backend;
  }
  return cfg;
}

/** Poll `url` until it answers 2xx. Every attempt has a ref'd deadline, so this always settles (exit-13 fix). */
export async function waitForUrl(url: string, timeoutMs: number, attemptTimeoutMs = 5_000, header?: { name: string; value: string }): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    const budget = Math.max(1, Math.min(attemptTimeoutMs, deadline - Date.now()));
    try {
      const r = await withDeadline((signal) => fetch(url, { signal }), budget, `GET ${url}`);
      if (r.ok && (!header || r.headers.get(header.name) === header.value)) return;
      if (r.ok) last = ` (got 2xx without the expected ${header!.name} header — another process on that port?)`;
    } catch { /* not ready */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out waiting for ${url}${last}`);
}

export async function runFlow(core: WalkthroughCore, cfg: FlowConfig, opts: { skipWait?: boolean; agent?: (id: string) => Promise<void> } = {}) {
  const w = core.startWalkthrough({ title: cfg.title, sandbox: cfg.sandbox });
  const names = new Map<string, string>();
  const up = await core.runInSandbox(w.id, "up");
  if (up.exitCode !== 0) throw new Error(`sandbox up failed:\n${up.output}`);
  try {
    if (cfg.waitFor && !opts.skipWait) await waitForUrl(cfg.waitFor.url, cfg.waitFor.timeoutMs ?? 60_000, cfg.waitFor.attemptTimeoutMs, cfg.waitFor.header);
    for (const c of cfg.exec ?? []) await core.runInSandbox(w.id, "exec", c);
    // The host agent plans, executes and submits evidence here (core only keeps the ledger and judges).
    if (opts.agent) await opts.agent(w.id);
    for (const cap of cfg.captures) {
      const ev = await core.captureEvidence(w.id, cap.type === "screenshot" ? { type: "screenshot", url: cap.url } : { type: "logs", service: cap.service });
      names.set(cap.as, ev.id);
    }
    for (const s of cfg.sources ?? []) names.set(s.as, (await core.linkSource(w.id, s)).id);
    const ref = (n: string) => names.get(n) ?? n;
    for (const c of cfg.claims) {
      await core.recordClaim(w.id, { ...c, evidenceIds: (c.evidence ?? []).map(ref), sourceIds: (c.sources ?? []).map(ref) });
    }
  } finally {
    if (!cfg.keepRunning) await core.runInSandbox(w.id, "down");
  }
  return { id: w.id, html: renderWalkthrough(core, w.id) };
}

