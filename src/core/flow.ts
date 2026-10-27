import { flowScreenshot } from "./flow-capture.internal.js";
import { flowPolicy, guardedFetch, ReplayRejectedError, type Resolver } from "./replay.js";
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
  /** Token-type values substituted for `${NAME}` at load time; runFlow registers them with the core's Redactor. */
  substituted?: string[];
}

/**
 * Env vars a flow config may reference as `${NAME}`: per-run plumbing only (an OS-assigned port and the readiness
 * token checked by waitFor.header). Anything else — even if set in the environment — is a load error, so a config
 * can never pull a credential out of the environment.
 */
export const FLOW_ENV_VARS: Readonly<Record<string, { redact: boolean }>> = {
  // A port is not a secret, and masking its digits everywhere would corrupt timestamps / ids / amounts.
  PORT: { redact: false },
  // Token-type: registered with the Redactor so it never appears in evidence or reports.
  DEMO_HEALTH_TOKEN: { redact: true },
};
export const FLOW_ENV_ALLOWLIST: readonly string[] = Object.keys(FLOW_ENV_VARS);

/** Expand `${NAME}` (allowlisted names only). Values of `redact: true` names are pushed to `used` for the Redactor. */
export function expandEnv(v: unknown, where: string, env: NodeJS.ProcessEnv = process.env, used: string[] = []): unknown {
  if (typeof v === "string") return v.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, k: string) => {
    if (!FLOW_ENV_ALLOWLIST.includes(k)) throw new Error(`${where}: \${${k}} is not allowed in a flow config (allowed: ${FLOW_ENV_ALLOWLIST.join(", ")})`);
    const x = env[k];
    if (x === undefined || x === "") throw new Error(`${where}: \${${k}} is not set`);
    if (FLOW_ENV_VARS[k].redact) used.push(x);
    return x;
  });
  if (Array.isArray(v)) return v.map((x) => expandEnv(x, where, env, used));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandEnv(x, where, env, used)]));
  return v;
}

export function loadFlowConfig(path: string, overrides: Partial<Pick<SandboxConfig, "up" | "down" | "backend">> = {}): FlowConfig {
  // `${NAME}` (upper-case env var) in any string is replaced from the environment, so per-run values (an OS-assigned
  // port, a readiness token for waitFor.header) never have to be hard-coded. An unset variable is an error.
  const used: string[] = [];
  const cfg = expandEnv(JSON.parse(readFileSync(path, "utf8")), path, process.env, used) as FlowConfig;
  if (used.length) cfg.substituted = [...new Set(used)];
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
export async function waitForUrl(url: string, timeoutMs: number, attemptTimeoutMs = 5_000, header?: { name: string; value: string }, opts: { resolver?: Resolver } = {}): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    const budget = Math.max(1, Math.min(attemptTimeoutMs, deadline - Date.now()));
    try {
      // Same guarded path as replay (flow policy, checkHop + pinned IP, manual redirects, every hop re-checked).
      const r = await withDeadline(async () => guardedFetch(await flowPolicy(url, opts.resolver, budget), url, { resolver: opts.resolver }), budget, `GET ${url}`);
      const ok = r.status >= 200 && r.status < 300;
      const hv = header ? Object.entries(r.headers).find(([k]) => k.toLowerCase() === header.name.toLowerCase())?.[1] : undefined;
      if (ok && (!header || hv === header.value)) return;
      if (ok) last = ` (got 2xx without the expected ${header!.name} header — another process on that port?)`;
    } catch (e) {
      if (e instanceof ReplayRejectedError) throw e; // policy refusal (blocklist, redirect off-host…): never retried
      /* not ready */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out waiting for ${url}${last}`);
}

export async function runFlow(core: WalkthroughCore, cfg: FlowConfig, opts: { skipWait?: boolean; agent?: (id: string) => Promise<void> } = {}) {
  if (cfg.substituted?.length) core.addRedactions(cfg.substituted); // never in evidence / reports
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
      // Screenshots: same guarded browser path as capture_page, under the flow policy (own host only, core blocklist).
      const ev = cap.type === "screenshot"
        ? await flowScreenshot.get(core)!(w.id, cap.url)
        : await core.captureEvidence(w.id, { type: "logs", service: cap.service });
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

