import { ReplayRejectedError } from "./egress/policy.js";
import { guardedFetch } from "./egress/fetch.js";
import { withDeadline } from "./settle.js";
import { evaluateExpect } from "./checks.js";
import { Registry, type SourceContext } from "./registry.js";
import { MCP_IMPORT_PRESETS, mcpImportSource } from "./imports.js";
import type { Check, CommandAction, HttpAction, LogObserve } from "./types.js";

const HTTP_ACTION_TIMEOUT_MS = 15_000;
const HTTP_ACTION_MAX_BODY_BYTES = 1024 * 1024; // what flowPolicy used before; unchanged

export const httpSource = {
  type: "http" as const,
  async run(a: HttpAction, ctx: Pick<SourceContext, "replay" | "resolver">) {
    const method = a.method ?? "GET";
    const repro = `curl -i -X ${method} ${JSON.stringify(a.url)}`;
    try {
      // Same guarded path and policy as replay: replay.allowHosts + allowCidrs, checkHop + pinned IP, manual redirects,
      // every hop re-checked (core blocklist, metadata, DNS rebinding). No allowlist configured → refused, no fallback.
      const replay = ctx.replay;
      if (!replay?.allowHosts?.length) throw new ReplayRejectedError("http action needs replay.allowHosts (same policy as replay)");
      const policy = { ...replay, timeoutMs: HTTP_ACTION_TIMEOUT_MS, maxBodyBytes: HTTP_ACTION_MAX_BODY_BYTES };
      const r = await withDeadline(() => guardedFetch(policy, a.url, { method, body: a.body, headers: a.headers, resolver: ctx.resolver }), HTTP_ACTION_TIMEOUT_MS, `${method} ${a.url}`);
      return { status: r.status, body: r.body, repro, evidenceText: `${method} ${a.url}\nHTTP ${r.status}\n\n${r.body}` };
    } catch (e) {
      return { body: "", repro, evidenceText: `${method} ${a.url}\nrequest failed: ${(e as Error).message}` };
    }
  },
};

export const commandSource = {
  type: "command" as const,
  async run(a: CommandAction, ctx: { sandbox: { exec(c: string): Promise<{ exitCode: number; output: string }> } }) {
    const r = await ctx.sandbox.exec(a.command);
    return { exitCode: r.exitCode, body: r.output, repro: a.command, evidenceText: `$ ${a.command}\nexit ${r.exitCode}\n\n${r.output}` };
  },
};

export const logSource = {
  source: "log" as const,
  snapshot: (o: LogObserve, ctx: { sandbox: { logs(s: string): Promise<string> } }) => ctx.sandbox.logs(o.service),
  async collect(o: LogObserve, ctx: { walkthrough: { sandbox: { backend?: string } }; sandbox: { logs(s: string): Promise<string> } }, before: unknown) {
    const after = await ctx.sandbox.logs(o.service);
    const prev = typeof before === "string" ? before : "";
    const text = after.startsWith(prev) ? after.slice(prev.length) : after;
    return { label: `${ctx.walkthrough.sandbox.backend === "local" ? "local" : "docker"}:${o.service}`, text, evidenceType: "logs" as const };
  },
};

export const ruleVerifier = { type: "rule", verify: async (check: Check, texts: string[]) => evaluateExpect(check.expect, texts) };

/** Built-in sources, plus one `connector:<name>` import source per read-only MCP preset (mongodb, langfuse, aliyun). */
export function defaultRegistry(): Registry {
  const r = new Registry().registerAction(httpSource).registerAction(commandSource).registerObserver(logSource).registerVerifier(ruleVerifier);
  for (const c of MCP_IMPORT_PRESETS) r.registerAction(mcpImportSource(c));
  return r;
}
