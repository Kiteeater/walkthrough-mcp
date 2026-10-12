import { withDeadline } from "./settle.js";
import { evaluateExpect } from "./checks.js";
import { Registry } from "./registry.js";
import type { Check, CommandAction, HttpAction, LogObserve } from "./types.js";

export const httpSource = {
  type: "http" as const,
  async run(a: HttpAction) {
    const method = a.method ?? "GET";
    const repro = `curl -i -X ${method} ${JSON.stringify(a.url)}`;
    try {
      const { res, body } = await withDeadline(async (signal) => {
        const r = await fetch(a.url, { method, body: a.body, headers: a.headers, signal });
        return { res: r, body: await r.text() };
      }, 15_000, `${method} ${a.url}`);
      return { status: res.status, body, repro, evidenceText: `${method} ${a.url}\nHTTP ${res.status} ${res.statusText}\n\n${body}` };
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

/** Built-in sources. PR 5 adds `connector:<name>` action/observe sources via the same registry. */
export function defaultRegistry(): Registry {
  return new Registry().registerAction(httpSource).registerAction(commandSource).registerObserver(logSource).registerVerifier(ruleVerifier);
}
