// Demo agent: stands in for the host agent. It executes every check ITSELF, submits raw output through
// capture_evidence, asks the core to judge (evaluate_check), and writes findings with a root-cause chain.
// The core never executes a check and the agent never decides pass/fail.
import { traceStack, type Check, type CheckResult, type RootCauseLink, type Severity, type WalkthroughCore } from "../core/index.js";
import { planFromRoutes, type RouteSpec } from "./planner.js";

export interface DemoOptions { goal: string; baseUrl: string; service?: string; settleMs?: number }

const RANK: Severity[] = ["critical", "high", "medium", "low"];

export async function runDemoAgent(core: WalkthroughCore, id: string, routes: RouteSpec[], o: DemoOptions): Promise<CheckResult[]> {
  const service = o.service ?? "app";
  const { checks } = await core.planChecks(id, { goal: o.goal, checks: planFromRoutes(routes, { baseUrl: o.baseUrl, service }) });
  await core.captureEvidence(id, { type: "logs", service, delta: true }); // baseline: startup logs
  const results: CheckResult[] = [];
  for (const main of checks.filter((c) => /^chk-\d+$/.test(c.id))) {
    const group = checks.filter((c) => c.id === main.id || c.id.startsWith(`${main.id}-`));
    const [method, url] = main.target.split(" ");
    // 1. execute it ourselves through the action-source seam (http today, connector:<name> later)
    const out = await core.registry.action("http").run({ type: "http", method, url }, { walkthrough: core.load(id), sandbox: undefined as never, replay: core.replayPolicy() });
    await new Promise((r) => setTimeout(r, o.settleMs ?? 200));
    // 2. submit raw output; the core hashes and redacts it
    const evIds: Record<string, string> = {};
    for (const c of group) {
      if (c.method === "http") {
        evIds[c.id] = (await core.captureEvidence(id, { type: "submit", checkId: c.id, kind: "http", source: { tool: "fetch", command: out.repro }, content: out.evidenceText })).id;
      } else {
        evIds[c.id] = (await core.captureEvidence(id, { type: "logs", service, delta: true, checkId: c.id })).id;
      }
    }
    // 3. the core judges
    const judged = [];
    for (const c of group) judged.push({ check: c, result: await core.evaluateCheck(id, { checkId: c.id, evidenceIds: [evIds[c.id]] }) });
    results.push(...judged.map((j) => j.result));
    const failed = judged.filter((j) => j.result.status === "fail");
    if (failed.length) await reportFinding(core, id, main, failed, evIds, out.repro, service);
  }
  return results;
}

/** Turn the failed checks of one route into a finding: symptom → error in logs → offending source line. */
async function reportFinding(
  core: WalkthroughCore, id: string, main: Check, failed: { check: Check; result: CheckResult }[],
  evIds: Record<string, string>, repro: string, service: string,
) {
  const w = core.load(id);
  const chain: RootCauseLink[] = failed.map(({ check, result }) => ({ claim: `${check.intent}: FAIL — ${result.reasons.join("; ")}`, kind: "observed", evidence_ids: result.evidenceIds }));
  const logEv = w.evidence.find((e) => e.id === evIds[`${main.id}-logs`]);
  const hit = logEv ? traceStack(core.readEvidenceText(w, logEv), w.sandbox.cwd, core.root) : undefined;
  if (hit && logEv) {
    const src = await core.linkSource(id, { file: hit.file, line: hit.line, note: hit.message });
    chain.push({ claim: `the stack trace's first in-project frame is ${hit.file}:${hit.line} (${hit.message})`, kind: "observed", evidence_ids: [logEv.id], source_ref: src.id });
  }
  const severity = RANK.find((s) => failed.some((f) => f.check.severity_if_fail === s)) ?? "medium";
  const up = w.sandbox.backend === "local" ? (w.sandbox.local?.up ?? w.sandbox.up) : w.sandbox.up;
  await core.recordFinding(id, {
    title: `${main.target.replace(/^(\S+) https?:\/\/[^/]+/, "$1 ")} — ${failed[0].result.reasons[0]}`,
    severity, check_id: main.id,
    symptom: failed.map((f) => `${f.check.id}: ${f.result.reasons.join("; ")}`).join(" | ") + (hit ? `. ${service} logged "${hit.message}".` : ""),
    repro_steps: [`Start the sandbox: ${up}`, repro],
    root_cause_chain: chain,
  });
}
