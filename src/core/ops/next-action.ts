// Next-action guidance moved verbatim from walkthrough.ts (ops/ split step 2; no logic change).
import type { Check, EvidenceKind } from "../types.js";

/** Raw output the host agent obtained itself (own tools / external MCP / computer use) and submits for a check. */
export interface SubmittedEvidence {
  type: "submit"; checkId: string; kind: EvidenceKind;
  source: { tool: string; server?: string; command?: string };
  content?: string; path?: string;
}

/** Instruction returned to the host agent: what to do next (design: guide via next_actions, no server→agent calls). */
export interface NextAction { check_id: string; do: string; then: string[] }

export function nextActionFor(c: Check): NextAction {
  const how: Record<string, [string, EvidenceKind]> = {
    http: [`send the request yourself: ${c.target}`, "http"],
    cli: [`run it yourself (or via run_cli when available): ${c.target}`, "cli_output"],
    mcp: [`call the external MCP tool yourself: ${c.target}`, "mcp_result"],
    ui: [`operate the page with computer use / Playwright: ${c.target}; judge by HAR or DOM text, not the screenshot`, "har"],
    script: [`run the script yourself: ${c.target}`, "cli_output"],
  };
  const [d, kind] = how[c.method];
  return {
    check_id: c.id, do: d,
    then: [`capture_evidence(check_id="${c.id}", kind="${kind}", content=<raw output, unedited>)`, `evaluate_check(check_id="${c.id}", evidence_ids=[...])`],
  };
}
