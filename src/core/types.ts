/** `response` = HTTP response / command output / MCP result submitted for a check. */
export type EvidenceType = "screenshot" | "logs" | "response" | "har" | "blocked";
/** Design-doc evidence kinds for capture_evidence. */
export type EvidenceKind = "cli_output" | "mcp_result" | "http" | "screenshot" | "har" | "log" | "metric" | "alert" | "blocked";

/** Fixed evidence format. Claims reference evidence only by `id`. */
export interface Evidence {
  id: string;
  type: EvidenceType;
  /** Path relative to the walkthrough directory, e.g. `evidence/ev-1.png`. */
  path: string;
  sha256: string;
  createdAt: string;
  /** What produced it: a URL for screenshots, `docker:<service>` for logs, `agent:<tool>` for submitted output. */
  source: string;
  kind?: EvidenceKind;
  /** Check this evidence was submitted for. */
  checkId?: string;
  /** `core` = we executed/captured it; `agent` = raw output reported by the host agent. */
  executedBy?: "core" | "agent";
  /** For imported MCP results (connector:<name>): which server/tool the agent says it called, params redacted, creds dropped. */
  mcpCall?: { connector: string; server: string; tool: string; params: unknown };
  /** Correlation links to earlier evidence: `key` (trace id, doc id…) appears in both, verified at import time. */
  links?: { evidenceId: string; key: string }[];
}

export type ClaimKind = "observed" | "inferred";

export interface SourceLink {
  id: string;
  file: string;
  line: number;
  note?: string;
}

export interface Review {
  decision: "agree" | "flag";
  note?: string;
}

export interface Claim {
  id: string;
  question: string;
  conclusion: string;
  kind: ClaimKind;
  evidenceIds: string[];
  sourceIds: string[];
  review?: Review;
}

export interface HttpAction { type: "http"; method?: string; url: string; body?: string; headers?: Record<string, string> }
export interface CommandAction { type: "command"; command: string }
/** Reserved for read-only environment connectors (PR 5), e.g. `connector:mongodb`. */
export interface ConnectorAction { type: `connector:${string}`; [key: string]: unknown }
export type CheckAction = HttpAction | CommandAction | ConnectorAction;

export interface LogObserve { source: "log"; service: string }
export interface ConnectorObserve { source: `connector:${string}`; [key: string]: unknown }
export type ObserveSpec = LogObserve | ConnectorObserve;

/** How the agent executes a check (design doc §工具). The MCP never executes it; the agent does. */
export type CheckMethod = "cli" | "mcp" | "ui" | "http" | "script";
/**
 * Machine-checkable expectation, judged by the core over the submitted evidence:
 * - status: `value` = number | [min, max]; read from `HTTP <code>` in http evidence (or `"status": n` JSON)
 * - count: `value` = { pattern?, eq?, min?, max? } (or a number = eq); counts regex matches, or JSON array length / non-empty lines
 * - regex: `value` = pattern that must match
 * - threshold: `value` = { pattern (one capture group with a number), min?, max? }
 * - absent: `value` = pattern that must NOT match
 * - ui: `value` = {har: {urlMatch, status, bodyMatch?, method?}} (judged from HAR network entries) or {text: {contains}} (DOM text).
 *   Screenshots are never judged.
 * - metric: `value` = {op: > >= < <= == !=, value, query?} over Prometheus instant-query evidence (exactly one finite series).
 */
export type ExpectType = "status" | "count" | "regex" | "threshold" | "absent" | "ui" | "metric" | "sls_empty";
export interface Expect { type: ExpectType; value: unknown }

export interface Check {
  id: string;
  intent: string;
  method: CheckMethod;
  /** What to act on: URL, command, MCP tool, page… (free text for the agent; not executed by the core). */
  target: string;
  expect: Expect;
  severity_if_fail: Severity;
  /** Verifier type; `rule` (default) ships now, `script` / `playwright` / `computer-use` are reserved. */
  verify?: { type: string; [key: string]: unknown };
  /** Prometheus alert label matchers (any one matching → the alert relates to this check). `~` prefix = regex. */
  alertMatchers?: Record<string, string>[];
  /** Set by the core when the check was appended mid-run (plan_checks append): never supplied by the agent. */
  appended?: { at: string; triggeringEvidenceId: string; logSeq: number };
}

/** `pass_needs_review`: the rule passed but every piece of evidence was reported by the agent, none executed by us. */
export type Verdict = "pass" | "pass_needs_review" | "fail" | "inconclusive";

/** Written only by evaluate_check (the core). There is no API for the agent to set or change it. */
export interface CheckResult {
  checkId: string;
  status: Verdict;
  reasons: string[];
  evidenceIds: string[];
  at: string;
}

export type Severity = "critical" | "high" | "medium" | "low";

/** One step of a root-cause chain: symptom → … → cause. Observed steps must cite verified evidence. */
export interface RootCauseLink {
  claim: string;
  kind: ClaimKind;
  evidence_ids: string[];
  /** Source link id (file:line) from link_source. */
  source_ref?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  symptom: string;
  repro_steps: string[];
  root_cause_chain: RootCauseLink[];
  /** Signals observed at the same time (e.g. firing alerts). Supporting context only, never part of the causal chain. */
  corroborating?: { kind: "alert"; claim: string; evidence_ids: string[]; alertname: string; activeAt?: string; firstSeenAt?: string; alsoMatched: string[] }[];
  /**
   * Hypotheses that were checked and excluded (e.g. message backlog). NOT part of the root-cause chain and not in
   * `evidenceIds`; each cites the core-executed evidence it rests on.
   */
  ruled_out?: { claim: string; check_id?: string; evidence_ids: string[] }[];
  /** Hypotheses checked WITHOUT a conclusion (e.g. an SLS query whose progress is not Complete): never excluded. */
  inconclusive?: { claim: string; reason: string; check_id?: string; evidence_ids: string[] }[];
  /** Union of evidence ids cited in the chain. */
  evidenceIds: string[];
  /** observed only if every chain step is observed. */
  kind: ClaimKind;
  checkId?: string;
}

export interface SignOff {
  decision: "accept" | "reject";
  comment?: string;
  /** Watches still open at sign-off, auto-finalized with what was observed so far. */
  autoFinalizedWatches?: { watchId: string; outcome: string }[];
}

export interface RunRecord {
  id: string;
  command: string;
  exitCode: number;
  output: string;
  createdAt: string;
  /** exec only: ran in the sandbox ("exec") or was routed through run_cli's allowlist ("run_cli"). */
  via?: "exec" | "run_cli";
}

export type SandboxBackend = "compose" | "local";

export interface SandboxConfig {
  /** `compose` (default, isolated) or `local` (child processes on the host, NOT isolated). */
  backend?: SandboxBackend;
  /** Overrides used when backend is `local`: `up` is a long-running command whose stdout/stderr become the logs. */
  local?: {
    up: string;
    down?: string;
    /** Extra host env var names passed to local child processes (default: only PATH, HOME, LANG, TMPDIR, TERM). */
    passEnv?: string[];
    /** Grace period between SIGTERM and SIGKILL on down() (default 5000 ms). */
    killTimeoutMs?: number;
  };
  /** Enable run_in_sandbox exec (arbitrary commands). Default false; when true the report shows a red warning. */
  allowExec?: boolean;
  /** Working directory for sandbox commands. */
  cwd: string;
  up: string;
  down: string;
  /** Command template for logs; `{service}` is substituted. */
  logs?: string;
}

export interface Walkthrough {
  id: string;
  title: string;
  createdAt: string;
  sandbox: SandboxConfig;
  runs: RunRecord[];
  evidence: Evidence[];
  sources: SourceLink[];
  claims: Claim[];
  goal?: string;
  checks?: Check[];
  checkResults?: CheckResult[];
  findings?: Finding[];
  signoff?: SignOff;
  /** watch_alerts runs: window, evidence, which firing alerts attached where, which stayed unmatched. */
  alertWatches?: AlertWatch[];
  /** Last entry of the append-only run_cli command log (commands.jsonl); detects tail truncation. */
  commandLogHead?: { seq: number; hash: string };
}

export interface AlertWatch {
  watchId: string; evidenceId: string; start: string; end: string; polls: number;
  /** completed = window ran out; stopped_early = collected before the deadline; interrupted = poller died (partial data). */
  outcome: "completed" | "stopped_early" | "interrupted";
  finalizedBy: "collect" | "sign_off";
  /** Distinct poll errors (endpoint/policy rejections, non-success responses). A window with only errors is NOT quiet. */
  errors?: string[];
  matched: { alertname: string; checkIds: string[]; findingId: string; attached: boolean; activeAt?: string; firstSeenAt?: string }[];
  unmatched: { alertname: string; labels: Record<string, string>; severity: string; activeAt?: string; firstSeenAt?: string }[];
  pendingSeen: number;
}
