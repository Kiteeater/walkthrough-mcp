/** `response` = captured HTTP response or command output from a check. */
export type EvidenceType = "screenshot" | "logs" | "response";

/** Fixed evidence format. Claims reference evidence only by `id`. */
export interface Evidence {
  id: string;
  type: EvidenceType;
  /** Path relative to the walkthrough directory, e.g. `evidence/ev-1.png`. */
  path: string;
  sha256: string;
  createdAt: string;
  /** What produced it: a URL for screenshots, `docker:<service>` for logs. */
  source: string;
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

export interface Check {
  id: string;
  name: string;
  action: CheckAction;
  /** Typed observation sources captured around the action (e.g. `{source: "log", service}`). */
  observe?: ObserveSpec[];
  /** Shorthand: log services to watch, and alert patterns that must NOT appear in observed logs. */
  watch?: { logs?: string[]; alerts?: string[] };
  /** Verifier type; `rule` (default) ships in v1, `script` / `playwright` / `computer-use` are reserved. */
  verify?: { type: string; [key: string]: unknown };
  /** Expected result. HTTP: `status` (exact) or `statusRange` [min,max]; command: `exitCode`. */
  expect: { status?: number; statusRange?: [number, number]; bodyIncludes?: string; exitCode?: number };
}

export interface CheckResult {
  checkId: string;
  status: "pass" | "fail";
  reasons: string[];
  actual: { status?: number; exitCode?: number };
  evidenceIds: string[];
  findingId?: string;
  at: string;
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface RootCause {
  /** Source link id (file:line) the failure was traced to. */
  sourceId?: string;
  /** Logs evidence id containing the stack trace / error. */
  logEvidenceId?: string;
  /** One-line explanation, e.g. the error message. */
  summary?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  whatHappened: string;
  repro: string[];
  rootCause?: RootCause;
  evidenceIds: string[];
  kind: ClaimKind;
  /** Auto-drafted from a failed check (agent can refine it). */
  draft?: boolean;
  checkId?: string;
}

export interface SignOff {
  decision: "approve" | "reject";
  comment?: string;
}

export interface RunRecord {
  id: string;
  command: string;
  exitCode: number;
  output: string;
  createdAt: string;
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
}
