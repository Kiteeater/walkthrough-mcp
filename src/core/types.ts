export type EvidenceType = "screenshot" | "logs";

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
}
