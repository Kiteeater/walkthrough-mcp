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

export interface SandboxConfig {
  /** Working directory for compose commands. */
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
