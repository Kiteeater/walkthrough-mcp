/**
 * Single source for the core's string-literal enums. Each list is an `as const` tuple; the TypeScript type is derived
 * from it and zod schemas use the same tuple (z.enum(LIST)), so order and members cannot drift. Order is significant:
 * it is the order shown in MCP JSON schemas and error messages, and SEVERITIES is ranked most → least severe.
 */
export const SEVERITIES = Object.freeze(["critical", "high", "medium", "low"] as const);
export type Severity = (typeof SEVERITIES)[number];

export const CHECK_METHODS = Object.freeze(["cli", "mcp", "ui", "http", "script"] as const);
export type CheckMethod = (typeof CHECK_METHODS)[number];

export const EXPECT_TYPES = Object.freeze(["status", "count", "regex", "threshold", "absent", "ui", "metric", "sls_empty"] as const);
export type ExpectType = (typeof EXPECT_TYPES)[number];

export const CLAIM_KINDS = Object.freeze(["observed", "inferred"] as const);
export type ClaimKind = (typeof CLAIM_KINDS)[number];

export const VERDICTS = Object.freeze(["pass", "pass_needs_review", "fail", "inconclusive"] as const);
export type Verdict = (typeof VERDICTS)[number];

export const SANDBOX_BACKENDS = Object.freeze(["compose", "local"] as const);
export type SandboxBackend = (typeof SANDBOX_BACKENDS)[number];

/** `response` = HTTP response / command output / MCP result submitted for a check. */
export const EVIDENCE_TYPES = Object.freeze(["screenshot", "logs", "response", "har", "blocked"] as const);
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

/** Evidence kinds an agent may pass to capture_evidence (design-doc kinds). */
export const SUBMITTABLE_EVIDENCE_KINDS = Object.freeze(["cli_output", "mcp_result", "http", "screenshot", "har", "log"] as const);
/** All evidence kinds: the submittable ones plus those only the core itself produces. */
export const EVIDENCE_KINDS = Object.freeze([...SUBMITTABLE_EVIDENCE_KINDS, "metric", "alert", "blocked"] as const);
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export const REVIEW_DECISIONS = Object.freeze(["agree", "flag"] as const);
export type ReviewDecision = (typeof REVIEW_DECISIONS)[number];

export const SIGNOFF_DECISIONS = Object.freeze(["accept", "reject"] as const);
export type SignOffDecision = (typeof SIGNOFF_DECISIONS)[number];

/** Membership test for a readonly enum tuple with an unknown/string input. */
export const isOneOf = <T extends string>(list: readonly T[], v: unknown): v is T => (list as readonly unknown[]).includes(v);
