// Core error classes moved verbatim from walkthrough.ts, so ops/ modules can import them without a cycle.
export class SignedOffError extends Error { constructor(m: string) { super(m); this.name = "SignedOffError"; } }
export class ClaimRejectedError extends Error {
  constructor(message: string) { super(message); this.name = "ClaimRejectedError"; }
}
/** walkthrough.json has an unknown schemaVersion or a malformed field. The message names the field path only, never its value. */
export class MigrationError extends Error { constructor(m: string) { super(m); this.name = "MigrationError"; } }
