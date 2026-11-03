// walkthrough.json schema versions. v1 = no `schemaVersion` field; v2 = `schemaVersion: 2` (current).
// migrate() is pure: it upgrades in memory only. Unsigned v1 files become v2 on their next locked save();
// signed-off v1 files are never written back (their bytes are what was signed).
// Errors name the field path only (never the value), so a malformed file cannot leak its content into messages.
import { MigrationError } from "../errors.js";
import type { Walkthrough } from "../types.js";
import { isReviewDecision, isSignOffDecision } from "./decisions.js";

export const SCHEMA_VERSION = 2;

type Raw = Record<string, unknown>;
const isObj = (v: unknown): v is Raw => typeof v === "object" && v !== null && !Array.isArray(v);
const bad = (path: string): never => { throw new MigrationError(`walkthrough.json: invalid field ${path}`); };
const optString = (o: Raw, k: string, path: string) => { if (o[k] !== undefined && typeof o[k] !== "string") bad(`${path}.${k}`); };

/** True for a file written before schemaVersion existed. */
export const isV1 = (raw: unknown): boolean => isObj(raw) && !("schemaVersion" in raw);

export function migrate(raw: unknown): Walkthrough {
  if (!isObj(raw)) bad("(root)");
  const o = raw as Raw;
  if ("schemaVersion" in o && o.schemaVersion !== SCHEMA_VERSION) throw new MigrationError("walkthrough.json: unsupported schemaVersion");
  if (typeof o.id !== "string") bad("id");
  for (const k of ["runs", "evidence", "sources", "claims"]) if (!Array.isArray(o[k])) bad(k);
  (o.claims as unknown[]).forEach((c, i) => {
    if (!isObj(c)) bad(`claims[${i}]`);
    const r = (c as Raw).review;
    if (r === undefined) return;
    if (!isObj(r)) bad(`claims[${i}].review`);
    if (!isReviewDecision((r as Raw).decision)) bad(`claims[${i}].review.decision`);
    optString(r as Raw, "note", `claims[${i}].review`);
  });
  const s = o.signoff;
  if (s !== undefined) {
    if (!isObj(s)) bad("signoff");
    const so = s as Raw;
    if (!isSignOffDecision(so.decision)) bad("signoff.decision");
    optString(so, "comment", "signoff");
    const a = so.autoFinalizedWatches;
    if (a !== undefined) {
      if (!Array.isArray(a)) bad("signoff.autoFinalizedWatches");
      (a as unknown[]).forEach((x, i) => {
        if (!isObj(x) || typeof x.watchId !== "string" || typeof x.outcome !== "string") bad(`signoff.autoFinalizedWatches[${i}]`);
      });
    }
  }
  // v1 -> v2: add the version (first key, so new and upgraded files share one layout); every other field is kept as is.
  return { schemaVersion: SCHEMA_VERSION, ...o } as unknown as Walkthrough;
}
