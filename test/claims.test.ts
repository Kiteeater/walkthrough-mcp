import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ClaimRejectedError } from "../src/core/index.js";
import { mockCore, SB } from "./helpers.js";

describe("record_claim rejection", () => {
  const setup = async () => {
    const { core } = mockCore();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
    return { core, w, ev };
  };
  const q = { question: "q?", conclusion: "c", kind: "observed" as const };

  it("rejects observed claim without evidence", async () => {
    const { core, w } = await setup();
    expect(() => core.recordClaim(w.id, q)).toThrow(ClaimRejectedError);
    expect(() => core.recordClaim(w.id, { ...q, evidenceIds: [] })).toThrow(/at least one evidence/);
  });

  it("rejects observed claim referencing a missing evidence id", async () => {
    const { core, w } = await setup();
    expect(() => core.recordClaim(w.id, { ...q, evidenceIds: ["ev-99"] })).toThrow(/evidence not found: ev-99/);
  });

  it("rejects observed claim when evidence hash no longer matches", async () => {
    const { core, w, ev } = await setup();
    appendFileSync(join(core.dir(w.id), ev.path), "tampered");
    expect(() => core.recordClaim(w.id, { ...q, evidenceIds: [ev.id] })).toThrow(/hash mismatch/);
  });

  it("accepts valid observed and evidence-free inferred claims", async () => {
    const { core, w, ev } = await setup();
    expect(core.recordClaim(w.id, { ...q, evidenceIds: [ev.id] }).id).toBe("claim-1");
    expect(core.recordClaim(w.id, { ...q, kind: "inferred" }).kind).toBe("inferred");
    expect(core.load(w.id).claims).toHaveLength(2);
  });

  it("rejects unknown source ids and bad kinds", async () => {
    const { core, w, ev } = await setup();
    expect(() => core.recordClaim(w.id, { ...q, evidenceIds: [ev.id], sourceIds: ["src-9"] })).toThrow(/source link not found/);
    expect(() => core.recordClaim(w.id, { ...q, kind: "guess" as never })).toThrow(ClaimRejectedError);
  });
});
