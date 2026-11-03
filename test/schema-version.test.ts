// walkthrough.json schemaVersion: v1 (no field) is upgraded in memory on load; signed-off v1 files are never
// rewritten; unknown versions / malformed fields are refused with a message that names the path, not the value.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { renderWalkthrough } from "../src/core/index.js";
import { MigrationError, SignedOffError } from "../src/core/errors.js";
import { mockCore, SB } from "./helpers.js";

const MARK = "ZZ-MARKER-7f3c"; // must never appear in an error message
const sha = (f: string) => createHash("sha256").update(readFileSync(f)).digest("hex");

/** Build a real walkthrough, then rewrite its file as v1 (no schemaVersion), optionally signed off. */
const v1 = async (signed: boolean) => {
  const { core } = mockCore();
  const w = await core.startWalkthrough({ title: "t", sandbox: SB });
  const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
  await core.recordClaim(w.id, { question: "q1", conclusion: "c1", kind: "observed", evidenceIds: [ev.id] });
  await core.recordClaim(w.id, { question: "q2", conclusion: "c2", kind: "inferred" });
  const file = join(core.dir(w.id), "walkthrough.json");
  const { schemaVersion, ...raw } = JSON.parse(readFileSync(file, "utf8"));
  expect(schemaVersion).toBe(2);
  raw.claims[0].review = { decision: "agree", note: "ok" };
  if (signed) raw.signoff = { decision: "accept", comment: "looks right" };
  writeFileSync(file, JSON.stringify(raw, null, 2));
  return { core, id: w.id as string, file, ev };
};

const corrupt = (file: string, edit: (raw: any) => void) => {
  const raw = JSON.parse(readFileSync(file, "utf8")); edit(raw); writeFileSync(file, JSON.stringify(raw, null, 2));
};

describe("walkthrough.json schemaVersion", () => {
  it("new files are v2", async () => {
    const { core } = mockCore();
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    expect(w.schemaVersion).toBe(2);
    expect(JSON.parse(readFileSync(join(core.dir(w.id), "walkthrough.json"), "utf8")).schemaVersion).toBe(2);
  });

  it("a signed-off v1 file keeps its exact bytes through load, render and refused writes; evidence still verifies", async () => {
    const { core, id, file, ev } = await v1(true);
    const before = sha(file);
    const w = core.load(id);
    expect(w.schemaVersion).toBe(2);
    expect(w.signoff).toEqual({ decision: "accept", comment: "looks right" });
    expect(w.claims[0].review).toEqual({ decision: "agree", note: "ok" });
    readFileSync(renderWalkthrough(core, id), "utf8");
    core.load(id);
    await expect(core.recordClaim(id, { question: "q", conclusion: "c", kind: "inferred" })).rejects.toBeInstanceOf(SignedOffError);
    await expect(core.signOff(id, { decision: "reject" })).rejects.toBeInstanceOf(SignedOffError);
    expect(() => core.save(core.load(id))).toThrow(SignedOffError); // backstop below withLock
    expect(sha(file)).toBe(before);
    expect(sha(join(core.dir(id), ev.path))).toBe(ev.sha256);
  });

  it("unknown versions and malformed fields throw MigrationError naming the path, never the value", async () => {
    const cases: [string, (raw: any) => void, RegExp][] = [
      ["version 3", (r) => { r.schemaVersion = 3; r.title = MARK; }, /unsupported schemaVersion/],
      ["version string", (r) => { r.schemaVersion = MARK; }, /unsupported schemaVersion/],
      ["claim review", (r) => { r.claims[1].review = { decision: MARK }; }, /claims\[1\]\.review\.decision/],
      ["review note", (r) => { r.claims[0].review = { decision: "flag", note: { v: MARK } }; }, /claims\[0\]\.review\.note/],
      ["signoff", (r) => { r.signoff = { decision: MARK, comment: MARK }; }, /signoff\.decision/],
      ["claims", (r) => { r.claims = MARK; }, /invalid field claims$/],
      ["id", (r) => { r.id = { v: MARK }; }, /invalid field id$/],
    ];
    for (const [name, edit, path] of cases) {
      const { core, id, file } = await v1(false);
      corrupt(file, edit);
      let err: unknown;
      try { core.load(id); } catch (e) { err = e; }
      expect(err, name).toBeInstanceOf(MigrationError);
      expect((err as Error).message, name).toMatch(path);
      expect((err as Error).message, name).not.toContain(MARK);
      expect((err as Error).message, name).not.toContain("ZZ-");
    }
  });

  it("an unsigned v1 file becomes v2 on its next save, and loads the same afterwards", async () => {
    const { core, id, file } = await v1(false);
    const upgraded = core.load(id);
    expect(JSON.parse(readFileSync(file, "utf8")).schemaVersion).toBeUndefined(); // reading did not write back
    await core.withLock(id, () => core.save(core.load(id)));
    const disk = JSON.parse(readFileSync(file, "utf8"));
    expect(disk.schemaVersion).toBe(2);
    expect(Object.keys(disk)[0]).toBe("schemaVersion");
    expect(core.load(id)).toEqual(upgraded);
    const once = sha(file);
    await core.withLock(id, () => core.save(core.load(id)));
    expect(sha(file)).toBe(once);
  });
});
