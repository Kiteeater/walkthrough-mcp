import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { mockCore, SB } from "./helpers.js";

const sha = (f: string) => createHash("sha256").update(readFileSync(f)).digest("hex");

describe("startWalkthrough with a caller-supplied id", () => {
  it("refuses an id that already exists (not signed off); the file bytes stay the same", async () => {
    const { core, root } = mockCore({});
    core.startWalkthrough({ title: "original", sandbox: SB, id: "wt-dup" });
    const file = join(root, ".walkthrough", "wt-dup", "walkthrough.json");
    const before = sha(file);
    let err: unknown;
    try { core.startWalkthrough({ title: "second", sandbox: SB, id: "wt-dup" }); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toBe("walkthrough wt-dup already exists");
    expect((err as Error).message).not.toContain("original");
    expect(sha(file)).toBe(before);
    expect(core.load("wt-dup").title).toBe("original");
  });

  it("two concurrent starts with the same id: exactly one succeeds", async () => {
    const { core, root } = mockCore({});
    const start = (title: string) => Promise.resolve().then(() => core.startWalkthrough({ title, sandbox: SB, id: "wt-race" }));
    const results = await Promise.allSettled([start("a"), start("b")]);
    expect(results.map((r) => r.status).sort()).toEqual(["fulfilled", "rejected"]);
    const won = results.find((r) => r.status === "fulfilled") as PromiseFulfilledResult<{ title: string }>;
    expect(JSON.parse(readFileSync(join(root, ".walkthrough", "wt-race", "walkthrough.json"), "utf8")).title).toBe(won.value.title);
  });
});
