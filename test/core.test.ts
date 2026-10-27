import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough } from "../src/core/index.js";
import { NotImplementedMetricsAdapter } from "../src/core/metrics.js";
import { secretValues } from "../src/core/redact.js";
import { sha256File } from "../src/core/walkthrough.js";
import { LOCAL_REPLAY, mockCore, SB } from "./helpers.js";

describe("core", () => {
  it("stores evidence in the fixed format under .walkthrough/<id>/evidence", async () => {
    const { core, root } = mockCore({ replay: LOCAL_REPLAY });
    const w = core.startWalkthrough({ title: "t", sandbox: SB, id: "wt-fixed" });
    const ev = await core.captureEvidence(w.id, { type: "screenshot", url: "http://localhost:3000/" });
    expect(Object.keys(ev).sort()).toEqual(["createdAt", "executedBy", "id", "kind", "path", "sha256", "source", "type"]);
    const file = join(root, ".walkthrough", "wt-fixed", ev.path);
    expect(ev.path).toBe("evidence/ev-1.png");
    expect(sha256File(file)).toBe(ev.sha256);
    const logs = await core.captureEvidence(w.id, { type: "logs", service: "web" });
    expect(logs).toMatchObject({ id: "ev-2", type: "logs", source: "docker:web" });
  });

  it("records sandbox runs and source links", async () => {
    const { core } = mockCore();
    const w = core.startWalkthrough({ title: "t", sandbox: { ...SB, allowExec: true } });
    expect((await core.runInSandbox(w.id, "up")).command).toBe(SB.up);
    expect((await core.runInSandbox(w.id, "exec", "echo hi")).output).toContain("echo,hi"); // spawned as argv, not a shell line
    await expect(core.runInSandbox(w.id, "exec")).rejects.toThrow();
    expect((await core.linkSource(w.id, { file: "a.ts", line: 3 })).id).toBe("src-1");
    await expect(core.linkSource(w.id, { file: "a.ts", line: 0 })).rejects.toThrow();
    expect(core.load(w.id).runs).toHaveLength(2);
  });

  it("rejects path-like ids", async () => {
    const { core } = mockCore();
    expect(() => core.load("../etc")).toThrow(/invalid walkthrough id/);
  });

  it("renders HTML with badges, buttons and export, escaping content", async () => {
    const { core } = mockCore({ logs: "<script>alert(1)</script>" });
    const w = core.startWalkthrough({ title: "Demo", sandbox: SB });
    const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
    const src = await core.linkSource(w.id, { file: "server.js", line: 7 });
    await core.recordClaim(w.id, { question: "Q1", conclusion: "C1", kind: "observed", evidenceIds: [ev.id], sourceIds: [src.id] });
    await core.recordClaim(w.id, { question: "Q2", conclusion: "C2", kind: "inferred" });
    const html = readFileSync(renderWalkthrough(core, w.id), "utf8");
    expect(html).toContain('class="badge observed"');
    expect(html).toContain('class="badge inferred"');
    expect(html).toContain("导出 review.json");
    expect(html).toContain('data-d="agree"');
    expect(html).toContain('data-d="flag"');
    expect(html).toContain("server.js:7");
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("imports review decisions back into the walkthrough JSON", async () => {
    const { core, root } = mockCore();
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.recordClaim(w.id, { question: "q", conclusion: "c", kind: "inferred" });
    const f = join(root, "review.json");
    writeFileSync(f, JSON.stringify({ walkthroughId: w.id, decisions: [{ claimId: "claim-1", decision: "flag", note: "why?" }] }));
    expect(await core.importReview(JSON.parse(readFileSync(f, "utf8")))).toEqual({ id: w.id, applied: 1 });
    expect(core.load(w.id).claims[0].review).toEqual({ decision: "flag", note: "why?" });
    await expect(core.importReview({ walkthroughId: w.id, decisions: [{ claimId: "claim-9", decision: "agree" }] })).rejects.toThrow();
    await expect(core.importReview({ walkthroughId: w.id, decisions: [{ claimId: "claim-1", decision: "maybe" }] })).rejects.toThrow();
    expect(existsSync(join(core.dir(w.id), "walkthrough.json"))).toBe(true);
  });

  it("redactor picks secret-looking env vars only", () => {
    expect(secretValues({ API_KEY: "abcd1234", HOME: "/home/x", DB_PASSWORD: "pw-long" })).toEqual(["abcd1234", "pw-long"]);
    expect(new Redactor(["s3cr3t"]).text("x s3cr3t y")).toBe("x [REDACTED] y");
  });

  it("metrics adapter is a read-only stub in v1", async () => {
    await expect(new NotImplementedMetricsAdapter().query("up")).rejects.toThrow(/not configured/);
  });
});
