import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { fmtTime, renderTimeZone } from "../src/core/render.js";
import { SB } from "./helpers.js";

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };

describe("times on the audit page", () => {
  it("static fallback in the configured zone, UTC ISO in the tooltip, re-rendered in the viewer's zone by script", async () => {
    const root = mkdtempSync(join(tmpdir(), "wt-time-"));
    const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async (_u, o) => writeFileSync(o, "png") }, redactor: new Redactor([]), now: () => new Date("2026-10-12T20:00:00Z") });
    const w = core.startWalkthrough({ title: "t", sandbox: SB });
    await core.planChecks(w.id, { goal: "g", checks: [{ id: "a", intent: "a", method: "http", target: "GET /a", expect: { type: "status", value: 200 }, severity_if_fail: "high" }] });
    const ev = await core.captureEvidence(w.id, { type: "submit", checkId: "a", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    await core.recordFinding(w.id, { title: "500", severity: "high", symptom: "s", check_id: "a", root_cause_chain: [{ claim: "c", kind: "observed", evidence_ids: [ev.id] }] });
    const taipei = readFileSync(renderWalkthrough(core, w.id, { timeZone: "Asia/Taipei" }), "utf8");
    expect(taipei).toContain('<time datetime="2026-10-12T20:00:00.000Z" title="2026-10-12T20:00:00.000Z (UTC)">2026-10-13 04:00:00 (Asia/Taipei)</time>');
    expect(taipei).toMatch(/querySelectorAll\("time\[datetime\]"\)[^\n]*toLocaleString/);
    const la = readFileSync(renderWalkthrough(core, w.id, { timeZone: "America/Los_Angeles" }), "utf8");
    expect(la).toContain(">2026-10-12 13:00:00 (America/Los_Angeles)</time>");
  });
  it("zone resolution: option > WALKTHROUGH_TZ > TZ > system; invalid zones skipped", () => {
    const old = { a: process.env.WALKTHROUGH_TZ, b: process.env.TZ };
    try {
      process.env.WALKTHROUGH_TZ = "Europe/Berlin"; process.env.TZ = "Asia/Tokyo";
      expect(renderTimeZone("Asia/Taipei")).toBe("Asia/Taipei");
      expect(renderTimeZone()).toBe("Europe/Berlin");
      process.env.WALKTHROUGH_TZ = "Not/AZone";
      expect(renderTimeZone()).toBe("Asia/Tokyo");
      expect(fmtTime(new Date("2026-01-01T00:00:00Z"), "UTC")).toBe("2026-01-01 00:00:00 (UTC)");
    } finally {
      if (old.a === undefined) delete process.env.WALKTHROUGH_TZ; else process.env.WALKTHROUGH_TZ = old.a;
      if (old.b === undefined) delete process.env.TZ; else process.env.TZ = old.b;
    }
  });
});
