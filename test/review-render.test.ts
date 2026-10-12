import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Redactor, renderWalkthrough } from "../src/core/index.js";
import { mockCore, SB } from "./helpers.js";

const setup = async (secrets: string[] = []) => {
  const { core } = mockCore({ redactor: new Redactor(secrets) });
  const w = await core.startWalkthrough({ title: "t", sandbox: SB });
  const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
  await core.recordClaim(w.id, { question: "q1", conclusion: "c1", kind: "observed", evidenceIds: [ev.id] });
  await core.recordClaim(w.id, { question: "q2", conclusion: "c2", kind: "inferred" });
  await core.recordClaim(w.id, { question: "q3", conclusion: "c3", kind: "inferred" });
  return { core, id: w.id };
};
const section = (html: string, id: string) => html.split(`id="${id}"`)[1].split("</section>")[0];

describe("rendered review status", () => {
  it("shows imported decisions and notes under each claim", async () => {
    const { core, id } = await setup();
    await core.importReview({ walkthroughId: id, decisions: [
      { claimId: "claim-1", decision: "agree", note: "matches the screenshot" },
      { claimId: "claim-2", decision: "flag", note: "needs a runtime check" },
    ] });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(section(html, "claim-1")).toContain("matches the screenshot");
    expect(section(html, "claim-1")).toContain('class="review agree"');
    expect(section(html, "claim-2")).toContain("needs a runtime check");
    expect(section(html, "claim-2")).toContain('class="review flag"');
    expect(section(html, "claim-3")).toContain("pending");
  });

  it("summary counts are correct", async () => {
    const { core, id } = await setup();
    await core.importReview({ walkthroughId: id, decisions: [
      { claimId: "claim-1", decision: "agree" }, { claimId: "claim-2", decision: "agree" }, { claimId: "claim-3", decision: "flag" },
    ] });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    const n = (k: string) => html.match(new RegExp(`data-count="${k}">(\\d+)<`))![1];
    expect([n("observed"), n("inferred"), n("agreed"), n("flagged")]).toEqual(["1", "2", "2", "1"]);
  });

  it("escapes HTML injection and redacts secrets in notes", async () => {
    const { core, id } = await setup(["note-secret-123"]);
    await core.importReview({ walkthroughId: id, decisions: [
      { claimId: "claim-1", decision: "flag", note: `<img src=x onerror=alert(1)><script>x()</script> key note-secret-123` },
    ] });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>x()");
    expect(section(html, "claim-1")).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("note-secret-123");
    expect(section(html, "claim-1")).toContain("[REDACTED]");
  });
});

describe("note prefill", () => {
  it("re-rendered HTML prefills notes so a re-export keeps them", async () => {
    const { core, id } = await setup();
    const note = `keep me "quoted" <b>&</b>`;
    await core.importReview({ walkthroughId: id, decisions: [{ claimId: "claim-1", decision: "flag", note }] });
    const html = readFileSync(renderWalkthrough(core, id), "utf8");
    // Simulate the page's export: read prior decision + prefilled note input per claim.
    const unesc = (s: string) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
    const decisions = [...html.matchAll(/data-claim="([^"]+)" data-prior="([^"]+)"[\s\S]*?<input class="note"[^>]*value="([^"]*)"/g)]
      .map(([, claimId, decision, value]) => ({ claimId, decision, note: unesc(value) }));
    expect(decisions).toEqual([{ claimId: "claim-1", decision: "flag", note }]);
    expect(html).not.toContain("<b>&</b>");
    await core.importReview({ walkthroughId: id, decisions });
    expect(core.load(id).claims[0].review).toEqual({ decision: "flag", note });
  });
});
