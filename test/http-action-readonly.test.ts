import { describe, expect, it } from "vitest";
import { httpSource } from "../src/core/sources.js";

const ctx = { replay: { allowHosts: ["example.test"] }, resolver: async () => "203.0.113.10" };

describe("http action read-only contract", () => {
  it.each([
    ["POST", "HTTP action is read-only; POST is not allowed"],
    ["PUT", "HTTP action is read-only; PUT is not allowed"],
    ["PATCH", "HTTP action is read-only; PATCH is not allowed"],
    ["DELETE", "HTTP action is read-only; DELETE is not allowed"],
  ])("blocks %s before any network request", async (method, reason) => {
    const out = await httpSource.run({ type: "http", method, url: "http://example.test/" }, ctx);
    expect(out.kind).toBe("blocked");
    expect(out.blockedReason).toBe(reason);
    expect(out.status).toBeUndefined();
    expect(out.evidenceText).toContain(`request blocked: ${reason}`);
  });

  it("blocks request bodies even for GET", async () => {
    const out = await httpSource.run({ type: "http", method: "GET", url: "http://example.test/", body: "payload" }, ctx);
    expect(out.kind).toBe("blocked");
    expect(out.blockedReason).toMatch(/request body/);
  });

  it.each(["Authorization", "Cookie", "X-Api-Key", "X-Session-Id", "X-Csrf-Token"]) (
    "blocks sensitive header %s",
    async (header) => {
      const out = await httpSource.run({ type: "http", url: "http://example.test/", headers: { [header]: "secret" } }, ctx);
      expect(out.kind).toBe("blocked");
      expect(out.blockedReason).toContain(`sensitive header ${header}`);
    },
  );

  it("classifies a missing allowlist as blocked instead of a generic failure", async () => {
    const out = await httpSource.run({ type: "http", url: "http://example.test/" }, { replay: undefined });
    expect(out.kind).toBe("blocked");
    expect(out.retryable).toBe(false);
    expect(out.blockedReason).toMatch(/needs replay\.allowHosts/);
  });

  it("classifies transport errors separately from policy blocks", async () => {
    const out = await httpSource.run({ type: "http", url: "http://example.test/" }, { replay: ctx.replay, resolver: async () => { throw new Error("DNS unavailable"); } });
    expect(out.kind).toBe("error");
    expect(out.reason).toBe("DNS unavailable");
    expect(out.retryable).toBe(true);
    expect(out.blockedReason).toBeUndefined();
  });
});
