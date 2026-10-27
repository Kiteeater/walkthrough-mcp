import { existsSync, readdirSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Redactor, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { run } from "../src/core/sandbox.js";

const cfg = { cwd: ".", up: "true", down: "true" };

describe("durability and runtime bounds", () => {
  it("writes an intact manifest without leaving temporary snapshots", () => {
    const root = mkdtempSync(join(tmpdir(), "wt-atomic-"));
    const core = new WalkthroughCore({
      root,
      sandboxFactory: () => ({ up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" }),
      capturer: { screenshot: async () => undefined },
      redactor: new Redactor([]),
    });
    const w = core.startWalkthrough({ title: "atomic", sandbox: cfg });
    expect(() => JSON.parse(readFileSync(join(core.dir(w.id), "walkthrough.json"), "utf8"))).not.toThrow();
    expect(readdirSync(core.dir(w.id)).some((x) => x.startsWith("walkthrough.json.tmp-"))).toBe(false);
  });

  it("keeps log delta cursors across core restarts", async () => {
    const root = mkdtempSync(join(tmpdir(), "wt-cursor-"));
    let logs = "first\n";
    const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => logs };
    const factory = () => sandbox;
    const make = () => new WalkthroughCore({ root, sandboxFactory: factory, capturer: { screenshot: async () => undefined }, redactor: new Redactor([]) });
    const first = make();
    const id = first.startWalkthrough({ title: "cursor", sandbox: cfg }).id;
    await first.captureEvidence(id, { type: "logs", service: "app", delta: true });
    logs = "first\nsecond\n";
    const second = make();
    const ev = await second.captureEvidence(id, { type: "logs", service: "app", delta: true });
    expect(readFileSync(join(second.dir(id), ev.path), "utf8")).toBe("second\n");
    expect(existsSync(join(second.dir(id), "walkthrough.json"))).toBe(true);
  });

  it("caps command output by bytes rather than JavaScript characters", async () => {
    const r = await run(process.execPath, ["-e", "process.stdout.write('😀😀😀')"], { cwd: process.cwd(), env: process.env, timeoutMs: 5_000, maxBytes: 5 });
    expect(Buffer.byteLength(r.output)).toBeLessThanOrEqual(5);
  });
});
