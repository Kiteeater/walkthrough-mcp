import { describe, expect, it } from "vitest";
import { CliRejectedError, DEFAULT_ALERTS, PRESET_CONNECTORS } from "../src/core/index.js";
import { cliArgv } from "../src/core/runcli.js";
import { deepFreeze } from "../src/core/domain/freeze.js";
import { mockCore, SB } from "./helpers.js";

const aliyun = PRESET_CONNECTORS.find((c) => c.name === "aliyun")!;
const mq = PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!;
const tamper = (f: () => unknown) => expect(f).toThrow(TypeError);

describe("public presets are deep-frozen (PRESET_CONNECTORS, DEFAULT_ALERTS)", () => {
  it("outer array, every connector, and nested allow / args / denyArgs are frozen", () => {
    const walk = (v: unknown, path: string): void => {
      if (!v || typeof v !== "object") return;
      expect(Object.isFrozen(v), path).toBe(true);
      for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
    };
    walk(PRESET_CONNECTORS, "PRESET_CONNECTORS");
    walk(DEFAULT_ALERTS, "DEFAULT_ALERTS");
  });
  it("tampering throws TypeError and leaves the data unchanged", () => {
    const snap = JSON.stringify([PRESET_CONNECTORS, DEFAULT_ALERTS]);
    tamper(() => PRESET_CONNECTORS.push({ name: "evil", binary: "sh" }));
    tamper(() => { PRESET_CONNECTORS[0] = { name: "evil", binary: "sh" }; });
    tamper(() => mq.allow!.push(["updateTopic"]));
    tamper(() => mq.allow![0].push("x"));
    tamper(() => aliyun.args!["sls get-logs"].push("--endpoint"));
    tamper(() => { aliyun.args!["sls get-logs"] = ["--endpoint"]; });
    tamper(() => { aliyun.denyArgs = []; });
    tamper(() => { aliyun.binary = "sh"; });
    tamper(() => { delete (aliyun as { allow?: unknown }).allow; });
    tamper(() => DEFAULT_ALERTS.push("x"));
    tamper(() => { DEFAULT_ALERTS.length = 0; });
    expect(JSON.stringify([PRESET_CONNECTORS, DEFAULT_ALERTS])).toBe(snap);
  });
  it("after tampering attempts, run_cli still refuses write subcommands and non-allowlisted args", async () => {
    for (const f of [() => mq.allow!.push(["updateTopic"]), () => aliyun.args!["sls get-logs"].push("--endpoint"), () => aliyun.allow!.push(["sls", "delete-project"]), () => { aliyun.denyArgs = []; }]) try { f(); } catch { /* frozen */ }
    expect(() => cliArgv({ ...mq, namesrvs: ["127.0.0.1:9876"] }, ["updateTopic", "-t", "x"])).toThrow(CliRejectedError);
    expect(() => cliArgv(aliyun, ["sls", "get-logs", "--project", "p", "--logstore", "l", "--endpoint", "http://127.0.0.2"])).toThrow(CliRejectedError);
    expect(() => cliArgv(aliyun, ["sls", "delete-project", "--project", "p"])).toThrow(CliRejectedError);
    expect(() => cliArgv(aliyun, ["sls", "get-logs", "--project", "p", "--body", "{}"])).toThrow(CliRejectedError);
    const { core } = mockCore({ resolver: async () => "127.0.0.1" }); // default connectors = PRESET_CONNECTORS
    const id = core.startWalkthrough({ title: "t", sandbox: SB }).id;
    await expect(core.runCli(id, { connector: "aliyun", argv: ["sls", "delete-project", "--project", "p"] })).rejects.toBeInstanceOf(CliRejectedError);
    await expect(core.runCli(id, { connector: "aliyun", argv: ["sls", "get-logs", "--project", "p", "--logstore", "l", "--endpoint", "http://127.0.0.2"] })).rejects.toBeInstanceOf(CliRejectedError);
  });
  it("deepFreeze: returns the same value, freezes nested plain data, leaves primitives alone", () => {
    const o = { a: [1, { b: ["x"] }], c: "s" };
    expect(deepFreeze(o)).toBe(o);
    expect(Object.isFrozen((o.a[1] as { b: string[] }).b)).toBe(true);
    expect(deepFreeze(3)).toBe(3);
    expect(deepFreeze(null)).toBe(null);
  });
  it("variants are made by copying, not in place", () => {
    const before = JSON.stringify(mq);
    const v = { ...mq, namesrvs: ["127.0.0.1:9876"] };
    expect(v.namesrvs).toEqual(["127.0.0.1:9876"]);
    expect(JSON.stringify(mq)).toBe(before);
    expect(mq.namesrvs).not.toContain("127.0.0.1:9876");
  });
});
