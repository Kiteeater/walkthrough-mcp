import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cliArgv, CliRejectedError, PRESET_CONNECTORS, type ConnectorConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const aliyun = PRESET_CONNECTORS.find((c) => c.name === "aliyun")!;
const mq = PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!;
const bad = (c: ConnectorConfig, argv: string[]) => expect(() => cliArgv(c, argv)).toThrow(CliRejectedError);

describe("aliyun per-subcommand argument allowlist (B1)", () => {
  const base = ["sls", "GetLogs", "--project", "p", "--logstore", "app"];
  it.each([
    ["--endpoint", "http://evil"], ["--insecure", "true"], ["--body-file", "/etc/passwd"], ["--config-path", "/tmp/x.json"],
    ["--Endpoint", "http://evil"], ["--ENDPOINT", "http://evil"], ["--Insecure", "true"], ["--retry-count", "9"], ["--secure", "false"],
    ["--mode", "AK"], ["--profile", "x"], ["--access-key-id", "x"], ["--sts-token", "x"], ["-k", "x"],
  ])("rejects %s (separate and =value forms)", (flag, value) => {
    bad(aliyun, [...base, flag, value]);
    bad(aliyun, [...base, `${flag}=${value}`]);
  });
  it("rejects the exact reviewer exploit", () => bad(aliyun, ["sls", "GetLogs", "--endpoint", "http://evil", "--insecure"]));
  it("rejects bare flags, positional args, missing values and flag-as-value smuggling", () => {
    bad(aliyun, [...base, "--insecure"]);
    bad(aliyun, [...base, "positional"]);
    bad(aliyun, [...base, "--query"]);
    bad(aliyun, [...base, "--query", "--endpoint=http://evil"]);
    bad(aliyun, ["sls", "GetLogs", "--endpoint", "http://evil", "--project", "p"]);
  });
  it("flags allowed for one subcommand are not allowed for another", () => bad(aliyun, ["sls", "ListProject", "--logstore", "app"]));
  it("still accepts legit read subcommands", () => {
    expect(cliArgv(aliyun, [...base, "--from", "1", "--to", "2", "--query", "status: 500"])).toEqual([...base, "--from", "1", "--to", "2", "--query", "status: 500"]);
    expect(cliArgv(aliyun, ["sls", "GetLogs", "--project=p", "--query=status: 500 and -x"])).toBeTruthy();
    expect(cliArgv(aliyun, ["sls", "ListProject"])).toEqual(["sls", "ListProject"]);
    expect(cliArgv(aliyun, ["cms", "DescribeMetricList", "--Namespace", "acs_ecs_dashboard", "--MetricName", "CPUUtilization"])).toBeTruthy();
  });
  it("--region is rejected by default and only allowed from the config region allowlist", () => {
    bad(aliyun, [...base, "--region", "cn-hangzhou"]);
    const cfg: ConnectorConfig = { ...aliyun, regions: ["cn-hangzhou"], args: { ...aliyun.args, "sls GetLogs": [...aliyun.args!["sls GetLogs"], "--region"] } };
    expect(cliArgv(cfg, [...base, "--region", "cn-hangzhou"])).toBeTruthy();
    expect(cliArgv(cfg, [...base, "--region=cn-hangzhou"])).toBeTruthy();
    bad(cfg, [...base, "--region", "us-west-1"]);
    bad(cfg, [...base, "--region=CN-HANGZHOU"]);
  });
});

describe("mqadmin also uses an allowlist (same denylist pattern converted)", () => {
  it("accepts listed flags, rejects others", () => {
    expect(cliArgv(mq, ["topicStatus", "-n", "ns:9876", "-t", "orders"])).toBeTruthy();
    bad(mq, ["topicList", "-n", "ns:9876", "-t", "x"]);
    bad(mq, ["clusterList", "--namesrvAddr", "evil:9876"]);
    bad(mq, ["topicList", "-N", "x"]);
  });
});

describe("run_cli child env never carries ALIBABA_CLOUD_* / ALICLOUD_* vars", () => {
  it("strips them even when present in the parent env and listed in passEnv", async () => {
    const bin = mkdtempSync(join(tmpdir(), "wt-env-"));
    const p = join(bin, "aliyun");
    writeFileSync(p, `#!/usr/bin/env node
if(process.argv[2]==="--version"){console.log("aliyun 0");process.exit(0)}
require("fs").writeFileSync(require("path").join(__dirname,"env.json"),JSON.stringify(process.env));`);
    chmodSync(p, 0o755);
    const names = ["ALIBABA_CLOUD_ENDPOINT", "ALIBABA_CLOUD_REGION_ID", "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY", "alibaba_cloud_profile", "WT_OK_VAR"];
    for (const n of names) process.env[n] = "http://evil";
    try {
      const { core, root } = mockCore({ connectors: [{ ...aliyun, binary: p, passEnv: names }] });
      const id = (await core.startWalkthrough({ title: "env", sandbox: { cwd: root, up: "true", down: "true", local: { passEnv: names } } as never })).id;
      await core.runCli(id, { connector: "aliyun", argv: ["sls", "ListProject"] });
      const env = JSON.parse(readFileSync(join(bin, "env.json"), "utf8")) as Record<string, string>;
      for (const n of Object.keys(env)) expect(n).not.toMatch(/^(ALIBABA_CLOUD_|ALICLOUD_)/i);
      expect(env.WT_OK_VAR).toBe("http://evil");
      await expect(core.runCli(id, { connector: "aliyun", argv: ["sls", "ListProject"], env: { ALIBABA_CLOUD_ENDPOINT: "x" } } as never)).rejects.toThrow(/env/);
    } finally { for (const n of names) delete process.env[n]; }
  });
});
