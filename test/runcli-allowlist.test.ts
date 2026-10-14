import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cliArgv, CliRejectedError, PRESET_CONNECTORS, type ConnectorConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const aliyun = PRESET_CONNECTORS.find((c) => c.name === "aliyun")!;
const mq = { ...PRESET_CONNECTORS.find((c) => c.name === "mqadmin")!, namesrvs: ["ns:9876"] };
const bad = (c: ConnectorConfig, argv: string[]) => expect(() => cliArgv(c, argv)).toThrow(CliRejectedError);

describe("aliyun per-subcommand argument allowlist (B1)", () => {
  const base = ["sls", "get-logs", "--project", "p", "--logstore", "app"];
  it.each([
    ["--endpoint", "http://evil"], ["--insecure", "true"], ["--body-file", "/etc/passwd"], ["--config-path", "/tmp/x.json"],
    ["--Endpoint", "http://evil"], ["--ENDPOINT", "http://evil"], ["--Insecure", "true"], ["--retry-count", "9"], ["--secure", "false"],
    ["--mode", "AK"], ["--profile", "x"], ["--access-key-id", "x"], ["--sts-token", "x"], ["-k", "x"],
  ])("rejects %s (separate and =value forms)", (flag, value) => {
    bad(aliyun, [...base, flag, value]);
    bad(aliyun, [...base, `${flag}=${value}`]);
  });
  it("rejects the exact reviewer exploit", () => bad(aliyun, ["sls", "get-logs", "--endpoint", "http://evil", "--insecure"]));
  it("rejects bare flags, positional args, missing values and flag-as-value smuggling", () => {
    bad(aliyun, [...base, "--insecure"]);
    bad(aliyun, [...base, "positional"]);
    bad(aliyun, [...base, "--query"]);
    bad(aliyun, [...base, "--query", "--endpoint=http://evil"]);
    bad(aliyun, ["sls", "get-logs", "--endpoint", "http://evil", "--project", "p"]);
  });
  it("flags allowed for one subcommand are not allowed for another", () => bad(aliyun, ["sls", "list-project", "--logstore", "app"]));
  it("still accepts legit read subcommands", () => {
    expect(cliArgv(aliyun, [...base, "--from", "1", "--to", "2", "--query", "status: 500"])).toEqual([...base, "--from", "1", "--to", "2", "--query", "status: 500"]);
    expect(cliArgv(aliyun, ["sls", "get-logs", "--project=p", "--query=status: 500 and x"])).toBeTruthy();
    expect(cliArgv(aliyun, ["sls", "list-project"])).toEqual(["sls", "list-project"]);
    expect(cliArgv(aliyun, ["cms", "DescribeMetricList", "--Namespace", "acs_ecs_dashboard", "--MetricName", "CPUUtilization"])).toBeTruthy();
  });
  it("--region is rejected by default and only allowed from the config region allowlist", () => {
    bad(aliyun, [...base, "--region", "cn-hangzhou"]);
    const cfg: ConnectorConfig = { ...aliyun, regions: ["cn-hangzhou"], args: { ...aliyun.args, "sls get-logs": [...aliyun.args!["sls get-logs"], "--region"] } };
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
      await core.runCli(id, { connector: "aliyun", argv: ["sls", "list-project"] });
      const env = JSON.parse(readFileSync(join(bin, "env.json"), "utf8")) as Record<string, string>;
      for (const n of Object.keys(env)) expect(n).not.toMatch(/^(ALIBABA_CLOUD_|ALICLOUD_)/i);
      expect(env.WT_OK_VAR).toBe("http://evil");
      await expect(core.runCli(id, { connector: "aliyun", argv: ["sls", "list-project"], env: { ALIBABA_CLOUD_ENDPOINT: "x" } } as never)).rejects.toThrow(/env/);
    } finally { for (const n of names) delete process.env[n]; }
  });
});

describe("run_cli positive path with a configured profile", () => {
  it("runs sls get-logs, captures output, logs cli/version/profile/redacted argv/exit/sha256, and the log verifies", async () => {
    const SECRET = "LTAI-fake-secret-positive";
    const bin = mkdtempSync(join(tmpdir(), "wt-pos-"));
    const p = join(bin, "aliyun");
    writeFileSync(p, `#!/usr/bin/env node
if(process.argv[2]==="--version"){console.log("aliyun 3.0.200-fake");process.exit(0)}
console.log("GETLOGS-OK "+process.argv.slice(2).join(" "));`);
    chmodSync(p, 0o755);
    const { core, root } = mockCore({ secrets: [SECRET], connectors: [{ ...aliyun, binary: p, profile: "readonly-prod" }] });
    const id = (await core.startWalkthrough({ title: "pos", sandbox: { cwd: root, up: "true", down: "true" } })).id;
    const argv = ["sls", "get-logs", "--project", "p", "--logstore", "app", "--query", `status: 500 ${SECRET}`];
    const r = await core.runCli(id, { connector: "aliyun", argv });
    expect(r.exitCode).toBe(0);
    expect(r.evidence.executedBy ?? "core").toBe("core");
    expect(r.log).toMatchObject({ connector: "aliyun", exitCode: 0, executedBy: "core", cli: { name: "aliyun", version: "aliyun 3.0.200-fake", profile: "readonly-prod" } });
    expect(r.log.outputSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.log.argv.slice(0, 2)).toEqual(["sls", "get-logs"]);
    expect(r.log.argv.slice(-2)).toEqual(["--profile", "readonly-prod"]);
    expect(JSON.stringify(r.log.argv)).not.toContain(SECRET);
    const ev = readFileSync(join(root, ".walkthrough", id, `evidence/${r.log.evidenceId}.txt`), "utf8");
    expect(ev).toContain("GETLOGS-OK sls get-logs");
    expect(ev).not.toContain(SECRET);
    expect(core.verifyCommandLog(id)).toEqual({ ok: true, entries: 1 });
  });
});

describe("--flag=value gets the same value check as the split form", () => {
  it("rejects flag-looking values in =value form (aliyun and mqadmin)", () => {
    expect(() => cliArgv(aliyun, ["sls", "get-logs", "--project=--endpoint=http://e"])).toThrow(/looks like a flag/);
    expect(() => cliArgv(aliyun, ["sls", "get-logs", "--project", "--endpoint=http://e"])).toThrow(/looks like a flag/);
    expect(() => cliArgv(aliyun, ["sls", "get-logs", "--query=-x"])).toThrow(/looks like a flag/);
    expect(() => cliArgv(mq, ["topicStatus", "-t=--namesrvAddr=evil:9876"])).toThrow(/looks like a flag/);
    expect(() => cliArgv(mq, ["topicStatus", "-t", "-n"])).toThrow(/looks like a flag/);
    expect(cliArgv(mq, ["topicStatus", "-n=ns:9876", "-t=orders"])).toBeTruthy();
  });
});
