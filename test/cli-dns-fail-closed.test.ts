// run_cli connector targets: the core check (assertNoCoreBlockedTargets) is the ONLY check before an external CLI
// connects by itself, so it fails closed, and its single DNS answer is what the CLI gets:
//  - resolver error / timeout → refused, the CLI never starts;
//  - lockable connectors (mqadmin `-n host:port`) get the checked IP in argv, so a second DNS answer cannot reach them;
//  - non-lockable HTTPS CLIs (aliyun): no host outside the connector's allowHosts may appear in argv.
// Injected resolvers only; nothing is resolved or connected for real. 34.142.135.39 appears only as a resolver answer.
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CliRejectedError, PRESET_CONNECTORS, Redactor, WalkthroughCore, type ConnectorConfig, type Sandbox } from "../src/core/index.js";

const sandbox: Sandbox = { up: async () => ({ exitCode: 0, output: "" }), down: async () => ({ exitCode: 0, output: "" }), exec: async () => ({ exitCode: 0, output: "" }), logs: async () => "" };
const preset = (n: string) => PRESET_CONNECTORS.find((c) => c.name === n)!;

/** Fake CLI: records the argv of every non-version call to calls.jsonl. */
function fakeCli(): { bin: string; calls: () => string[][] } {
  const dir = mkdtempSync(join(tmpdir(), "wt-dnsbin-"));
  const bin = join(dir, "fakecli");
  writeFileSync(bin, `#!/usr/bin/env node\nconst a=process.argv.slice(2);if(a[0]==="--version"||a[0]==="version"){console.log("1");process.exit(0)}\nrequire("fs").appendFileSync(require("path").join(__dirname,"calls.jsonl"),JSON.stringify(a)+"\\n");console.log("ok")\n`);
  chmodSync(bin, 0o755);
  const f = join(dir, "calls.jsonl");
  return { bin, calls: () => (existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as string[]) : []) };
}
function mk(connector: ConnectorConfig, resolver: (h: string) => Promise<string>) {
  const root = mkdtempSync(join(tmpdir(), "wt-dns-"));
  const core = new WalkthroughCore({ root, sandboxFactory: () => sandbox, capturer: { screenshot: async () => undefined }, redactor: new Redactor([]), resolver, connectors: [connector] });
  return { core, id: core.startWalkthrough({ title: "t", sandbox: { cwd: root, up: "true", down: "true" } }).id };
}

describe("run_cli target check fails closed on DNS failure", () => {
  const mq = (bin: string): ConnectorConfig => ({ ...preset("mqadmin"), binary: bin, namesrvs: ["ns.example.test:9876"] });
  it("resolver times out (3 s) → refused, the CLI never starts", async () => {
    const { bin, calls } = fakeCli();
    const { core, id } = mk(mq(bin), () => new Promise<string>(() => {}));
    const p = core.runCli(id, { connector: "mqadmin", argv: ["topicList"] });
    await expect(p).rejects.toBeInstanceOf(CliRejectedError);
    await expect(p).rejects.toThrow(/ns\.example\.test could not be resolved .*timed out.*refused/);
    expect(calls()).toEqual([]);
  }, 15_000);
  it("resolver errors → refused, the CLI never starts", async () => {
    const { bin, calls } = fakeCli();
    const { core, id } = mk(mq(bin), async () => { throw new Error("ENOTFOUND"); });
    const p = core.runCli(id, { connector: "mqadmin", argv: ["topicList"] });
    await expect(p).rejects.toBeInstanceOf(CliRejectedError);
    await expect(p).rejects.toThrow(/ns\.example\.test could not be resolved .*\(ENOTFOUND\); refused/);
    expect(calls()).toEqual([]);
  });
  it("the same holds for a host named in agent argv (allowlisted, but unresolvable)", async () => {
    const { bin, calls } = fakeCli();
    const tool: ConnectorConfig = { name: "tool", binary: bin, allow: [["get"]], args: { get: ["--host"] }, allowHosts: ["api.example.test"] };
    const { core, id } = mk(tool, async () => { throw new Error("SERVFAIL"); });
    await expect(core.runCli(id, { connector: "tool", argv: ["get", "--host", "api.example.test"] })).rejects.toThrow(/api\.example\.test could not be resolved .*\(SERVFAIL\)/);
    expect(calls()).toEqual([]);
  });
});

describe("lockable connector (mqadmin name server): the CLI gets the IP we checked", () => {
  // First answer: a public test address (TEST-NET-3). Any later answer: the core-blocked IP (DNS rebinding).
  const rebinding = () => { let n = 0; return { resolver: async () => (n++ === 0 ? "203.0.113.7" : "34.142.135.39"), count: () => n }; };
  it.each([[["topicList"]], [["topicStatus", "-t", "orders", "-n", "ns.example.test:9876"]], [["topicStatus", "-t", "orders", "-n=ns.example.test:9876"]]])("argv %j → -n is the checked IP, never the name or 34.142.135.39", async (argv) => {
    const { bin, calls } = fakeCli();
    const r = rebinding();
    const { core, id } = mk({ ...preset("mqadmin"), binary: bin, namesrvs: ["ns.example.test:9876"] }, r.resolver);
    await core.runCli(id, { connector: "mqadmin", argv });
    expect(calls()).toHaveLength(1);
    const ran = calls()[0];
    expect(ran.some((a) => a === "203.0.113.7:9876" || a === "-n=203.0.113.7:9876")).toBe(true);
    expect(ran.join(" ")).not.toContain("ns.example.test");
    expect(ran.join(" ")).not.toContain("34.142.135.39");
    expect(r.count()).toBe(1); // resolved once; nothing re-resolves
  });
});

describe("non-lockable connector (aliyun HTTPS endpoint): only allowlisted hosts in argv", () => {
  it.each([
    [["sls", "get-logs", "--project", "evil.example.com", "--logstore", "l"]],
    [["sls", "get-logs", "--project", "p", "--logstore", "l", "--query", "https://evil.example.com/x"]],
    [["sls", "get-logs", "--project", "p", "--logstore", "l", "--topic", "10.0.0.9"]],
  ])("argv %j names a host outside allowHosts → refused before DNS, the CLI never starts", async (argv) => {
    const { bin, calls } = fakeCli();
    let resolved = 0;
    const { core, id } = mk({ ...preset("aliyun"), binary: bin, profile: "ro", allowHosts: ["logs.example.test"] }, async () => { resolved++; return "203.0.113.7"; });
    const p = core.runCli(id, { connector: "aliyun", argv });
    await expect(p).rejects.toBeInstanceOf(CliRejectedError);
    await expect(p).rejects.toThrow(/not in the connector's allowHosts/);
    expect(calls()).toEqual([]);
    expect(resolved).toBe(0);
  });
  it("the endpoint cannot be set by the agent (--endpoint is on no allowlist)", async () => {
    const { bin, calls } = fakeCli();
    const { core, id } = mk({ ...preset("aliyun"), binary: bin, profile: "ro" }, async () => "203.0.113.7");
    await expect(core.runCli(id, { connector: "aliyun", argv: ["sls", "get-logs", "--project", "p", "--endpoint", "logs.example.test"] })).rejects.toThrow(/argument not in allowlist/);
    expect(calls()).toEqual([]);
  });
  it("control: an allowlisted host and plain values (timestamps, --line 100) run", async () => {
    const { bin, calls } = fakeCli();
    const { core, id } = mk({ ...preset("aliyun"), binary: bin, profile: "ro", allowHosts: ["logs.example.test"] }, async () => "203.0.113.7");
    await core.runCli(id, { connector: "aliyun", argv: ["sls", "get-logs", "--project", "logs.example.test", "--logstore", "l", "--from", "1717000000", "--to", "1717000600", "--line", "100"] });
    expect(calls()).toHaveLength(1);
  });
});
