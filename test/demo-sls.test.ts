import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cliArgv, PRESET_CONNECTORS } from "../src/core/index.js";
// @ts-expect-error plain ESM helper without types
import { writeMockAliyun } from "../examples/trace-demo/mock-aliyun.mjs";

// Committed demo sample (examples/output-trace, regenerated from `npm run demo`'s path); CI asserts the same live.
const dir = join(__dirname, "..", "examples", "output-trace");
const w = JSON.parse(readFileSync(join(dir, "walkthrough.json"), "utf8"));
const html = readFileSync(join(dir, "index.html"), "utf8");
const f = w.findings.find((x: { severity: string }) => x.severity === "high");
const ev = (id: string) => w.evidence.find((e: { id: string }) => e.id === id);
const slsItem = () => f.ruled_out.find((r: { claim: string }) => /排除基础设施问题/.test(r.claim));

describe("demo: cloud logs (aliyun sls GetLogsV2) checked through the real aliyun preset and ruled out", () => {
  it("ruled-out item + core evidence whose sha256 recomputes from the file", () => {
    const r = slsItem();
    expect(r.claim).toMatch(/^查过 SLS 日志，这段时间没有基础设施层报错，排除基础设施问题/);
    const e = ev(r.evidence_ids[0]);
    expect(e).toMatchObject({ kind: "cli_output", executedBy: "core" });
    expect(e.source).toMatch(/^run_cli:aliyun sls GetLogsV2 --project demo-prod-logs --logstore infra --from \d+ --to \d+ --query layer: infra and level: ERROR --profile demo-readonly$/);
    const body = JSON.parse(readFileSync(join(dir, e.path), "utf8").split(/^exit 0\n\n/m)[1]);
    expect(body.meta.progress).toBe("Complete");
    expect(body.data).toEqual([]);
    expect(createHash("sha256").update(readFileSync(join(dir, e.path))).digest("hex")).toBe(e.sha256);
    expect(w.checkResults.find((x: { checkId: string }) => x.checkId === r.check_id).status).toBe("pass");
    expect(html).toContain(`data-evidence="${e.id}"`);
    expect(html).toContain(`<code class="sha256" data-sha256="${e.sha256}">${e.sha256}</code>`);
  });

  it("was produced via the aliyun preset: commands.jsonl records cli name/version/profile and the allowlisted argv", () => {
    const e = ev(slsItem().evidence_ids[0]);
    const log = readFileSync(join(dir, "commands.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((l) => l.evidenceId === e.id);
    expect(log).toMatchObject({ connector: "aliyun", outputSha256: e.sha256, executedBy: "core", cli: { name: "aliyun", version: "3.0.277-mock", profile: "demo-readonly" } });
    const preset = PRESET_CONNECTORS.find((c) => c.name === "aliyun")!;
    const agentArgv = log.argv.slice(0, -2); // without the --profile pair the core appends
    expect(cliArgv({ ...preset, profile: "demo-readonly" }, agentArgv)).toEqual(log.argv);
  });

  it("root-cause chain still has the same 5 steps; demo has evidence from all four read-only sources", () => {
    expect(f.root_cause_chain).toHaveLength(5);
    expect(f.evidenceIds).not.toContain(slsItem().evidence_ids[0]);
    const src = (re: RegExp) => w.evidence.some((e: { source?: string }) => re.test(e.source ?? ""));
    const mcp = (c: string) => w.evidence.some((e: { mcpCall?: { connector: string } }) => e.mcpCall?.connector === c);
    expect({ mongodb: mcp("mongodb"), langfuse: mcp("langfuse"), rocketmq: src(/^run_cli:mqadmin /), cloudlogs: src(/^run_cli:aliyun sls GetLogsV2 /) })
      .toEqual({ mongodb: true, langfuse: true, rocketmq: true, cloudlogs: true });
  });
});

describe("mock aliyun CLI (sls GetLogs JSON shape)", () => {
  const bin = writeMockAliyun(mkdtempSync(join(tmpdir(), "wt-aly-")));
  const run = (...a: string[]) => spawnSync(bin, a, { encoding: "utf8" });
  it("returns an array of string-valued logs with __time__/__source__/__topic__, filtered by query and [from, to)", () => {
    const all = JSON.parse(run("sls", "GetLogs", "--project", "p", "--logstore", "l", "--from", "100", "--to", "200").stdout);
    expect(all.length).toBeGreaterThan(0);
    for (const l of all) { expect(Object.values(l).every((v) => typeof v === "string")).toBe(true); expect(l).toHaveProperty("__time__"); expect(l).toHaveProperty("__source__"); expect(l).toHaveProperty("__topic__"); }
    expect(JSON.parse(run("sls", "GetLogs", "--project", "p", "--logstore", "l", "--from", "100", "--to", "200", "--query", "layer: app and level: ERROR").stdout)).toHaveLength(1);
    expect(run("sls", "GetLogs", "--project", "p", "--logstore", "l", "--from", "100", "--to", "200", "--query", "layer: infra and level: ERROR").stdout.trim()).toBe("[]");
    expect(run("sls", "GetLogs", "--project", "p", "--logstore", "l", "--from", "200", "--to", "200").status).toBe(1);
    expect(run("--version").stdout.trim()).toBe("3.0.277-mock");
  });
});
