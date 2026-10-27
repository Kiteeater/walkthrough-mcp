import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CliRejectedError, PRESET_CONNECTORS, renderWalkthrough } from "../src/core/index.js";
import { cliArgv } from "../src/core/runcli.js";
import { judgeSlsEmpty } from "../src/core/sls.js";
import { checkSlsInfra } from "../src/demo-agent/trace.js";
import { mockCore } from "./helpers.js";
// @ts-expect-error plain ESM helper without types
import { writeMockAliyun } from "../examples/trace-demo/mock-aliyun.mjs";

const aliyun = PRESET_CONNECTORS.find((c) => c.name === "aliyun")!;
const base = (sub: string) => ["sls", sub, "--project", "p", "--logstore", "infra", "--from", "100", "--to", "200"];

describe("get-logs-v2 argument allowlist (#31)", () => {
  it("is on the aliyun preset and no wider than get-logs", () => {
    expect(aliyun.allow).toContainEqual(["sls", "get-logs-v2"]);
    const v1 = aliyun.args!["sls get-logs"], v2 = aliyun.args!["sls get-logs-v2"];
    expect(v2.every((a) => v1.includes(a))).toBe(true);
    expect(v2).toEqual(["--project", "--logstore", "--from", "--to", "--query", "--topic", "--line", "--offset", "--reverse"]);
  });
  it("accepts the read-only args (split and = forms)", () => {
    const argv = [...base("get-logs-v2"), "--query", "layer: infra and level: ERROR", "--topic", "t", "--line", "100", "--offset", "0", "--reverse", "true"];
    expect(cliArgv(aliyun, argv)).toEqual(argv);
    expect(cliArgv(aliyun, ["sls", "get-logs-v2", "--project=p", "--logstore=infra", "--from=100", "--to=200"])).toBeTruthy();
  });
  it.each([["--powerSql", "true"], ["--session", "s"], ["--forward", "true"], ["--highlight", "true"], ["--isAccurate", "true"], ["--endpoint", "http://evil"], ["--region", "cn-x"], ["--body", "{}"]])(
    "rejects non-allowlisted arg %s", (flag, value) => {
      expect(() => cliArgv(aliyun, [...base("get-logs-v2"), flag, value])).toThrow(CliRejectedError);
      expect(() => cliArgv(aliyun, [...base("get-logs-v2"), `${flag}=${value}`])).toThrow(CliRejectedError);
    });
  it.each([["--access-key-id"], ["--access-key-secret"], ["--sts-token"], ["--ram-role-arn"], ["--profile"], ["--config"], ["--secret"]])(
    "rejects credential/global flag %s via CRED_FLAGS", (flag) => {
      expect(() => cliArgv(aliyun, [...base("get-logs-v2"), flag, "x"])).toThrow(/flag not allowed/);
      expect(() => cliArgv(aliyun, [...base("get-logs-v2"), `${flag}=x`])).toThrow(/flag not allowed/);
    });
});

describe("SLS SQL analysis (`|`) is rejected", () => {
  const q = "layer: infra | SELECT count(*) as c";
  it("get-logs --query with | is rejected", () => {
    expect(() => cliArgv(aliyun, [...base("get-logs"), "--query", q])).toThrow(/shell syntax/);
    expect(() => cliArgv(aliyun, [...base("get-logs"), `--query=${q}`])).toThrow(/shell syntax/);
  });
  it("get-logs-v2 --query with | is rejected", () => {
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), "--query", q])).toThrow(/shell syntax/);
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), `--query=${q}`])).toThrow(/shell syntax/);
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), "--query", "*|select 1"])).toThrow(/shell syntax/);
  });
});

describe("judgeSlsEmpty", () => {
  const ev = (body: unknown, exit = 0) => `$ aliyun ["sls","get-logs-v2"]\nexit ${exit}\n\n${typeof body === "string" ? body : JSON.stringify(body, null, "\t")}\n`;
  it("Complete + [] → pass; Complete + rows → fail", () => {
    expect(judgeSlsEmpty([ev({ meta: { progress: "Complete" }, data: [] })])).toEqual({ status: "pass", reasons: [] });
    expect(judgeSlsEmpty([ev({ meta: { progress: "Complete" }, data: [{ a: "1" }] })]).status).toBe("fail");
  });
  it("anything that cannot prove completeness → inconclusive", () => {
    expect(judgeSlsEmpty([ev([])])).toMatchObject({ status: "inconclusive" }); // get-logs v1 array: no progress
    expect(judgeSlsEmpty([ev({ meta: { progress: "Complete" }, data: [] }, 1)])).toMatchObject({ status: "inconclusive" });
    expect(judgeSlsEmpty([ev("not json")])).toMatchObject({ status: "inconclusive" });
    expect(judgeSlsEmpty([ev({ meta: { progress: "Complete" } })])).toMatchObject({ status: "inconclusive" });
    expect(judgeSlsEmpty([ev({ meta: { progress: 1 }, data: [] })]).reasons[0]).toMatch(/无法识别的 progress=1/);
  });
});

/** Runs the demo agent's SLS step against a mock aliyun returning `progress`, records the finding, renders the page. */
async function scenario(progress: string | null | undefined) {
  const bin = writeMockAliyun(mkdtempSync(join(tmpdir(), "wt-sls-")), progress === undefined ? {} : { progress });
  const { core, root } = mockCore({ connectors: [{ ...aliyun, binary: bin, profile: "demo-readonly" }] });
  const id = (await core.startWalkthrough({ title: "sls", sandbox: { cwd: root, up: "true", down: "true" } })).id;
  await core.planChecks(id, { goal: "g", checks: [{ id: "c1", intent: "GET 2xx", method: "http", target: "GET http://svc/api", expect: { type: "status", value: 200 }, severity_if_fail: "high" }] });
  const http = await core.captureEvidence(id, { type: "submit", checkId: "c1", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
  await core.evaluateCheck(id, { checkId: "c1", evidenceIds: [http.id] });
  const r = await checkSlsInfra(core, id, { goal: "g", checkId: "c1-sls", triggeringEvidenceId: http.id, actedAt: new Date().toISOString(), project: "demo-prod-logs", logstore: "infra" });
  await core.recordFinding(id, { title: "GET /api 返回 500", severity: "high", symptom: "500", check_id: "c1", root_cause_chain: [{ claim: "500", kind: "observed", evidence_ids: [http.id] }],
    ...(r.ruledOut ? { ruled_out: [r.ruledOut] } : {}), ...(r.inconclusive ? { inconclusive: [r.inconclusive] } : {}) });
  const w = core.load(id);
  const html = readFileSync(renderWalkthrough(core, id), "utf8");
  const audit = html.slice(html.indexOf('id="verdict"'), html.indexOf("</section>", html.indexOf('id="verdict"')));
  const report = html.slice(html.indexOf('<details class="finding" id="finding-1">'));
  return { r, w, html, audit, report, status: w.checkResults!.find((x) => x.checkId === "c1-sls")!.status };
}

function expectInconclusive(s: Awaited<ReturnType<typeof scenario>>, reason: string) {
  expect(s.status).toBe("inconclusive");
  expect(s.r.ruledOut).toBeUndefined();
  expect(s.w.findings![0].ruled_out).toBeUndefined();
  expect(s.html).not.toContain('class="ruled-out"');
  expect(s.html).not.toContain("排除基础设施问题");
  expect(s.w.findings![0].inconclusive![0].reason).toBe(reason);
  for (const [part, where] of [[s.audit, "audit"], [s.report, "report"]] as const) {
    expect(part).toContain(`<div class="inconclusive-block" data-where="${where}" data-inconclusive="1"><b>未下结论</b>`);
    expect(part).toContain(`<div class="inconclusive-reason">原因：${reason}</div>`);
  }
}

describe("#31: an SLS result that is not provably complete is inconclusive, never 已排除", () => {
  it("progress=Incomplete (with data: []) → inconclusive, in 未下结论 on the audit page and in the report", async () => {
    expectInconclusive(await scenario("Incomplete"), "SLS 查询未完成，progress=Incomplete");
  });
  it("meta.progress missing → inconclusive, in 未下结论 on the audit page and in the report", async () => {
    expectInconclusive(await scenario(null), "SLS 响应缺少 meta.progress，无法确认查询已完成");
  });
  it("unrecognised progress value → inconclusive, in 未下结论 on the audit page and in the report", async () => {
    expectInconclusive(await scenario("Partial"), "SLS 返回无法识别的 progress=Partial，无法确认查询已完成");
  });
  it("progress=Complete with data: [] still rules infrastructure out (已排除), no 未下结论 block", async () => {
    const s = await scenario(undefined);
    expect(s.status).toBe("pass");
    expect(s.r.ruledOut?.claim).toMatch(/^查过 SLS 日志，这段时间没有基础设施层报错，排除基础设施问题/);
    expect(s.audit).toContain('<div class="ruled-out" data-ruled-out="1"><b>已排除</b>');
    expect(s.html).not.toContain('class="inconclusive-block"');
  });
});

describe("#31 B1: core recordFinding only accepts ruled_out backed by a passing check", () => {
  async function setup(progress: string | null | undefined) {
    const bin = writeMockAliyun(mkdtempSync(join(tmpdir(), "wt-sls-")), progress === undefined ? {} : { progress });
    const { core, root } = mockCore({ connectors: [{ ...aliyun, binary: bin, profile: "demo-readonly" }] });
    const id = (await core.startWalkthrough({ title: "b1", sandbox: { cwd: root, up: "true", down: "true" } })).id;
    await core.planChecks(id, { goal: "g", checks: [
      { id: "c1", intent: "GET 2xx", method: "http", target: "GET http://svc/api", expect: { type: "status", value: 200 }, severity_if_fail: "high" },
      { id: "sls", intent: "no infra errors", method: "cli", target: "aliyun sls get-logs-v2", expect: { type: "sls_empty", value: {} }, severity_if_fail: "medium" }] });
    const http = await core.captureEvidence(id, { type: "submit", checkId: "c1", kind: "http", source: { tool: "t" }, content: "HTTP/1.1 500" });
    await core.evaluateCheck(id, { checkId: "c1", evidenceIds: [http.id] });
    const run = () => core.runCli(id, { connector: "aliyun", checkId: "sls", argv: [...base("get-logs-v2"), "--query", "layer: infra and level: ERROR"] });
    const chain = [{ claim: "500", kind: "observed" as const, evidence_ids: [http.id] }];
    const finding = (ruled_out: { claim: string; check_id?: string; evidence_ids: string[] }[]) =>
      core.recordFinding(id, { title: "t", severity: "high", symptom: "s", check_id: "c1", root_cause_chain: chain, ruled_out });
    return { core, id, http, run, finding };
  }

  it("rejects ruled_out citing Incomplete-progress SLS evidence (check verdict inconclusive)", async () => {
    const s = await setup("Incomplete");
    const ev = (await s.run()).evidence.id;
    expect((await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [ev] })).status).toBe("inconclusive");
    await expect(s.finding([{ claim: "排除基础设施问题", check_id: "sls", evidence_ids: [ev] }])).rejects.toThrow(/latest verdict is inconclusive, not pass.*inconclusive \(未下结论\)/);
  });
  it("rejects ruled_out without check_id, even with Complete + [] evidence", async () => {
    const s = await setup(undefined);
    const ev = (await s.run()).evidence.id;
    await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [ev] });
    await expect(s.finding([{ claim: "排除基础设施问题", evidence_ids: [ev] }])).rejects.toThrow(/check_id is required.*未下结论/);
  });
  it("rejects ruled_out whose check was never evaluated", async () => {
    const s = await setup(undefined);
    const ev = (await s.run()).evidence.id;
    await expect(s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [ev] }])).rejects.toThrow(/has not been evaluated/);
  });
  it("uses the LATEST verdict: a pass later overturned to fail is rejected", async () => {
    const s = await setup(undefined);
    const ev = (await s.run()).evidence.id;
    expect((await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [ev] })).status).toBe("pass");
    const rows = await s.core.captureEvidence(s.id, { type: "submit", checkId: "sls", kind: "log", source: { tool: "t" },
      content: `$ aliyun\nexit 0\n\n${JSON.stringify({ meta: { progress: "Complete" }, data: [{ level: "ERROR" }] })}\n` });
    expect((await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [rows.id] })).status).toBe("fail");
    await expect(s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [ev] }])).rejects.toThrow(/latest verdict is fail/);
  });
  it("rejects evidence that the passing verdict did not use", async () => {
    const s = await setup(undefined);
    const ev = (await s.run()).evidence.id;
    await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [ev] });
    await expect(s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [s.http.id] }])).rejects.toThrow(/was not used by check sls/);
    await expect(s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [ev, s.http.id] }])).rejects.toThrow(/was not used/);
  });
  it("rejects pass_needs_review (agent-reported evidence only)", async () => {
    const s = await setup(undefined);
    const sub = await s.core.captureEvidence(s.id, { type: "submit", checkId: "sls", kind: "log", source: { tool: "t" },
      content: `$ aliyun\nexit 0\n\n${JSON.stringify({ meta: { progress: "Complete" }, data: [] })}\n` });
    expect((await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [sub.id] })).status).toBe("pass_needs_review");
    await expect(s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [sub.id] }])).rejects.toThrow(/latest verdict is pass_needs_review/);
  });
  it("accepts a passing check with its own evidence", async () => {
    const s = await setup(undefined);
    const ev = (await s.run()).evidence.id;
    await s.core.evaluateCheck(s.id, { checkId: "sls", evidenceIds: [ev] });
    expect((await s.finding([{ claim: "排除", check_id: "sls", evidence_ids: [ev] }])).ruled_out).toHaveLength(1);
  });
});

describe("#34: aliyun preset uses the real CLI's command names", () => {
  it.each([["GetLogs"], ["GetLogsV2"], ["GetHistograms"], ["ListLogStores"], ["ListProject"]])(
    "built-in PascalCase sls %s (raw JSON --body form) is not allowed", (sub) => {
      expect(() => cliArgv(aliyun, ["sls", sub, "--project", "p"])).toThrow(/not in whitelist/);
    });
  it("SLS flags use the plugin's kebab-case spelling", () => {
    expect(cliArgv(aliyun, ["sls", "list-log-stores", "--project", "p", "--logstore-name", "x"])).toBeTruthy();
    expect(cliArgv(aliyun, ["sls", "list-project", "--project-name", "x"])).toBeTruthy();
    expect(() => cliArgv(aliyun, ["sls", "list-log-stores", "--project", "p", "--logstoreName", "x"])).toThrow(/not in allowlist/);
    expect(() => cliArgv(aliyun, ["sls", "list-project", "--projectName", "x"])).toThrow(/not in allowlist/);
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), "--power-sql", "true"])).toThrow(/not in allowlist/);
  });
});

describe("#35: --body (raw JSON request body) is never allowed on any aliyun command", () => {
  it.each([["GetLogs"], ["GetLogsV2"]])("old built-in sls %s is rejected, with or without --body", (sub) => {
    expect(() => cliArgv(aliyun, ["sls", sub, "--project", "p", "--logstore", "l"])).toThrow(CliRejectedError);
    expect(() => cliArgv(aliyun, ["sls", sub, "--project", "p", "--logstore", "l", "--body", '{"from":1,"to":2}'])).toThrow(CliRejectedError);
    expect(() => cliArgv(aliyun, ["sls", sub, "--project", "p", "--logstore", "l", '--body={"from":1,"to":2}'])).toThrow(CliRejectedError);
  });
  it.each(aliyun.allow!.map((p) => [p.join(" ")]))("aliyun %s rejects --body x and --body=x", (key) => {
    const prefix = key.split(" ");
    expect(() => cliArgv(aliyun, [...prefix, "--body", "x"])).toThrow(/flag not allowed: --body/);
    expect(() => cliArgv(aliyun, [...prefix, "--body=x"])).toThrow(/flag not allowed: --body/);
  });
  it("get-logs-v2 with otherwise valid args plus --body is rejected (both forms)", () => {
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), "--body", '{"query":"*|select 1"}'])).toThrow(/flag not allowed: --body|shell syntax/);
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), "--body", '{"line":1}'])).toThrow(/flag not allowed: --body/);
    expect(() => cliArgv(aliyun, [...base("get-logs-v2"), '--body={"line":1}'])).toThrow(/flag not allowed: --body/);
  });
  it("--body is denied even if a config adds it to an allowlist, and no preset allowlist contains it", () => {
    expect(aliyun.denyArgs).toContain("--body");
    expect(Object.values(aliyun.args!).flat()).not.toContain("--body");
    const widened = { ...aliyun, args: { ...aliyun.args, "sls get-logs-v2": [...aliyun.args!["sls get-logs-v2"], "--body"] } };
    expect(() => cliArgv(widened, [...base("get-logs-v2"), "--body", "x"])).toThrow(/flag not allowed: --body/);
  });
});
