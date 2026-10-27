import { mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createSandboxFactory, Redactor, renderWalkthrough, runFlow, WalkthroughCore, type Capturer, type FlowConfig,
} from "../src/core/index.js";
import { fakePageCapturer, LOCAL_REPLAY, mockCore, SB } from "./helpers.js";

const walk = (d: string): string[] =>
  readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
const assertAbsent = (dir: string, secret: string) => {
  const forms = [secret, JSON.stringify(secret).slice(1, -1)];
  for (const f of walk(dir)) {
    const body = readFileSync(f, "utf8");
    for (const form of forms) expect(body.includes(form), `${f} contains ${form}`).toBe(false);
  }
};
const fakeCapturer: Capturer = fakePageCapturer();

describe("redaction of JSON-special secrets", () => {
  const SECRET = 'q"uo\\te\\"d-secret';
  afterEach(() => { delete process.env.WT_QUOTED_TOKEN; });

  it("does not leak secrets with quotes/backslashes in raw or JSON-escaped form", async () => {
    process.env.WT_QUOTED_TOKEN = SECRET;
    const { core, root } = mockCore({ redactor: Redactor.fromEnv(), logs: `log ${SECRET}`, output: `out ${SECRET}` });
    const w = await core.startWalkthrough({ title: `t ${SECRET}`, sandbox: { ...SB, up: `run ${SECRET}` } });
    await core.runInSandbox(w.id, "up");
    const ev = await core.captureEvidence(w.id, { type: "logs", service: "web" });
    await core.linkSource(w.id, { file: `f${SECRET}.ts`, line: 1, note: SECRET });
    await core.recordClaim(w.id, { question: SECRET, conclusion: SECRET, kind: "observed", evidenceIds: [ev.id] });
    renderWalkthrough(core, w.id);
    assertAbsent(join(root, ".walkthrough"), SECRET);
    expect(new Redactor([SECRET]).value({ [SECRET]: [SECRET, 1] })).toEqual({ "[REDACTED]": ["[REDACTED]", 1] });
  });
});

describe("per-id lock", () => {
  it("loses no evidence or claims under concurrent calls", async () => {
    const { core } = mockCore({ replay: LOCAL_REPLAY });
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    const evs = await Promise.all(Array.from({ length: 10 }, (_, i) =>
      i % 2 ? core.captureEvidence(w.id, { type: "logs", service: "web" }) : core.captureEvidence(w.id, { type: "screenshot", url: "http://localhost:3000/" })));
    await Promise.all([
      ...evs.map((e) => core.recordClaim(w.id, { question: "q", conclusion: e.id, kind: "observed", evidenceIds: [e.id] })),
      ...evs.map(() => core.recordClaim(w.id, { question: "q", conclusion: "i", kind: "inferred" })),
      core.recordClaim(w.id, { question: "bad", conclusion: "x", kind: "observed" }).catch(() => "rejected"),
    ]);
    const saved = core.load(w.id);
    expect(new Set(saved.evidence.map((e) => e.id)).size).toBe(10);
    expect(saved.claims).toHaveLength(20);
    expect(new Set(saved.claims.map((c) => c.id)).size).toBe(20);
  });
});

describe("local backend", () => {
  const SECRET = "local-fake-secret-5a4b3c";
  afterEach(() => { delete process.env.WT_LOCAL_API_KEY; });

  it("captures child-process logs, shows the not-isolated badge, and leaks no secret", async () => {
    process.env.WT_LOCAL_API_KEY = SECRET;
    const root = mkdtempSync(join(tmpdir(), "wt-local-"));
    const core = new WalkthroughCore({ root, sandboxFactory: createSandboxFactory(), capturer: fakeCapturer, redactor: Redactor.fromEnv(), replay: { allowHosts: ["localhost"] } });
    const cfg: FlowConfig = {
      title: "local",
      sandbox: {
        backend: "local", cwd: root, up: "unused", down: "unused", allowExec: true,
        local: { up: `exec node -e 'console.log("key=" + process.env.WT_LOCAL_API_KEY); console.error("stderr line"); setInterval(()=>{},1000)'`, passEnv: ["WT_LOCAL_API_KEY"] },
      },
      exec: ["echo exec ok"], // $VAR arguments are rejected by the exec policy (no expansion)
      captures: [{ as: "shot", type: "screenshot", url: "http://localhost/" }, { as: "logs", type: "logs", service: "app" }],
      claims: [
        { question: "logs?", conclusion: "printed key", kind: "observed", evidence: ["logs", "shot"] },
        { question: "why?", conclusion: "guess", kind: "inferred" },
      ],
    };
    const { id, html } = await runFlow(core, cfg, { skipWait: true });
    const w = core.load(id);
    const logEv = w.evidence.find((e) => e.type === "logs")!;
    expect(logEv.source).toBe("local:app");
    const log = readFileSync(join(core.dir(id), logEv.path), "utf8");
    expect(log).toContain("key=[REDACTED]");
    expect(log).toContain("stderr line");
    expect(w.runs.at(-1)!.output).toContain("stopped local process");
    const page = readFileSync(html, "utf8");
    expect(page.match(/本地运行、未隔离/g)!.length).toBeGreaterThanOrEqual(3);
    assertAbsent(join(root, ".walkthrough"), SECRET);
  });

  it("compose walkthroughs have no local badge", async () => {
    const { core } = mockCore();
    const w = await core.startWalkthrough({ title: "t", sandbox: SB });
    await core.recordClaim(w.id, { question: "q", conclusion: "c", kind: "inferred" });
    expect(readFileSync(renderWalkthrough(core, w.id), "utf8")).not.toContain("本地运行、未隔离");
  });
});
