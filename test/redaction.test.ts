import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Redactor, runFlow, type FlowConfig } from "../src/core/index.js";
import { mockCore } from "./helpers.js";

const SECRET = "fake-secret-value-9f8e7d6c";
const walk = (d: string): string[] =>
  readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));

describe("redaction", () => {
  afterEach(() => { delete process.env.WALKTHROUGH_TEST_API_KEY; });

  it("never writes env secret values to the output dir or HTML", async () => {
    process.env.WALKTHROUGH_TEST_API_KEY = SECRET;
    const { core, root } = mockCore({ redactor: Redactor.fromEnv(), logs: `web | key=${SECRET}`, output: `booted with ${SECRET}` });
    const cfg: FlowConfig = {
      title: `Demo ${SECRET}`,
      sandbox: { cwd: ".", up: `env TOKEN=${SECRET} docker compose up -d`, down: "docker compose down" },
      exec: [`curl -H "Authorization: ${SECRET}" localhost`],
      captures: [
        { as: "home", type: "screenshot", url: `http://localhost:3000/?k=${SECRET}` },
        { as: "logs", type: "logs", service: "web" },
      ],
      claims: [
        { question: "Does it log the key?", conclusion: `It logged ${SECRET}`, kind: "observed", evidence: ["logs", "home"] },
        { question: "Why?", conclusion: "inferred", kind: "inferred" },
      ],
    };
    const { html } = await runFlow(core, cfg, { skipWait: true });
    const files = walk(join(root, ".walkthrough"));
    expect(files.length).toBeGreaterThan(3);
    for (const f of files) expect(readFileSync(f).includes(SECRET), f).toBe(false);
    const out = readFileSync(html, "utf8");
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain(SECRET);
  });
});
