// PR-D config rule: every host a flow contacts (waitFor.url, screenshot captures) must also be in replay.allowHosts.
// No network: the sandbox is a stub, waits are skipped, and the rule is checked before anything starts.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runFlow, type FlowConfig } from "../src/core/index.js";
import { expandEnv } from "../src/core/flow.js";
import { mockCore, SB } from "./helpers.js";

const startedWalkthroughs = (root: string) => (existsSync(join(root, ".walkthrough")) ? readdirSync(join(root, ".walkthrough")) : []);
const flow = (url: string): FlowConfig => ({ title: "f", sandbox: SB, waitFor: { url }, captures: [{ as: "logs", type: "logs", service: "web" }], claims: [] });

describe("flow hosts must be listed in replay.allowHosts", () => {
  it("positive: waitFor host listed → the flow runs", async () => {
    const { core } = mockCore({ replay: { allowHosts: ["127.0.0.1:4100"] } });
    const r = await runFlow(core, flow("http://127.0.0.1:4100/health"), { skipWait: true });
    expect(core.load(r.id).evidence).toHaveLength(1);
  });
  it("negative: a screenshot host missing from replay.allowHosts is a config error, raised before any walkthrough starts", async () => {
    const { core, root } = mockCore({ replay: { allowHosts: ["127.0.0.1:4100"] } });
    const cfg: FlowConfig = { ...flow("http://127.0.0.1:4100/health"), captures: [{ as: "s", type: "screenshot", url: "http://other.local:4100/" }] };
    await expect(runFlow(core, cfg, { skipWait: true })).rejects.toThrow("flow config: captures[s].url host other.local:4100 is not in replay.allowHosts");
    expect(startedWalkthroughs(root)).toEqual([]);
  });
  it("negative: no replay.allowHosts at all is a config error too", async () => {
    const { core, root } = mockCore();
    await expect(runFlow(core, flow("http://127.0.0.1:4100/health"), { skipWait: true })).rejects.toThrow("flow config: waitFor.url contacts 127.0.0.1:4100, but replay.allowHosts is not configured");
    expect(startedWalkthroughs(root)).toEqual([]);
  });
});

describe("examples follow the rule", () => {
  // The demo runners (src/demo-agent/run.ts, trace-run.ts) allowlist exactly the agent.baseUrl host.
  it.each(["examples/walkthrough.config.json", "examples/walkthrough.local.json", "examples/trace-demo/walkthrough.trace.json"])("%s: every flow host is the agent.baseUrl host", (f) => {
    const raw = readFileSync(f, "utf8").replaceAll("${SERVICE_URL}", "http://127.0.0.1:4200").replaceAll("${HEALTH_TOKEN}", "t");
    const cfg = expandEnv(JSON.parse(raw), f, { PORT: "4200", DEMO_HEALTH_TOKEN: "t" }) as FlowConfig & { agent: { baseUrl: string } };
    const hosts = [cfg.waitFor?.url, ...cfg.captures.map((c) => (c.type === "screenshot" ? c.url : undefined))].filter((u): u is string => !!u).map((u) => new URL(u).host);
    expect(hosts.length).toBeGreaterThan(0);
    for (const h of hosts) expect(h).toBe(new URL(cfg.agent.baseUrl).host);
  });
});
