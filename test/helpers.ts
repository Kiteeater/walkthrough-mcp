import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Redactor, WalkthroughCore, type Capturer, type ConnectorConfig, type ReplayConfig, type Sandbox } from "../src/core/index.js";

export function mockCore(opts: { secrets?: string[]; redactor?: Redactor; logs?: string; output?: string; connectors?: ConnectorConfig[]; replay?: ReplayConfig } = {}) {
  const root = mkdtempSync(join(tmpdir(), "wt-"));
  const sandbox: Sandbox = {
    up: async () => ({ exitCode: 0, output: opts.output ?? "up ok" }),
    down: async () => ({ exitCode: 0, output: "down ok" }),
    exec: async (c) => ({ exitCode: 0, output: `${c}: ${opts.output ?? "ok"}` }),
    logs: async () => opts.logs ?? "web | listening on 3000",
  };
  const capturer = fakePageCapturer("fake-png");
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer, redactor: opts.redactor ?? new Redactor(opts.secrets ?? []), connectors: opts.connectors, ...(opts.replay ? { replay: opts.replay } : {}),
  });
  return { core, root };
}

export const SB = { cwd: ".", up: "docker compose up -d", down: "docker compose down" };

/** Fake browser: core still runs its guard (pinned resolve + checkHop) before calling page(); nothing is fetched. */
export function fakePageCapturer(png = "png"): Capturer {
  return { page: async (url) => ({ screenshot: Buffer.from(png), har: JSON.stringify({ log: { entries: [] } }), text: "", navigations: [{ url, status: 200, ip: "127.0.0.1" }], subresources: [], blocked: [] }) };
}

/** replay config for direct captureEvidence screenshot calls in unit tests (local demo host only). */
export const LOCAL_REPLAY: ReplayConfig = { allowHosts: ["localhost:3000"], allowCidrs: ["127.0.0.1/32", "::1/128"] };
