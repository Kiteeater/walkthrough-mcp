import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Redactor, WalkthroughCore, type Capturer, type ConnectorConfig, type Sandbox } from "../src/core/index.js";

export function mockCore(opts: { secrets?: string[]; redactor?: Redactor; logs?: string; output?: string; connectors?: ConnectorConfig[] } = {}) {
  const root = mkdtempSync(join(tmpdir(), "wt-"));
  const sandbox: Sandbox = {
    up: async () => ({ exitCode: 0, output: opts.output ?? "up ok" }),
    down: async () => ({ exitCode: 0, output: "down ok" }),
    exec: async (c) => ({ exitCode: 0, output: `${c}: ${opts.output ?? "ok"}` }),
    logs: async () => opts.logs ?? "web | listening on 3000",
  };
  const capturer: Capturer = { screenshot: async (_u, out) => writeFileSync(out, Buffer.from("fake-png")) };
  const core = new WalkthroughCore({
    root, sandboxFactory: () => sandbox, capturer, redactor: opts.redactor ?? new Redactor(opts.secrets ?? []), connectors: opts.connectors,
  });
  return { core, root };
}

export const SB = { cwd: ".", up: "docker compose up -d", down: "docker compose down" };
