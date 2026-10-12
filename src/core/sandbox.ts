import { spawn } from "node:child_process";
import type { SandboxConfig } from "./types.js";

export interface ExecResult { exitCode: number; output: string }

export interface Sandbox {
  up(): Promise<ExecResult>;
  down(): Promise<ExecResult>;
  exec(command: string): Promise<ExecResult>;
  logs(service: string): Promise<string>;
}

export function sh(command: string, cwd: string, timeoutMs = 300_000): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = spawn("bash", ["-lc", command], { cwd, env: process.env });
    let output = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.on("data", (d) => (output += d));
    child.stderr.on("data", (d) => (output += d));
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code ?? 1, output });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ exitCode: 127, output: String(err) });
    });
  });
}

/** Docker Compose sandbox; up/down/logs commands come from config. */
export class ComposeSandbox implements Sandbox {
  constructor(private readonly cfg: SandboxConfig) {}
  up() { return sh(this.cfg.up, this.cfg.cwd); }
  down() { return sh(this.cfg.down, this.cfg.cwd); }
  exec(command: string) { return sh(command, this.cfg.cwd); }
  async logs(service: string) {
    if (!/^[\w.-]+$/.test(service)) throw new Error(`invalid service name: ${service}`);
    const tpl = this.cfg.logs ?? "docker compose logs --no-color {service}";
    return (await sh(tpl.replaceAll("{service}", service), this.cfg.cwd)).output;
  }
}
