import { spawn, type ChildProcess } from "node:child_process";
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

/**
 * Local backend: runs the service as a child process on the host. NOT isolated.
 * Logs are the captured stdout/stderr of the `up` process.
 */
export class LocalSandbox implements Sandbox {
  private child?: ChildProcess;
  private buffer = "";
  constructor(private readonly cfg: SandboxConfig) {}
  private get upCmd() { return this.cfg.local?.up ?? this.cfg.up; }
  async up(): Promise<ExecResult> {
    if (this.child && this.child.exitCode === null) return { exitCode: 0, output: "already running" };
    this.buffer = "";
    const child = spawn("bash", ["-c", this.upCmd], { cwd: this.cfg.cwd, env: process.env, detached: true });
    this.child = child;
    child.stdout?.on("data", (d) => (this.buffer += d));
    child.stderr?.on("data", (d) => (this.buffer += d));
    await new Promise((r) => setTimeout(r, 300));
    if (child.exitCode !== null) return { exitCode: child.exitCode || 1, output: this.buffer };
    return { exitCode: 0, output: `started pid ${child.pid}` };
  }
  async down(): Promise<ExecResult> {
    const child = this.child;
    if (child?.pid && child.exitCode === null) {
      try { process.kill(-child.pid, "SIGTERM"); } catch { /* already gone */ }
      await new Promise((r) => child.once("close", r));
    }
    this.child = undefined;
    const extra = this.cfg.local?.down ? await sh(this.cfg.local.down, this.cfg.cwd) : { exitCode: 0, output: "" };
    return { exitCode: extra.exitCode, output: `stopped local process\n${extra.output}` };
  }
  exec(command: string) { return sh(command, this.cfg.cwd); }
  async logs(): Promise<string> { return this.buffer; }
}

/** Pick the backend. Local sandboxes are cached per walkthrough so the process survives across tool calls. */
export function createSandboxFactory(): (cfg: SandboxConfig, key?: string) => Sandbox {
  const local = new Map<string, LocalSandbox>();
  return (cfg, key = cfg.cwd) => {
    if (cfg.backend !== "local") return new ComposeSandbox(cfg);
    let sb = local.get(key);
    if (!sb) local.set(key, (sb = new LocalSandbox(cfg)));
    return sb;
  };
}
