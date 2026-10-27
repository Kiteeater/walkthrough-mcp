import { spawn, type ChildProcess } from "node:child_process";
import { parseCommand, UnsafeCommandError } from "./argv.js";
import type { SandboxConfig } from "./types.js";

export interface ExecResult { exitCode: number; output: string }

export interface Sandbox {
  up(): Promise<ExecResult>;
  down(): Promise<ExecResult>;
  exec(command: string | string[]): Promise<ExecResult>;
  logs(service: string): Promise<string>;
}

/** Run one command line WITHOUT a shell: parsed to argv and spawned as spawn(file, args). Unsafe syntax exits 126. */
export function sh(command: string | string[], cwd: string, timeoutMs = 300_000, env: NodeJS.ProcessEnv = process.env): Promise<ExecResult> {
  let parsed;
  try { parsed = parseCommand(command, env); } catch (e) {
    if (e instanceof UnsafeCommandError) return Promise.resolve({ exitCode: 126, output: `rejected: ${e.message}` });
    throw e;
  }
  return run(parsed.file, parsed.args, { cwd, env: { ...env, ...parsed.env }, timeoutMs });
}

/** spawn(file, args) with captured output and a hard timeout; shell is never enabled. */
export function run(file: string, args: string[], o: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs?: number; maxBytes?: number }): Promise<ExecResult> {
  return new Promise((resolve) => {
    // Put commands in their own process group where the platform supports it. A timeout
    // must not leave grandchildren (for example a compose wrapper) running behind.
    const grouped = process.platform !== "win32";
    const child = spawn(file, args, { cwd: o.cwd, env: o.env, shell: false, detached: grouped, stdio: ["ignore", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    const cap = o.maxBytes ?? 5_000_000;
    let outputBytes = 0;
    const add = (d: Buffer) => {
      if (outputBytes >= cap) return;
      const chunk = d.subarray(0, Math.max(0, cap - outputBytes));
      chunks.push(chunk);
      outputBytes += chunk.byteLength;
    };
    const fitBytes = (value: string) => {
      // A byte cut can split a UTF-8 sequence. Drop the incomplete trailing code point
      // until the returned string still re-encodes within the byte cap.
      let text = value;
      while (Buffer.byteLength(text) > cap) text = text.slice(0, -1);
      return text;
    };
    const output = () => fitBytes(Buffer.concat(chunks).toString("utf8"));
    const killTree = () => {
      try {
        if (grouped && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch { try { child.kill("SIGKILL"); } catch { /* already exited */ } }
    };
    const timer = setTimeout(killTree, o.timeoutMs ?? 300_000);
    child.stdout.on("data", add);
    child.stderr.on("data", add);
    child.on("close", (code) => { clearTimeout(timer); resolve({ exitCode: code ?? 1, output: output() }); });
    child.on("error", (err) => { clearTimeout(timer); resolve({ exitCode: 127, output: fitBytes(`${output()}${String(err)}`) }); });
  });
}

/** Docker Compose sandbox; up/down/logs commands come from config. */
export class ComposeSandbox implements Sandbox {
  constructor(private readonly cfg: SandboxConfig) {}
  up() { return sh(this.cfg.up, this.cfg.cwd); }
  down() { return sh(this.cfg.down, this.cfg.cwd); }
  exec(command: string | string[]) { return sh(command, this.cfg.cwd); }
  async logs(service: string) {
    if (!/^[\w.-]+$/.test(service)) throw new Error(`invalid service name: ${service}`);
    const tpl = parseCommand(this.cfg.logs ?? "docker compose logs --no-color {service}");
    return (await sh([tpl.file, ...tpl.args].map((a) => a.replaceAll("{service}", service)), this.cfg.cwd)).output;
  }
}

/**
 * Local backend: runs the service as a child process on the host. NOT isolated.
 * Logs are the captured stdout/stderr of the `up` process.
 */
export const DEFAULT_LOCAL_ENV = ["PATH", "HOME", "LANG", "TMPDIR", "TERM"];

/** Build the child env from an allowlist: defaults plus explicitly listed names. Nothing else from the host passes through. */
export function allowlistEnv(passEnv: string[] = [], host: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of [...DEFAULT_LOCAL_ENV, ...passEnv]) if (host[name] !== undefined) env[name] = host[name];
  return env;
}

export class LocalSandbox implements Sandbox {
  private child?: ChildProcess;
  private buffer = "";
  constructor(private readonly cfg: SandboxConfig) {}
  private get upCmd() { return this.cfg.local?.up ?? this.cfg.up; }
  private get env() { return allowlistEnv(this.cfg.local?.passEnv); }
  async up(): Promise<ExecResult> {
    if (this.child && this.child.exitCode === null) return { exitCode: 0, output: "already running" };
    this.buffer = "";
    let cmd;
    try { cmd = parseCommand(this.upCmd, this.env); } catch (e) {
      if (e instanceof UnsafeCommandError) return { exitCode: 126, output: `rejected: ${e.message}` };
      throw e;
    }
    const child = spawn(cmd.file, cmd.args, { cwd: this.cfg.cwd, env: { ...this.env, ...cmd.env }, detached: true, shell: false });
    child.on("error", (err) => (this.buffer += String(err)));
    this.child = child;
    child.stdout?.on("data", (d) => (this.buffer += d));
    child.stderr?.on("data", (d) => (this.buffer += d));
    await new Promise((r) => setTimeout(r, 300));
    if (child.exitCode !== null || child.pid === undefined) return { exitCode: child.exitCode || 127, output: this.buffer };
    return { exitCode: 0, output: `started pid ${child.pid}` };
  }
  async down(): Promise<ExecResult> {
    const child = this.child;
    let forced = false;
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      const pid = child.pid;
      const closed = new Promise<void>((r) => child.once("close", () => r()));
      const signal = (sig: NodeJS.Signals) => { try { process.kill(-pid, sig); } catch { /* already gone */ } };
      signal("SIGTERM");
      const grace = this.cfg.local?.killTimeoutMs ?? 5000;
      const timedOut = await Promise.race([closed.then(() => false), new Promise<boolean>((r) => setTimeout(() => r(true), grace))]);
      if (timedOut) { forced = true; signal("SIGKILL"); await closed; }
    }
    this.child = undefined;
    const extra = this.cfg.local?.down ? await sh(this.cfg.local.down, this.cfg.cwd, 300_000, this.env) : { exitCode: 0, output: "" };
    return { exitCode: extra.exitCode, output: `stopped local process${forced ? " (SIGKILL after timeout)" : ""}\n${extra.output}` };
  }
  exec(command: string | string[]) { return sh(command, this.cfg.cwd, 300_000, this.env); }
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
