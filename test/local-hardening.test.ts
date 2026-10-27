import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LocalSandbox, type SandboxConfig } from "../src/core/index.js";
import { allowlistEnv } from "../src/core/sandbox.js";

const cwd = () => mkdtempSync(join(tmpdir(), "wt-lh-"));
const cfg = (local: SandboxConfig["local"]): SandboxConfig => ({ backend: "local", cwd: cwd(), up: "unused", down: "unused", local });
const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const pidOf = (out: string) => Number(/pid (\d+)/.exec(out)![1]);

describe("local env allowlist", () => {
  const SECRET = "host-only-secret-77aa";
  afterEach(() => { delete process.env.WT_HOST_SECRET_TOKEN; delete process.env.WT_PASSED_VAR; });

  it("child cannot read host secrets unless explicitly passed", async () => {
    process.env.WT_HOST_SECRET_TOKEN = SECRET;
    process.env.WT_PASSED_VAR = "visible-value";
    const sb = new LocalSandbox(cfg({
      up: `exec node -e 'console.log(JSON.stringify(process.env)); setInterval(()=>{},1000)'`, passEnv: ["WT_PASSED_VAR"], killTimeoutMs: 1000,
    }));
    await sb.up();
    await new Promise((r) => setTimeout(r, 300));
    const logs = await sb.logs();
    await sb.down();
    expect(logs).toContain("visible-value");
    expect(logs).toContain('"PATH"');
    expect(logs).not.toContain(SECRET);
    expect(logs).not.toContain("WT_HOST_SECRET_TOKEN");
    const execOut = await new LocalSandbox(cfg({ up: "true" })).exec("env");
    expect(execOut.output).not.toContain(SECRET);
  });

  it("allowlistEnv keeps only defaults plus listed names", () => {
    expect(allowlistEnv(["EXTRA"], { PATH: "/bin", HOME: "/h", EXTRA: "1", API_KEY: "x" })).toEqual({ PATH: "/bin", HOME: "/h", EXTRA: "1" });
  });
});

describe("local down()", () => {
  it("SIGKILLs a child that ignores SIGTERM after the timeout", async () => {
    const sb = new LocalSandbox(cfg({
      up: `exec node -e 'process.on("SIGTERM",()=>console.log("ignored")); setInterval(()=>{},1000)'`, killTimeoutMs: 400,
    }));
    const pid = pidOf((await sb.up()).output);
    await new Promise((r) => setTimeout(r, 300));
    expect(alive(pid)).toBe(true);
    const t0 = Date.now();
    const res = await sb.down();
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeGreaterThanOrEqual(380);
    expect(elapsed).toBeLessThan(4000);
    expect(res.output).toContain("SIGKILL after timeout");
    expect(alive(pid)).toBe(false);
  });

  it("stops a well-behaved child without waiting for the timeout", async () => {
    const sb = new LocalSandbox(cfg({ up: `exec node -e 'setInterval(()=>{},1000)'`, killTimeoutMs: 5000 }));
    const pid = pidOf((await sb.up()).output);
    const t0 = Date.now();
    const res = await sb.down();
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(res.output).not.toContain("SIGKILL");
    expect(alive(pid)).toBe(false);
  });
});
