// The demo uses no fixed ports: with the old ports (3100 Langfuse, 3102 Prometheus, 3200 service) occupied it
// still runs end to end (mocks listen on 0, the service gets a free port passed through the generated config).
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const OLD = [3100, 3102, 3200];

describe("demo ports", () => {
  it("no fixed demo ports in the demo sources / flow config", () => {
    for (const f of ["examples/trace-demo/run.mjs", "examples/trace-demo/mock-prometheus.mjs", "examples/trace-demo/service/server.js", "examples/trace-demo/walkthrough.trace.json"]) {
      const s = readFileSync(f, "utf8");
      for (const p of OLD) expect(s, `${f} mentions ${p}`).not.toMatch(new RegExp(`\\b${p}\\b`));
    }
    expect(readFileSync("examples/trace-demo/walkthrough.trace.json", "utf8")).toContain("${SERVICE_URL}");
  });

  it("demo still works while 3100/3102/3200 are in use", async () => {
    const held: net.Server[] = [];
    for (const p of OLD) {
      const s = net.createServer();
      await new Promise<void>((r) => { s.once("error", () => r()); s.listen(p, () => { held.push(s); r(); }); }); // already busy is fine too
    }
    try {
      const root = mkdtempSync(join(tmpdir(), "wt-ports-"));
      const r = spawnSync(process.execPath, ["examples/trace-demo/run.mjs", root], { encoding: "utf8", timeout: 150_000, env: { ...process.env, DEMO_SERVICE_PORT: "" } });
      expect(r.status, r.stderr.slice(-2000)).toBe(0);
      const res = JSON.parse(r.stdout.trim().split("\n").at(-1)!);
      const w = JSON.parse(readFileSync(res.html.replace(/index\.html$/, "walkthrough.json"), "utf8"));
      expect(w.findings).toHaveLength(1);
      const target = w.checks.find((c: { id: string }) => c.id === w.findings[0].checkId).target as string;
      const port = Number(/127\.0\.0\.1:(\d+)/.exec(target)![1]);
      expect(OLD).not.toContain(port);
    } finally { for (const s of held) s.close(); }
  }, 180_000);
});
