// Regenerates the committed sample run in examples/output-trace/ through the normal demo path (in-process Mongo).
// Host-specific absolute paths are replaced so the sample reads the same on every machine.
// usage: npm run build && node examples/regen-output-trace.mjs
import { spawnSync } from "node:child_process";
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const r = spawnSync(process.execPath, ["examples/trace-demo/run.mjs", "."], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
if (r.status !== 0) { console.error(r.stdout); process.exit(r.status ?? 1); }
const { html } = JSON.parse(r.stdout.trim().split("\n").at(-1));
const src = dirname(resolve(html)), out = resolve("examples/output-trace");
rmSync(out, { recursive: true, force: true });
cpSync(src, out, { recursive: true });
const root = resolve(".");
for (const f of ["walkthrough.json", "index.html"]) {
  const p = resolve(out, f);
  writeFileSync(p, readFileSync(p, "utf8").split(root + "/").join("").split(root).join("."));
}
const shot = spawnSync(process.execPath, ["examples/screenshot.mjs", resolve(out, "index.html"), resolve(out, "walkthrough-html.png")], { stdio: "inherit" });
if (shot.status !== 0) process.exit(shot.status ?? 1);
console.log(`examples/output-trace regenerated from ${src.slice(root.length + 1)}`);
