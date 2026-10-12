// CI test-count gate: runs vitest with the JSON reporter and fails if any test is skipped/todo/pending
// or if fewer tests executed than test/EXPECTED_TEST_COUNT. New tests must bump that file.
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";

const expected = Number(readFileSync(new URL("../test/EXPECTED_TEST_COUNT", import.meta.url), "utf8").trim());
const out = "vitest-report.json";
rmSync(out, { force: true });
const r = spawnSync("npx", ["vitest", "run", "--reporter=default", "--reporter=json", `--outputFile.json=${out}`], { stdio: "inherit" });
let j;
try { j = JSON.parse(readFileSync(out, "utf8")); } catch { console.error("test-gate: no vitest JSON report"); process.exit(1); }
const files = j.testResults.map((f) => f.name.replace(/.*\/test\//, "test/")).sort();
const executed = j.numPassedTests + j.numFailedTests;
const skipped = j.numPendingTests + j.numTodoTests;
console.log(`test-gate: files ${files.length}: ${files.join(" ")}`);
console.log(`test-gate: executed ${executed} / expected ${expected}, skipped ${skipped}, failed ${j.numFailedTests}`);
const errs = [];
if (r.status !== 0 || j.numFailedTests > 0 || !j.success) errs.push(`vitest failed (exit ${r.status}, ${j.numFailedTests} failed)`);
if (skipped > 0) errs.push(`${skipped} test(s) skipped/todo/pending — every test must run in CI`);
if (executed < expected) errs.push(`executed ${executed} < expected ${expected} (a test file is missing or not matched)`);
if (executed > expected) console.log(`test-gate: note — executed more than expected; bump test/EXPECTED_TEST_COUNT to ${executed}`);
if (errs.length) { for (const e of errs) console.error(`test-gate: FAIL ${e}`); process.exit(1); }
console.log("test-gate: OK");
