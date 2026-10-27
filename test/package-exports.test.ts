// PR-D: the package has one entry ("." → dist/core/index.js). Deep imports are refused by Node, and guard internals
// are not part of the public index. Runs Node itself (package self-reference), so dist must be built (npm test does).
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";

const importIn = (spec: string) => spawnSync(process.execPath, ["--input-type=module", "-e",
  `const m = await import(${JSON.stringify(spec)}); console.log(JSON.stringify(Object.keys(m).sort()));`], { encoding: "utf8", cwd: process.cwd() });

describe("package exports", () => {
  it("the root entry loads and carries the public API only", () => {
    const r = importIn("walkthrough-mcp");
    expect(r.status, r.stderr).toBe(0);
    const keys: string[] = JSON.parse(r.stdout);
    expect(keys).toEqual(expect.arrayContaining(["createCore", "WalkthroughCore", "runFlow", "renderWalkthrough", "ReplayRejectedError"]));
    for (const internal of ["loginCookieHostnames", "loginOriginAllowed", "parseAllowHost", "hostAllowed", "authFor", "checkHop", "loadLoginState", "addTestCoreBlocked", "guardedGet", "signOffShape", "replayConfigFrom"])
      expect(keys, internal).not.toContain(internal);
  });
  it.each(["walkthrough-mcp/dist/core/egress/allowhosts.js", "walkthrough-mcp/dist/core/index.js", "walkthrough-mcp/dist/core/loginstate.js"])("deep import %s is refused", (spec) => {
    const r = importIn(spec);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("ERR_PACKAGE_PATH_NOT_EXPORTED");
  });
});
