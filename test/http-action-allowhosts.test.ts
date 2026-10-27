// http check actions (httpSource, run by the MCP-side agent through core.registry) use the core's replay policy:
// a target host outside replay.allowHosts is refused, and so is any target when no allowlist is configured.
// Local server on 127.0.0.1 only; names resolve through a stub.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ReplayConfig } from "../src/core/index.js";
import { loopbackCidrs } from "../src/demo-agent/allowlist.js";
import { mockCore, SB } from "./helpers.js";

let srv: http.Server, port = 0, hits = 0;
beforeAll(async () => {
  srv = http.createServer((_q, r) => { hits++; r.writeHead(200); r.end("ok"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

const resolver = async () => "127.0.0.1";
async function runHttp(replay: ReplayConfig | undefined, url: string) {
  const { core } = mockCore(replay ? { replay } : {});
  const w = core.startWalkthrough({ title: "t", sandbox: SB });
  const before = hits;
  const out = await core.registry.action("http").run({ type: "http", method: "GET", url }, { walkthrough: core.load(w.id), sandbox: undefined as never, replay: core.replayPolicy(), resolver });
  return { out, hits: hits - before };
}
const listed = (): ReplayConfig => ({ allowHosts: [`app.local:${port}`], allowCidrs: ["127.0.0.1/32"] });

describe("http check action follows replay.allowHosts", () => {
  it("negative: a host outside replay.allowHosts is refused, nothing is sent", async () => {
    const { out, hits: n } = await runHttp(listed(), `http://other.local:${port}/`);
    expect(out.status).toBeUndefined();
    expect(out.evidenceText).toContain(`host other.local:${port} is not in the replay allowlist`);
    expect(n).toBe(0);
  });
  it("negative: no replay.allowHosts configured → refused, no fallback", async () => {
    const { out, hits: n } = await runHttp(undefined, `http://app.local:${port}/`);
    expect(out.status).toBeUndefined();
    expect(out.evidenceText).toContain("http action needs replay.allowHosts");
    expect(n).toBe(0);
  });
  it("positive: a listed host is fetched", async () => {
    const { out, hits: n } = await runHttp(listed(), `http://app.local:${port}/`);
    expect(out).toMatchObject({ status: 200, body: "ok" });
    expect(n).toBe(1);
  });
});

describe("demo allowlist: localhost is treated like 127.0.0.1", () => {
  it("both get the loopback exception (localhost also ::1, whichever it resolves to)", () => {
    expect(loopbackCidrs([new URL("http://127.0.0.1:3000")])).toEqual(["127.0.0.1/32"]);
    expect(loopbackCidrs([new URL("http://localhost:3000")])).toEqual(["127.0.0.1/32", "::1/128"]);
    expect(loopbackCidrs([new URL("http://svc.example:3000")])).toEqual([]);
  });
});
