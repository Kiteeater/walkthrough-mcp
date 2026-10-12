// Minimal stand-in for Langfuse's public API (ingestion + GET trace), basic-auth protected like the real one.
import http from "node:http";

export function startMockLangfuse(port, publicKey, secretKey) {
  const traces = new Map();
  const expected = "Basic " + Buffer.from(`${publicKey}:${secretKey}`).toString("base64");
  const server = http.createServer(async (req, res) => {
    if (req.headers.authorization !== expected) { res.writeHead(401); return res.end("unauthorized"); }
    if (req.method === "POST" && req.url === "/api/public/ingestion") {
      let body = ""; for await (const c of req) body += c;
      const t = JSON.parse(body); traces.set(t.id, { ...t, timestamp: new Date().toISOString() });
      res.writeHead(207, { "content-type": "application/json" }); return res.end(JSON.stringify({ successes: [{ id: t.id }] }));
    }
    const m = /^\/api\/public\/traces\/([\w-]+)$/.exec(req.url ?? "");
    if (req.method === "GET" && m && traces.has(m[1])) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(traces.get(m[1]))); }
    res.writeHead(404); res.end("not found");
  });
  return new Promise((r) => server.listen(port, () => r(server)));
}
