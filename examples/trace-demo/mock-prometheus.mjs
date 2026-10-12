// Minimal fake Prometheus for the trace demo: only GET /api/v1/query, bearer token required.
// http_requests_total for the orders total route shows a 5xx spike (ratio 0.5 over 5m). No Grafana.
import http from "node:http";

export function startMockPrometheus(port, token) {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.method !== "GET" || u.pathname !== "/api/v1/query") return json(404, { status: "error", errorType: "not_found", error: "mock serves GET /api/v1/query only" });
    if (req.headers.authorization !== `Bearer ${token}`) return json(401, { status: "error", errorType: "unauthorized", error: "bad token" });
    const q = u.searchParams.get("query") ?? "";
    const now = Date.now() / 1000;
    if (/http_requests_total/.test(q) && /status=~"5\.\."/.test(q)) return json(200, { status: "success", data: { resultType: "vector", result: [{ metric: {}, value: [now, "0.5"] }] } });
    return json(200, { status: "success", data: { resultType: "vector", result: [] } });
  });
  return new Promise((r) => srv.listen(port, "127.0.0.1", () => r(srv)));
}
