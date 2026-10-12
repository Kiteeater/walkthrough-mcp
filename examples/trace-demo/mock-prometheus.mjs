// Minimal fake Prometheus for the trace demo: only GET /api/v1/query and /api/v1/alerts, bearer token required.
// http_requests_total for the orders total route shows a 5xx spike (ratio 0.5 over 5m). No Grafana.
import http from "node:http";

export function startMockPrometheus(port, token, serviceUrl) {
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, "http://x");
    const json = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.method === "GET" && u.pathname === "/api/v1/alerts") {
      if (req.headers.authorization !== `Bearer ${token}`) return json(401, { status: "error", errorType: "unauthorized", error: "bad token" });
      const activeAt = new Date(Date.now() - 4 * 60_000).toISOString();
      // HighOrders5xx fires only once the service has actually answered a 500 (activeAt = that moment).
      const stats = await fetch(`${serviceUrl}/metrics.json`).then((r) => r.json()).catch(() => ({ orders5xx: 0 }));
      return json(200, { status: "success", data: { alerts: [
        // Firing, related to the orders total route (the traced 500). The runbook URL carries a token that must be redacted.
        ...(stats.orders5xx > 0 ? [{ labels: { alertname: "HighOrders5xx", route: "/api/orders/:id/total", severity: "critical" }, annotations: { summary: "5xx ratio on /api/orders/:id/total above 10% for 2m", runbook_url: `https://runbook.example/orders-5xx?token=${token}&v=2` }, state: "firing", activeAt: stats.first5xxAt, value: "0.5" }] : []),
        // Firing but unrelated to any check: listed separately, never attached.
        { labels: { alertname: "DiskAlmostFull", instance: "mongo-1", severity: "warning" }, annotations: { summary: "disk 91% full" }, state: "firing", activeAt, value: "0.91" },
        // Pending: not counted.
        { labels: { alertname: "SlowCheckout", route: "/api/checkout", severity: "warning" }, annotations: {}, state: "pending", activeAt, value: "2.1" },
      ] } });
    }
    if (req.method !== "GET" || u.pathname !== "/api/v1/query") return json(404, { status: "error", errorType: "not_found", error: "mock serves GET /api/v1/query only" });
    if (req.headers.authorization !== `Bearer ${token}`) return json(401, { status: "error", errorType: "unauthorized", error: "bad token" });
    const q = u.searchParams.get("query") ?? "";
    const now = Date.now() / 1000;
    if (/http_requests_total/.test(q) && /status=~"5\.\."/.test(q)) return json(200, { status: "success", data: { resultType: "vector", result: [{ metric: {}, value: [now, "0.5"] }] } });
    return json(200, { status: "success", data: { resultType: "vector", result: [] } });
  });
  return new Promise((r) => srv.listen(port, "127.0.0.1", () => r(srv)));
}
