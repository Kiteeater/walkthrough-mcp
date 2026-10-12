const http = require("node:http");
const { listOrders, getOrder } = require("./orders");

const port = Number(process.env.PORT || 3000);
const apiKey = process.env.DEMO_API_KEY || "";
// Deliberately logs the key so the walkthrough's redaction can be seen working.
console.log(`orders-service starting, api key loaded: ${apiKey}`);

const json = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);
  try {
    if (req.url === "/health") { res.setHeader("x-walkthrough-demo-token", process.env.DEMO_HEALTH_TOKEN || ""); return json(res, 200, { ok: true }); }
    if (req.url === "/api/orders") return json(res, 200, listOrders());
    const m = /^\/api\/orders\/(\d+)$/.exec(req.url);
    if (m) {
      const order = getOrder(Number(m[1]));
      return order ? json(res, 200, order) : json(res, 404, { error: "not found" });
    }
    if (req.url === "/orders") {
      // Orders page: the frontend calls /api/orders and shows an error banner when it fails.
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(`<!doctype html><html><body style="font-family:sans-serif"><h1>Orders</h1><div id="out">loading…</div>
<script>
fetch("/api/orders").then(async (r) => {
  if (!r.ok) throw new Error("HTTP " + r.status);
  const rows = await r.json();
  document.getElementById("out").innerHTML = rows.map((o) => "<p>#" + o.id + " " + o.customer + " " + o.total + "</p>").join("");
}).catch((e) => {
  const out = document.getElementById("out");
  out.style.cssText = "color:#fff;background:#cf222e;padding:8px";
  out.textContent = "Failed to load orders (" + e.message + ")";
});
</script></body></html>`);
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><html><body style="font-family:sans-serif"><h1>orders-service</h1>
<p>Endpoints: <code>/api/orders</code>, <code>/api/orders/:id</code></p></body></html>`);
  } catch (err) {
    console.error(`request failed: ${req.method} ${req.url}`);
    console.error(err.stack);
    json(res, 500, { error: "internal error" });
  }
});

server.listen(port, process.env.HOST || undefined, () => console.log(`listening on ${server.address().port}`));
