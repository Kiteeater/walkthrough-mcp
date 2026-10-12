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
    if (req.url === "/health") return json(res, 200, { ok: true });
    if (req.url === "/api/orders") return json(res, 200, listOrders());
    const m = /^\/api\/orders\/(\d+)$/.exec(req.url);
    if (m) {
      const order = getOrder(Number(m[1]));
      return order ? json(res, 200, order) : json(res, 404, { error: "not found" });
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

server.listen(port, () => console.log(`listening on ${port}`));
