// Demo service for the cross-source trace: reads orders from MongoDB, reports failures to Langfuse.
const http = require("node:http");
const { randomUUID } = require("node:crypto");
const { MongoClient } = require("mongodb");
const { orderTotal } = require("./pricing");

const port = Number(process.env.PORT || 0);
const client = new MongoClient(process.env.MONGO_URL);
const dbName = process.env.MONGO_DB || "walkthrough_demo";
const langfuse = process.env.LANGFUSE_URL;
const auth = "Basic " + Buffer.from(`${process.env.LANGFUSE_PUBLIC_KEY}:${process.env.LANGFUSE_SECRET_KEY}`).toString("base64");

async function report(trace) {
  await fetch(`${langfuse}/api/public/ingestion`, { method: "POST", headers: { authorization: auth, "content-type": "application/json" }, body: JSON.stringify(trace) });
}

const json = (res, status, body, headers = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body)); };

// Tiny 5xx counter the mock Prometheus "scrapes", so HighOrders5xx only fires after a 500 really happened.
const stats = { orders5xx: 0, first5xxAt: null };

http.createServer(async (req, res) => {
  console.log(`${req.method} ${req.url}`);
  if (req.url === "/health") return json(res, 200, { ok: true });
  if (req.url === "/metrics.json") return json(res, 200, stats);
  const m = /^\/api\/orders\/([\w-]+)\/total$/.exec(req.url);
  if (!m) return json(res, 404, { error: "not found" });
  const traceId = randomUUID();
  try {
    const order = await client.db(dbName).collection("orders").findOne({ _id: m[1] });
    if (!order) return json(res, 404, { error: "not found" });
    return json(res, 200, { id: order._id, total: orderTotal(order) });
  } catch (err) {
    stats.orders5xx++; stats.first5xxAt ??= new Date().toISOString();
    console.error(`request failed: ${req.method} ${req.url} trace=${traceId}`);
    console.error(err.stack);
    await report({ id: traceId, name: "GET /api/orders/:id/total", metadata: { db: dbName, collection: "orders", orderId: m[1] },
      observations: [{ name: "orderTotal", level: "ERROR", statusMessage: String(err.message) }] }).catch(() => {});
    return json(res, 500, { error: "internal error", traceId }, { "x-trace-id": traceId });
  }
}).listen(port, () => console.log(`trace-service listening on ${port}`));
