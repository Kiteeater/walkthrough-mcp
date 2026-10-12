const http = require("node:http");

const apiKey = process.env.DEMO_API_KEY || "";
// Deliberately logs the key so the walkthrough's redaction can be seen working.
console.log(`hello-service starting, api key loaded: ${apiKey}`);

const greeting = () => ({ message: "Hello from the new greeting endpoint", version: 2 });

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("ok");
  }
  if (req.url === "/api/greeting") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(greeting()));
  }
  res.writeHead(200, { "content-type": "text/html" });
  res.end(`<!doctype html><html><body style="font-family:sans-serif">
<h1>hello-service</h1>
<div id="banner" style="background:#ddf4ff;padding:1rem">${greeting().message}</div>
</body></html>`);
});

server.listen(3000, () => console.log("listening on 3000"));
