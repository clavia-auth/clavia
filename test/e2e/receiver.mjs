// A webhook receiver for the end-to-end stack: it keeps what it is sent, and says so on request. Node only,
// no dependency.
//
//   https://receiver.clavia.test/...   (443, inside the stack) takes any POST: Clavia's deliveries. The
//                                      certificate is the stack's, so the CA Clavia trusts trusts it.
//   http://127.0.0.1:8026/deliveries   (published on this machine only) GET lists what arrived, oldest
//                                      first, headers and body exactly as received; DELETE forgets it.
//   http://127.0.0.1:8026/healthz      answers 200.
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const received = [];

function record(request, response) {
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    received.push({
      method: request.method,
      path: request.url,
      headers: request.headers,
      body: Buffer.concat(chunks).toString("utf8"),
      receivedAt: new Date().toISOString(),
    });
    response.writeHead(200, { "Content-Type": "application/json" }).end("{}");
  });
}

https
  .createServer(
    { cert: readFileSync("/certs/clavia.test.pem"), key: readFileSync("/certs/clavia.test-key.pem") },
    record,
  )
  .listen(443);

http
  .createServer((request, response) => {
    if (request.url === "/healthz") {
      response.writeHead(200).end("ok");
    } else if (request.url === "/deliveries" && request.method === "GET") {
      response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(received));
    } else if (request.url === "/deliveries" && request.method === "DELETE") {
      received.length = 0;
      response.writeHead(204).end();
    } else {
      response.writeHead(404).end();
    }
  })
  .listen(8026);
