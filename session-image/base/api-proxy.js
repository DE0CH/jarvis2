#!/usr/bin/env node
// Transparent logging proxy between the claude CLI and the Anthropic API (Deyao, 2026-10-02).
// harness-claude.sh starts it for a session created with "API proxy" on (SESSION_API_PROXY=1) and runs
// claude with ANTHROPIC_BASE_URL=http://127.0.0.1:$API_PROXY_PORT. Every request is forwarded to
// $API_PROXY_UPSTREAM (default https://api.anthropic.com) unchanged, the response is streamed back
// chunk by chunk, and the exchange is logged under ~/artifacts/api-log/ (archived with the session).
//
// Log: one gzip JSON per exchange, exchanges/<seq>-<method>-<path>.json.gz =
//   {seq, startedAt, endedAt, method, path, status, requestHeaders, responseHeaders (ALL headers,
//    unredacted — Deyao's choice: the log holds the live OAuth bearer token), request (the body exactly as sent: parsed JSON, or text), response (the
//    body exactly as received: SSE text for a streamed message), error?}
// Full bodies every time, repeats and all (Deyao: storage is no concern).
//
// Logging never blocks or breaks forwarding: it runs after the data is passed on, and any logging
// error is printed and ignored.
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const PORT = Number(process.env.API_PROXY_PORT || 8788);
const UPSTREAM = new URL(process.env.API_PROXY_UPSTREAM || "https://api.anthropic.com");
const LOG_DIR = process.env.API_PROXY_LOG_DIR || path.join(process.env.HOME || "/tmp", "artifacts", "api-log");
const agent = new (UPSTREAM.protocol === "https:" ? https : http).Agent({ keepAlive: true, maxSockets: 64 });

// API_PROXY_CLAUDE_AUTH=1 (the openclaw harness): replace the client's credential with the access token in
// ~/.claude/.credentials.json — the same shared Claude login a claude session uses, read fresh per request.
const CLAUDE_AUTH = process.env.API_PROXY_CLAUDE_AUTH === "1";
const CREDS = path.join(process.env.HOME || "/tmp", ".claude", ".credentials.json");
function claudeAccessToken() {
  try { return JSON.parse(fs.readFileSync(CREDS, "utf8")).claudeAiOauth.accessToken; }
  catch (e) { console.error("[api-proxy] no Claude login in", CREDS + ":", e.message); return null; }
}

fs.mkdirSync(path.join(LOG_DIR, "exchanges"), { recursive: true });
let seq = 0;
try { seq = fs.readdirSync(path.join(LOG_DIR, "exchanges")).length; } catch {}

const gz = (obj) => zlib.gzipSync(Buffer.from(JSON.stringify(obj)));
function requestRecord(buf) {
  const text = buf.toString("utf8");
  try { return JSON.parse(text); } catch { return text; }
}
function writeLog(rec) {
  try {
    const name = `${String(rec.seq).padStart(6, "0")}-${rec.method}-${rec.path.split("?")[0].replace(/[^A-Za-z0-9]+/g, "_").slice(0, 60)}.json.gz`;
    fs.writeFile(path.join(LOG_DIR, "exchanges", name), gz(rec), (e) => e && console.error("[api-proxy] log write:", e.message));
  } catch (e) { console.error("[api-proxy] log:", e.message); }
}

const server = http.createServer((req, res) => {
  const startedAt = new Date().toISOString(), id = ++seq, reqChunks = [];
  req.on("data", (c) => reqChunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(reqChunks);
    const headers = { ...req.headers, host: UPSTREAM.host };
    if (CLAUDE_AUTH) { // the client holds a placeholder: send the session's current Claude login instead
      const token = claudeAccessToken();
      if (token) { delete headers["x-api-key"]; headers.authorization = `Bearer ${token}`; }
    }
    delete headers["accept-encoding"]; // identity responses: logged as readable text, same content
    delete headers["connection"];
    headers["content-length"] = String(body.length);
    const up = (UPSTREAM.protocol === "https:" ? https : http).request({
      protocol: UPSTREAM.protocol, hostname: UPSTREAM.hostname, port: UPSTREAM.port || undefined,
      method: req.method, path: req.url, headers, agent,
    }, (upRes) => {
      res.writeHead(upRes.statusCode, upRes.headers);
      const resChunks = [];
      upRes.on("data", (c) => { res.write(c); resChunks.push(c); });
      upRes.on("end", () => {
        res.end();
        setImmediate(() => {
          let reqRec; try { reqRec = requestRecord(body); } catch (e) { reqRec = `[unloggable: ${e.message}]`; }
          writeLog({ seq: id, startedAt, endedAt: new Date().toISOString(), method: req.method, path: req.url, status: upRes.statusCode,
            requestHeaders: req.headers, responseHeaders: upRes.headers, request: reqRec,
            response: Buffer.concat(resChunks).toString("utf8") });
        });
      });
      upRes.on("error", (e) => { res.destroy(e); });
    });
    up.on("error", (e) => {
      console.error(`[api-proxy] upstream error #${id} ${req.method} ${req.url}: ${e.message}`);
      if (!res.headersSent) { res.writeHead(502, { "content-type": "application/json" }); res.end(JSON.stringify({ type: "error", error: { type: "api_error", message: `api-proxy: upstream unreachable: ${e.message}` } })); }
      else res.destroy(e);
      writeLog({ seq: id, startedAt, endedAt: new Date().toISOString(), method: req.method, path: req.url, status: null,
        requestHeaders: req.headers, request: (() => { try { return requestRecord(body); } catch { return null; } })(), error: e.message });
    });
    res.on("close", () => { if (!res.writableFinished) up.destroy(); }); // client went away: stop upstream too
    up.end(body);
  });
});
server.keepAliveTimeout = 120000;
server.listen(PORT, "127.0.0.1", () => console.log(`[api-proxy] listening on 127.0.0.1:${PORT} -> ${UPSTREAM.origin}, logging to ${LOG_DIR}`));
