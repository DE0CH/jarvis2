#!/usr/bin/env node
// Front for the Paseo daemon's web UI when it is published through the cf-tunnel.
//
// The daemon tells its web UI where to connect from the request it was served on
// (`Host` + `req.protocol` -> window.__PASEO_INITIAL_DAEMON_CONNECTION__). Behind the tunnel the
// agent fetches http://127.0.0.1:<port>, so the UI would be told "127.0.0.1:6767, no TLS" and
// try to reach the phone's own localhost. This proxy sits between the tunnel agent and the
// daemon and presents every request (WebSocket upgrades included) as having arrived on the
// public host over https; the daemon trusts X-Forwarded-Proto from loopback.
//
//   PASEO_FRONT_PORT   listen port on 127.0.0.1            (default 6768)
//   PASEO_DAEMON_PORT  the daemon's port on 127.0.0.1      (default 6767)
//   PASEO_PUBLIC_HOST  host[:port] the browser uses, e.g. <session id>-s.deyaochen.com:443 (required)
//   PASEO_PUBLIC_PROTO https | http                        (default https)
const http = require("http");
const net = require("net");

const PORT = parseInt(process.env.PASEO_FRONT_PORT || "6768", 10);
const DAEMON = parseInt(process.env.PASEO_DAEMON_PORT || "6767", 10);
const HOST = process.env.PASEO_PUBLIC_HOST;
if (!HOST) { console.error("[paseo-front] PASEO_PUBLIC_HOST is required"); process.exit(1); }
const PROTO = process.env.PASEO_PUBLIC_PROTO || "https";

const rewrite = (headers) => ({ ...headers, host: HOST, "x-forwarded-proto": PROTO, "x-forwarded-host": HOST });

const server = http.createServer((req, res) => {
  const up = http.request({ host: "127.0.0.1", port: DAEMON, method: req.method, path: req.url, headers: rewrite(req.headers) }, (r) => {
    res.writeHead(r.statusCode || 502, r.headers);
    r.pipe(res);
  });
  up.on("error", (e) => { if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" }); res.end("paseo daemon not reachable: " + e.message); });
  req.pipe(up);
});

// WebSocket upgrade: replay the handshake to the daemon with the rewritten headers, then splice.
server.on("upgrade", (req, socket, head) => {
  const up = net.connect(DAEMON, "127.0.0.1", () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (const [k, v] of Object.entries(rewrite(req.headers))) for (const one of [].concat(v)) lines.push(`${k}: ${one}`);
    up.write(lines.join("\r\n") + "\r\n\r\n");
    if (head && head.length) up.write(head);
    up.pipe(socket); socket.pipe(up);
  });
  const end = () => { up.destroy(); socket.destroy(); };
  up.on("error", end); socket.on("error", end);
});

server.listen(PORT, "127.0.0.1", () => console.log(`[paseo-front] 127.0.0.1:${PORT} -> 127.0.0.1:${DAEMON} as ${PROTO}://${HOST}`));
