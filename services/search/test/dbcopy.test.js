// The Storage Box copy of the index: seed a missing database from it, back a live one up to it (a local fake
// WebDAV server stands in for the Storage Box).
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { open } = require("../lib/db");
const { seed, backup, DIR } = require("../lib/dbcopy");

function fakeDav() {
  const files = new Map();
  const srv = http.createServer((req, res) => {
    const p = decodeURIComponent(req.url.slice(1));
    if (req.headers.authorization !== "Basic " + Buffer.from("u:p").toString("base64")) { res.writeHead(401); return res.end(); }
    if (req.method === "GET") { if (!files.has(p)) { res.writeHead(404); return res.end(); } res.writeHead(200); return res.end(files.get(p)); }
    if (req.method === "PUT") { const b = []; req.on("data", (c) => b.push(c)); req.on("end", () => { files.set(p, Buffer.concat(b)); res.writeHead(201); res.end(); }); return; }
    if (req.method === "MOVE") { const to = decodeURIComponent(new URL(req.headers.destination).pathname.slice(1)); files.set(to, files.get(p)); files.delete(p); res.writeHead(201); return res.end(); }
    res.writeHead(405); res.end();
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, files, env: { STORAGEBOX_HOST: `127.0.0.1:${srv.address().port}`, STORAGEBOX_USER: "u", STORAGEBOX_PASSWORD: "p", STORAGEBOX_SCHEME: "http" } })));
}

test("dbcopy: no copy -> none; backup then seed restores the same rows; an existing db is never replaced", async () => {
  const { srv, files, env } = await fakeDav();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dbcopy-"));
  process.env.TMPDIR = dir;
  const quiet = () => {};
  try {
    assert.equal(await seed(path.join(dir, "a.db"), env, quiet), "none");
    const db = open(path.join(dir, "a.db"));
    db.prepare("INSERT INTO kv(k, v) VALUES ('x', 'kept')").run();
    assert.equal(await backup(db, "search.db", env, quiet), true);
    assert.ok(files.has(`${DIR}/search.db.gz`) && !files.has(`${DIR}/search.db.gz.part`));
    const b = path.join(dir, "b.db");
    assert.equal(await seed(b, { ...env, SEED_NAME: "search.db" }, quiet), "seeded");
    assert.equal(open(b).prepare("SELECT v FROM kv WHERE k = 'x'").get().v, "kept");
    assert.equal(await seed(b, { ...env, SEED_NAME: "search.db" }, quiet), "exists");
  } finally { srv.close(); }
});
