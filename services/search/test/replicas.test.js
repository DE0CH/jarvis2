// The int8 vector store (query.js) ranks exactly like a full float scan, and the writer lease (lease.js) hands over
// between replicas: a clean release passes it at once, a dead holder's lease lapses, run records say how a copy ended.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { open } = require("../lib/db");
const { Searcher, quantize, dot } = require("../lib/query");
const { Lease } = require("../lib/lease");
const { vecToBlob, EMBED_MODEL, EMBED_DIMS } = require("../lib/embed");

function unit(rand) { const v = new Float32Array(EMBED_DIMS); let n = 0; for (let j = 0; j < v.length; j++) { v[j] = rand() - 0.5; n += v[j] * v[j]; } n = Math.sqrt(n); for (let j = 0; j < v.length; j++) v[j] /= n; return v; }
function rng(seed) { let s = seed; return () => ((s = (s * 1103515245 + 12345) % 2147483648) / 2147483648); }

test("int8 quantize keeps cosine within 1e-2", () => {
  const r = rng(7), a = unit(r), b = unit(r), q = new Int8Array(EMBED_DIMS * 2);
  const sa = quantize(a, q, 0), sb = quantize(b, q, EMBED_DIMS);
  let s = 0; for (let j = 0; j < EMBED_DIMS; j++) s += q[j] * b[j];
  assert.ok(Math.abs(s * sa - dot(a, b)) < 1e-2);
  assert.ok(sb > 0);
});

test("semantic leg: int8 candidates + exact rescore = the exact float ranking", async () => {
  const db = open(":memory:"), r = rng(42), ins = db.prepare("INSERT INTO chunks(file, grp, kind, text, hash) VALUES ('f','g','msg',?,?)"), emb = db.prepare("INSERT INTO emb(hash, model, vec) VALUES (?,?,?)");
  const center = unit(r), vecs = [];
  db.transaction(() => {
    for (let i = 0; i < 3000; i++) {
      // half the rows cluster near the query, so near-ties are many
      const v = unit(r); if (i % 2) { let n = 0; for (let j = 0; j < v.length; j++) { v[j] = v[j] * 0.3 + center[j]; n += v[j] * v[j]; } n = Math.sqrt(n); for (let j = 0; j < v.length; j++) v[j] /= n; }
      const h = crypto.randomBytes(8).toString("hex"); ins.run(`t${i}`, h); emb.run(h, EMBED_MODEL, vecToBlob(v)); vecs.push(v);
    }
  })();
  const s = new Searcher(db, () => {}); await s.load();
  assert.equal(s.q8.byteLength, 3000 * EMBED_DIMS);
  const got = s.semanticLeg(center, { where: "", params: [] }, false);
  const want = vecs.map((v, i) => ({ id: i + 1, score: dot(v, center) })).sort((a, b) => b.score - a.score).slice(0, got.length);
  assert.deepEqual(got.map((x) => x.id), want.map((x) => x.id));
  assert.ok(Math.abs(got[0].score - want[0].score) < 1e-6);
  // dedupe drops an exact duplicate
  assert.equal(s.dedupe([{ id: 1, score: 1 }, { id: 1, score: 0.9 }]).length, 1);
});

test("writer lease: one holder, clean handover, lapse after a kill, run records", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lease-")), file = path.join(dir, "s.db");
  let t = Date.parse("2026-10-15T03:00:00Z");
  const now = () => t;
  const dbA = open(file), dbB = open(file); // two replicas = two connections to one file
  const a = new Lease(dbA, { holder: "search-a", now }), b = new Lease(dbB, { holder: "search-b", now });
  a.runStarted({ started: new Date(t).toISOString() }); b.runStarted({ started: new Date(t).toISOString() });
  assert.equal(a.tryAcquire(), true);
  assert.equal(b.tryAcquire(), false);
  t += 10000; assert.equal(a.tryAcquire(), true); // renew
  // a rollout: a releases, b takes it at once
  a.release(); a.runEnded("SIGTERM (rollout)");
  assert.equal(b.tryAcquire(), true);
  assert.equal(b.previousRun().pod, "search-a");
  assert.match(b.previousRun().ended.how, /SIGTERM/);
  // b is killed (no release): c waits out the TTL
  const c = new Lease(open(file), { holder: "search-c", now });
  t += 1000; b.heartbeat({ memory: { rssMB: 760 } });
  assert.equal(c.tryAcquire(), false);
  t += 46000; assert.equal(c.tryAcquire(), true);
  t += 120001;
  const prev = c.previousRun();
  assert.equal(prev.pod, "search-b"); assert.match(prev.ended.how, /killed/); assert.equal(prev.ended.lastMemory.rssMB, 760);
  // b's container restarts in the same pod: its record says the last run had no clean exit
  b.runStarted({ started: new Date(t).toISOString() });
  const mine = b.read("run:search-b");
  assert.equal(mine.restarts, 1); assert.match(mine.restartedAfter.ended.how, /killed/);
  // index version + reindex requests travel through the file
  a.bumpIndexVersion(); assert.equal(c.indexVersion(), 1);
  b.requestReindex(true); assert.deepEqual(c.takeReindex().full, true); assert.equal(c.takeReindex(), null);
});
