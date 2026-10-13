// Transcript search service (Jarvis 2: k8s/apps/search.yaml, namespace jarvis2-edge). The router forwards
// /api/search* (the app) and /m/api/search* (sessions) here; it is never exposed on its own. Hybrid keyword +
// semantic search over every session transcript of both Jarvises on the Storage Box (archives, Jarvis 1's
// .paused/ snapshots, .live/ copies of running sessions) and the task records. API: docs/API.md "Transcript search".
//
// env: SEARCH_DB (sqlite path on the PVC), STORAGEBOX_HOST/USER/PASSWORD, OPENROUTER_API,
//      INDEX_INTERVAL_S (crawl period, default 600), PORT (8090), LOCAL_ROOT (dev: a local mirror),
//      BACKUP_INTERVAL_H (copy to the Storage Box, default 24; 0 = off)
const express = require("express");
const path = require("path");
const fs = require("fs");
const { open } = require("./db");
const source = require("./source");
const { Indexer } = require("./indexer");
const { Searcher } = require("./query");
const { EMBED_MODEL, RERANK_MODEL } = require("./embed");

const log = (m) => console.log(`${new Date().toISOString()} ${m}`);
const DB_FILE = process.env.SEARCH_DB || path.join(process.cwd(), "search.db");
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
fs.mkdirSync(require("os").tmpdir(), { recursive: true }); // TMPDIR points into the PVC (k8s/search)
const dbcopy = require("./dbcopy");
let db, searcher, indexer;

const app = express();
app.use(express.json());
const bool = (v, d) => (v == null || v === "" ? d : !/^(0|false|no|off)$/i.test(String(v)));
const KINDS = new Set(["msg", "tool", "doc"]);
const STATES = new Set(["live", "paused", "archive"]);
const DATE = /^\d{4}-\d{2}-\d{2}$/;

app.get("/search", async (req, res) => {
  const s = req.query, q = String(s.q || "").trim();
  if (!q) return res.status(400).json({ error: "q is required" });
  if (q.length > 2000) return res.status(400).json({ error: "q is too long (max 2000 chars)" });
  const kinds = String(s.kind || "").split(",").map((k) => k.trim()).filter((k) => KINDS.has(k));
  for (const k of ["after", "before"]) if (s[k] && !DATE.test(s[k])) return res.status(400).json({ error: `${k} must be YYYY-MM-DD` });
  const mode = ["hybrid", "keyword", "semantic"].includes(s.mode) ? s.mode : "hybrid";
  try {
    res.json(await searcher.search({
      q, mode, kinds, after: s.after, before: s.before, session: s.session ? String(s.session) : null, states: String(s.state || "").split(",").map((x) => x.trim()).filter((x) => STATES.has(x)), archived: bool(s.archived, false),
      limit: Math.min(Math.max(parseInt(s.limit, 10) || 10, 1), 50), rerank: bool(s.rerank, true), group: bool(s.group, false), full: bool(s.full, false),
    }));
  } catch (e) { log(`search failed: ${e.stack || e.message}`); res.status(500).json({ error: e.message }); }
});

app.get("/context", (req, res) => {
  const n = (v, d) => Math.min(Math.max(parseInt(v, 10) || d, 0), 30);
  const c = searcher.context(parseInt(req.query.id, 10), n(req.query.before, 3), n(req.query.after, 3));
  if (!c) return res.status(404).json({ error: "no such chunk" });
  res.json(c);
});

app.get("/status", (req, res) => {
  const counts = db.prepare("SELECT (SELECT count(*) FROM chunks) chunks, (SELECT count(*) FROM sessions) sessions, (SELECT count(*) FROM files) files, (SELECT count(*) FROM emb) vectors").get();
  const kinds = Object.fromEntries(db.prepare("SELECT kind, count(*) n FROM chunks GROUP BY kind").all().map((r) => [r.kind, r.n]));
  const states = Object.fromEntries(db.prepare("SELECT source, count(*) n FROM sessions GROUP BY source").all().map((r) => [r.source, r.n]));
  const span = db.prepare("SELECT min(date) first, max(date) last FROM chunks WHERE date IS NOT NULL").get();
  res.json({ ok: true, ...counts, kinds, sessions_by_state: states, span, vectorsLoaded: searcher.ids.length, embedModel: EMBED_MODEL, rerankModel: RERANK_MODEL, indexer: indexer.status });
});

// the router pokes this after an archive, so a finished session is searchable at once
app.post("/reindex", (req, res) => { indexer.run({ full: bool(req.query.full, false) }); res.status(202).json({ started: true, indexer: indexer.status }); });

app.get("/healthz", (req, res) => res.json({ ok: true }));

async function main() {
  // a new volume starts from the copy on the Storage Box (its embeddings are paid for), not from nothing
  if (!process.env.LOCAL_ROOT) log(`seed: ${await dbcopy.seed(DB_FILE, process.env, log)}`);
  db = open(DB_FILE);
  searcher = new Searcher(db, log);
  indexer = new Indexer(db, source.fromEnv(), log);
  indexer.onChange = () => searcher.load();
  const port = +(process.env.PORT || 8090);
  app.listen(port, process.env.HOST || "0.0.0.0", () => {
    log(`transcript search on :${port}, db ${DB_FILE}`);
    if (!bool(process.env.NO_INDEX, false)) {
      indexer.run();
      setInterval(() => indexer.run(), Math.max(60, +(process.env.INDEX_INTERVAL_S || 600)) * 1000).unref();
      if (!process.env.LOCAL_ROOT) dbcopy.backupLoop(db, path.basename(DB_FILE), process.env, log);
    }
  });
}
main().catch((e) => { log(`start failed: ${e.stack || e.message}`); process.exit(1); });
