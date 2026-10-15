// The index: one SQLite file (better-sqlite3) on the search pod's PVC.
//   files     what was indexed from the Storage Box and at which etag/size (incremental crawl)
//   sessions  one row per transcript (sid = the transcript's uuid)
//   chunks    the searchable units (see extract.js) — text kept verbatim for display
//   chunks_fts  FTS5 over the chunk text, contentless (rowid = chunks.id). Tokenizer is
//             porter+unicode61; CJK has no word boundaries, so text is indexed with every CJK
//             character spaced apart (cjkSpace) and a CJK query run becomes a phrase — exact
//             substring matching at any length (the trigram tokenizer can't match 2-char words
//             like 车票).
//   uuids     which file owns a transcript entry: a restored/resumed conversation is archived
//             again with its whole history, and the same entry must not be indexed twice
//   emb       embedding cache by chunk-text hash, so re-indexing a grown transcript is free
const Database = require("better-sqlite3");

const CJK = /([\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}])/gu;
const cjkSpace = (t) => String(t || "").replace(CJK, " $1 ");

function open(file) {
  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  // several replicas open this file (lease.js): a write waits briefly for another's lease transaction instead of
  // failing; short, because better-sqlite3 waits on the event loop
  db.pragma("busy_timeout = 300");
  db.exec(`
    CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, etag TEXT, size INTEGER, grp TEXT, indexed_at TEXT, chunks INTEGER DEFAULT 0, note TEXT);
    CREATE INDEX IF NOT EXISTS files_grp ON files(grp);
    CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, title TEXT, dir TEXT, source TEXT, machine_id TEXT, date TEXT, first_ts TEXT, last_ts TEXT, cwd TEXT, model TEXT, meta TEXT);
    CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, file TEXT NOT NULL, grp TEXT NOT NULL, sid TEXT, dir TEXT, title TEXT, source TEXT, kind TEXT NOT NULL, date TEXT, ts TEXT, line_from INTEGER, line_to INTEGER, text TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS chunks_file ON chunks(file);
    CREATE INDEX IF NOT EXISTS chunks_grp ON chunks(grp);
    CREATE INDEX IF NOT EXISTS chunks_sid ON chunks(sid, line_from);
    CREATE INDEX IF NOT EXISTS chunks_hash ON chunks(hash);
    CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, title, content='', contentless_delete=1, tokenize='porter unicode61 remove_diacritics 2');
    CREATE TABLE IF NOT EXISTS uuids(uuid TEXT PRIMARY KEY, grp TEXT NOT NULL) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS uuids_grp ON uuids(grp);
    CREATE TABLE IF NOT EXISTS emb(hash TEXT PRIMARY KEY, model TEXT NOT NULL, vec BLOB NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
  `);
  return db;
}

module.exports = { open, cjkSpace };
