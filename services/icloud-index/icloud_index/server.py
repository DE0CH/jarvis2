"""iCloud index service: runs the indexer threads and answers searches.

Jarvis 2: k8s/apps/icloud-index.yaml (namespace jarvis2-edge); the router forwards /api/icloud/* (the app) and
/m/api/icloud/* (sessions) here. Never exposed on its own. API: docs/API.md "iCloud index".
  GET  /search?q=…&limit=&kind=&ext=&under=&after=&before=&mode=hybrid|keyword|semantic&rerank=&full=
  GET  /file?path=…      one file's record and all its extracted text
  GET  /status           counts, spend, listing, the file being read now, errors
  POST /relist           list iCloud now (instead of waiting for the daily listing)
  POST /retry            give failed files another go
  GET  /healthz
env: INDEX_DB, WORK_DIR, RCLONE_CONFIG, ICLOUD_CONF_FILE, OPENROUTER_API, LOBSTER_TOKEN, AI_BUDGET_USD,
     LIST_INTERVAL_H, VISION_MODEL, AUDIO_MODEL, EMBED_MODEL, EMBED_DIMS, RERANK_MODEL, PORT, NO_INDEX,
     STORAGEBOX_HOST/USER/PASSWORD, SEED_REQUIRED, BACKUP_INTERVAL_H (backup.py: the copy on the Storage Box)
"""
import json, os, threading, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from . import ai, backup, db as D, indexer as I, search as S

DB_FILE = os.environ.get("INDEX_DB", "/data/index.db")
os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
print(f"seed: {backup.seed(DB_FILE)}", flush=True)  # a missing database starts from its copy, never from nothing
D.connect(DB_FILE).close()
searcher = S.Searcher(DB_FILE)
idx = I.Indexer(DB_FILE, searcher)
lock = threading.Lock()
KINDS = {"text", "pdf", "office", "iwork", "image", "raw", "audio", "video", "archive", "other"}


def status():
    db = searcher.db
    by = lambda col: {r[0]: r[1] for r in db.execute(f"SELECT {col}, count(*) FROM files GROUP BY {col}")}
    g = lambda k, d=None: D.kv_get(db, k, d)
    return {"ok": True, "files": db.execute("SELECT count(*) FROM files").fetchone()[0], "states": by("state"), "kinds": by("kind"),
            "chunks": db.execute("SELECT count(*) FROM chunks").fetchone()[0], "vectors": db.execute("SELECT count(*) FROM emb").fetchone()[0],
            "vectorsLoaded": len(searcher.hashes),
            "aiSpentUsd": round(float(g("ai_spent", 0) or 0), 4), "aiBudgetUsd": I.AI_BUDGET_USD, "embedSpentUsd": round(float(g("embed_spent", 0) or 0), 4),
            "lastListing": json.loads(g("last_list", "null") or "null"), "listError": g("list_error"),
            "models": {"vision": ai.VISION_MODEL, "audio": ai.AUDIO_MODEL, "embed": ai.EMBED_MODEL, "rerank": S.RERANK_MODEL},
            "indexer": idx.status,
            "errors": [dict(r) for r in db.execute("SELECT path, error, tries FROM files WHERE state='error' ORDER BY rowid DESC LIMIT 10")]}


class H(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
        try:
            if u.path == "/healthz": return self.reply(200, {"ok": True})
            if u.path == "/status":
                with lock: return self.reply(200, status())
            if u.path == "/file":
                with lock: r = searcher.file(q.get("path", ""))
                return self.reply(200, r) if r else self.reply(404, {"error": "no such file in the index"})
            if u.path == "/search":
                text = (q.get("q") or "").strip()
                if not text: return self.reply(400, {"error": "q is required"})
                if len(text) > 1000: return self.reply(400, {"error": "q is too long (max 1000 chars)"})
                if q.get("kind") and not set(q["kind"].split(",")) <= KINDS: return self.reply(400, {"error": f"kind must be among {sorted(KINDS)}"})
                b = lambda v, d: d if v in (None, "") else v.lower() not in ("0", "false", "no", "off")
                o = {"q": text, "limit": max(1, min(int(q.get("limit") or 10), 100)), "kind": q.get("kind"), "ext": q.get("ext"), "under": q.get("under"),
                     "after": q.get("after"), "before": q.get("before"), "mode": q.get("mode") if q.get("mode") in ("hybrid", "keyword", "semantic") else "hybrid",
                     "rerank": b(q.get("rerank"), True), "full": b(q.get("full"), False)}
                with lock: return self.reply(200, searcher.search(o))
            self.reply(404, {"error": "not found"})
        except Exception as e:
            self.reply(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        if self.path.startswith("/relist"):
            idx.relist_now.set(); return self.reply(202, {"started": True})
        if self.path.startswith("/retry"):
            with lock: searcher.db.execute("UPDATE files SET state='new', tries=0 WHERE state='error'")
            idx.wake.set(); return self.reply(202, {"started": True})
        self.reply(404, {"error": "not found"})


def main():
    if os.environ.get("NO_INDEX", "") not in ("1", "true"):
        idx.start()
        backup.backup_loop(DB_FILE)
    port = int(os.environ.get("PORT", "8091"))
    print(f"icloud index on :{port}, db {DB_FILE}", flush=True)
    ThreadingHTTPServer((os.environ.get("HOST", "0.0.0.0"), port), H).serve_forever()


if __name__ == "__main__":
    main()
