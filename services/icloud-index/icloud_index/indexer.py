"""The indexing loop: list iCloud, then extract one file at a time, then embed.

Three threads, each with its own SQLite connection:
  lister    every LIST_INTERVAL_H: `rclone lsjson -R`, upserting rows as they stream in (so names are
            searchable during the very first listing). Changed size/mtime -> re-extract. At the end,
            rows not seen are either renames (same iCloud id as a row inserted this run: the old row's
            text moves over, nothing is re-read) or deletions.
  worker    the queue: state='new' by prio (documents first, videos last), newest first. Local
            extraction is free; AI steps are bounded by AI_BUDGET_USD (total, lifetime) — when it is
            used up a file waits in state wait-ai and Deyao is DMed once.
  embedder  chunks whose text has no vector yet, in batches.

A dead iCloud session pauses everything and DMs Deyao once (re-login: icloud-drive skill).
"""
import hashlib, json, os, re, shutil, threading, time, traceback
from datetime import datetime, timezone

from . import ai, db as D, extract as X, notify, remote

LIST_INTERVAL_H = float(os.environ.get("LIST_INTERVAL_H", "24"))
AI_BUDGET_USD = float(os.environ.get("AI_BUDGET_USD", "0"))
WORK = os.environ.get("WORK_DIR", "/data/work")
THROTTLE_S = float(os.environ.get("THROTTLE_S", "1"))
BILLING_RETRY_S = 1800  # how often to try OpenRouter again after a 402 (out of credit)
CHUNK = 1500
MAX_FILE_CHARS = int(os.environ.get("MAX_FILE_CHARS", "400000"))
MAX_TRIES = 3

now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m):
    print(f"{now()} {m}", flush=True)


def chunk_text(text):
    """~CHUNK-char pieces cut at line breaks (or hard-cut inside a long line)."""
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > CHUNK:
            if cur: out.append(cur); cur = ""
            out.append(line[:CHUNK]); line = line[CHUNK:]
        if len(cur) + len(line) + 1 > CHUNK and cur:
            out.append(cur); cur = ""
        cur = (cur + "\n" + line) if cur else line
    if cur.strip(): out.append(cur)
    return [c.strip() for c in out if c.strip()]


def chunk_hash(name, text):
    return hashlib.sha256((name + "\n" + text).encode()).hexdigest()[:32]


class Ctx:
    """What an extractor sees: the AI gate (content cache + budget + spend) and the remote."""

    def __init__(self, idx, conn, file_id):
        self.idx, self.db, self.file_id, self.cost = idx, conn, file_id, 0.0

    def budget_left(self):
        return self.idx.budget_left(self.db)

    def cached(self, ckey, stage):
        return self.db.execute("SELECT 1 FROM aicache WHERE ckey=? AND stage=?", (ckey, stage)).fetchone() is not None

    def ai(self, ckey, stage, fn):
        r = self.db.execute("SELECT result FROM aicache WHERE ckey=? AND stage=?", (ckey, stage)).fetchone()
        if r: return json.loads(r[0])
        if not self.budget_left(): raise X.NeedBudget()
        try:
            result, cost = fn()
        except ai.Fatal as e:
            if e.billing:
                D.kv_set(self.db, "billing_retry_at", time.time() + BILLING_RETRY_S)
                self.idx.notice(self.db, "billing", "iCloud index: OpenRouter is out of credit, so reading images, scans and videos has paused. It resumes once the OpenRouter balance is topped up.")
                raise X.NeedBudget()
            raise
        if D.kv_get(self.db, "notice:billing"): self.idx.clear_notice(self.db, "billing")  # credit is back
        self.cost += cost
        D.kv_add(self.db, "ai_spent", cost)
        self.db.execute("INSERT OR REPLACE INTO aicache(ckey, stage, result) VALUES(?,?,?)", (ckey, stage, json.dumps(result, ensure_ascii=False)))
        return result


class Indexer:
    def __init__(self, db_file, searcher=None):
        self.db_file, self.searcher = db_file, searcher
        self.server = remote.Server()
        self.status = {"listing": None, "current": None, "auth": "ok", "lastError": None}
        self.wake = threading.Event()
        self.relist_now = threading.Event()
        self.stop = False

    def conn(self):
        return D.connect(self.db_file)

    # ------------------------------------------------------------ shared
    def budget_left(self, conn):
        return float(D.kv_get(conn, "ai_spent", 0) or 0) < AI_BUDGET_USD

    def notice(self, conn, key, text):
        """DM Deyao once per condition (cleared by clear_notice when it resolves)."""
        if D.kv_get(conn, "notice:" + key): return
        D.kv_set(conn, "notice:" + key, now())
        notify.dm(text)

    def clear_notice(self, conn, key):
        D.kv_set(conn, "notice:" + key, None)

    def auth_failed(self, conn, e):
        if self.status["auth"] != "expired":
            log(f"iCloud session no longer works: {str(e)[:200]}")
        self.status["auth"] = "expired"
        self.notice(conn, "auth", "iCloud index: the saved iCloud login has expired, so indexing has paused. Ask a session to run the icloud-drive skill's login (you approve one Apple 2FA code) and write the new session into k8s/secrets/icloud-session.enc.yaml (infra/router-secrets.py --part icloud-session); the index picks it up by itself.")

    def wait_auth(self, conn):
        """Blocks until the iCloud session works again (a new login lands in the Secret)."""
        while not self.stop:
            try:
                remote.probe()
                self.status["auth"] = "ok"; self.clear_notice(conn, "auth"); self.server.restart()
                log("iCloud session works again")
                return
            except remote.AuthError:
                time.sleep(600)
            except Exception:
                time.sleep(300)

    # ------------------------------------------------------------ lister
    def relist(self):
        # kinds with no readable content are indexed by name only, from the moment they are listed
        initial = lambda kind: ("done", "name only") if kind == "other" else ("new", None)
        conn = self.conn(); t0 = time.time(); n = new = changed = 0
        stamp = f"{now()}#{os.urandom(4).hex()}"  # unique per run: two listings can fall in the same second
        self.status["listing"] = {"started": now(), "files": 0}
        prev_total = conn.execute("SELECT count(*) FROM files").fetchone()[0]
        try:
            batch = []
            def flush():
                nonlocal new, changed
                conn.execute("BEGIN IMMEDIATE")
                for it in batch:
                    r = conn.execute("SELECT id, size, mtime FROM files WHERE path=?", (it["path"],)).fetchone()
                    if r and r["size"] == it["size"] and r["mtime"] == it["mtime"]:
                        conn.execute("UPDATE files SET seen=?, fid=? WHERE id=?", (stamp, it["fid"], r["id"])); continue
                    kind, prio = X.kind_of(it["path"], it["size"])
                    if r:  # changed in place: read it again
                        changed += 1; D.drop_chunks(conn, r["id"])
                        conn.execute("UPDATE files SET fid=?, size=?, mtime=?, kind=?, prio=?, state=?, tries=0, error=NULL, note=?, ckey=NULL, seen=? WHERE id=?",
                                     (it["fid"], it["size"], it["mtime"], kind, prio, *initial(kind), stamp, r["id"]))
                    else:
                        new += 1
                        cur = conn.execute("INSERT INTO files(path, fid, size, mtime, ext, kind, prio, state, note, seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                           (it["path"], it["fid"], it["size"], it["mtime"], X.ext_of(it["path"]), kind, prio, *initial(kind), stamp))
                        D.index_name(conn, cur.lastrowid, it["path"])
                conn.execute("COMMIT"); batch.clear()
            for it in remote.list_files():
                batch.append(it); n += 1
                if len(batch) >= 500:
                    flush(); self.status["listing"]["files"] = n; self.wake.set()
            if batch: flush()
        except remote.AuthError as e:
            if conn.in_transaction: conn.execute("ROLLBACK")
            self.auth_failed(conn, e); self.status["listing"] = None
            return False
        except Exception as e:
            if conn.in_transaction: conn.execute("ROLLBACK")
            self.status["lastError"] = f"listing: {e}"[:500]; log(f"listing failed: {e}"); self.status["listing"] = None
            D.kv_set(conn, "list_error", str(e)[:500])
            return False
        # A listing far smaller than the index means something went wrong upstream: never mass-delete on it.
        if prev_total > 1000 and n < prev_total * 0.5:
            msg = f"listing returned {n} files but the index has {prev_total}; not removing anything"
            log(msg); D.kv_set(conn, "list_error", msg); self.status["listing"] = None
            return False
        moved = gone = 0
        conn.execute("BEGIN IMMEDIATE")
        for old in conn.execute("SELECT * FROM files WHERE seen IS NOT ? ", (stamp,)).fetchall():
            twin = conn.execute("SELECT id, state FROM files WHERE fid=? AND fid!='' AND seen=? AND id!=? AND size=? AND mtime=?",
                                (old["fid"], stamp, old["id"], old["size"], old["mtime"])).fetchone() if old["fid"] else None
            if twin and twin["state"] == "new" and old["state"] in ("done", "wait-ai"):
                # renamed or moved: carry the extracted text over instead of reading the file again
                conn.execute("UPDATE chunks SET file_id=? WHERE file_id=?", (twin["id"], old["id"]))
                conn.execute("UPDATE files SET state=?, note=?, ckey=?, extracted_at=?, cost=? WHERE id=?",
                             (old["state"], old["note"], old["ckey"], old["extracted_at"], old["cost"], twin["id"]))
                conn.execute("DELETE FROM names_fts WHERE rowid=?", (old["id"],)); conn.execute("DELETE FROM files WHERE id=?", (old["id"],))
                moved += 1
            else:
                D.drop_file(conn, old["id"]); gone += 1
        # names only: RAW photos that sit next to their own JPEG
        for r in conn.execute("SELECT id, path FROM files WHERE state='new' AND kind='raw'").fetchall():
            stem = r["path"].rsplit(".", 1)[0]
            sib = conn.execute("SELECT path FROM files WHERE path IN (?,?,?,?,?,?) LIMIT 1",
                               tuple(stem + "." + e for e in ("jpg", "JPG", "jpeg", "JPEG", "heic", "HEIC"))).fetchone()
            if sib: conn.execute("UPDATE files SET state='done', note=? WHERE id=?", ("RAW of " + sib[0].rsplit("/", 1)[-1] + " (read that one)", r["id"]))
        # failed files get another go after each listing
        conn.execute("UPDATE files SET state='new' WHERE state='error' AND tries < ?", (MAX_TRIES,))
        conn.execute("COMMIT")
        D.kv_set(conn, "last_list", json.dumps({"finished": now(), "seconds": round(time.time() - t0), "files": n, "new": new, "changed": changed, "moved": moved, "removed": gone}))
        D.kv_set(conn, "list_error", None)
        log(f"listing done: {n} files ({new} new, {changed} changed, {moved} moved, {gone} removed) in {time.time() - t0:.0f}s")
        self.status["listing"] = None; self.wake.set()
        return True

    def lister_loop(self):
        conn = self.conn()
        while not self.stop:
            last = json.loads(D.kv_get(conn, "last_list", "null") or "null")
            due = not last or (time.time() - datetime.strptime(last["finished"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()) > LIST_INTERVAL_H * 3600
            if due or self.relist_now.is_set():
                self.relist_now.clear()
                if self.status["auth"] == "expired": self.wait_auth(conn)
                if not self.relist(): self.relist_now.wait(1800); continue
            self.relist_now.wait(600)

    # ------------------------------------------------------------ worker
    def process(self, conn, f):
        f = dict(f); f["name"] = f["path"].rsplit("/", 1)[-1]
        shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK, exist_ok=True)
        ctx = Ctx(self, conn, f["id"])
        if f["kind"] in ("video", "audio"):
            f["ckey"] = f"m:{f['size']}:{f['mtime']}:{f['name'].lower()}"
            parts, note = X.ex_media(ctx, f, self.server.fresh_url(f["path"]), WORK)
        else:
            local = os.path.join(WORK, "file." + (f["ext"] or "bin"))
            cap = X.MAX_ARCHIVE_BYTES if f["kind"] == "archive" else X.MAX_TEXT_BYTES if f["kind"] == "text" else X.MAX_DOC_BYTES
            if f["size"] > cap:
                return [], f"not read: larger than {cap >> 20} MB", 0.0, None
            self.server.download(f["path"], local)
            f["ckey"] = "s:" + X.sha256_file(local)
            parts, note = X.LOCAL_KINDS[f["kind"]](ctx, f, local)
        return parts, note, ctx.cost, f["ckey"]

    def store(self, conn, f, parts, note, cost, ckey):
        name = f["path"].rsplit("/", 1)[-1]; total = 0
        conn.execute("BEGIN IMMEDIATE")
        D.drop_chunks(conn, f["id"])
        for part, src, text in parts:
            for c in chunk_text(text or ""):
                if total >= MAX_FILE_CHARS:
                    note = (note + "; " if note else "") + f"only the first {MAX_FILE_CHARS} characters indexed"; break
                total += len(c)
                cur = conn.execute("INSERT INTO chunks(file_id, part, src, text, hash) VALUES(?,?,?,?,?)", (f["id"], part or "", src, c, chunk_hash(name, c)))
                conn.execute("INSERT INTO chunks_fts(rowid, text) VALUES(?,?)", (cur.lastrowid, D.cjk_space(c)))
        conn.execute("UPDATE files SET state='done', error=NULL, note=?, ckey=?, extracted_at=?, cost=cost+? WHERE id=?", (note, ckey, now(), cost, f["id"]))
        conn.execute("COMMIT")

    def worker_loop(self):
        conn = self.conn()
        while not self.stop:
            if self.status["auth"] == "expired":
                self.wait_auth(conn); continue
            # out of OpenRouter credit: retry the waiting files every BILLING_RETRY_S; the notice clears only
            # once an AI call succeeds again, so each failed retry stays silent
            billing_wait = float(D.kv_get(conn, "billing_retry_at", 0) or 0) > time.time()
            if self.budget_left(conn) and not billing_wait and conn.execute("SELECT 1 FROM files WHERE state='wait-ai' LIMIT 1").fetchone():
                conn.execute("UPDATE files SET state='new' WHERE state='wait-ai'"); self.clear_notice(conn, "budget")
            f = conn.execute("SELECT * FROM files WHERE state='new' ORDER BY prio, mtime DESC LIMIT 1").fetchone()
            if not f:
                self.status["current"] = None; self.wake.wait(300); self.wake.clear(); continue
            # a file that took the whole process down (out of memory, a native crash) is picked again after the
            # restart: count the attempt BEFORE reading it, and give up on it after MAX_TRIES such attempts
            if (f["tries"] or 0) >= MAX_TRIES:
                conn.execute("UPDATE files SET state='error', error=? WHERE id=?", (f"not read: stopped the indexer {f['tries']} times (out of memory?)", f["id"]))
                log(f"gave up on {f['path']}: it stopped the indexer {f['tries']} times"); continue
            conn.execute("UPDATE files SET tries=tries+1 WHERE id=?", (f["id"],))
            self.status["current"] = {"path": f["path"], "kind": f["kind"], "size": f["size"], "since": now()}
            try:
                parts, note, cost, ckey = self.process(conn, f)
                self.store(conn, f, parts, note, cost, ckey)
            except X.NeedBudget:
                if conn.in_transaction: conn.execute("ROLLBACK")
                conn.execute("UPDATE files SET state='wait-ai', tries=max(tries-1, 0) WHERE id=?", (f["id"],))
                if AI_BUDGET_USD > 0 and not D.kv_get(conn, "notice:billing"):  # 0 = AI reading not switched on yet: nothing to report
                    spent = float(D.kv_get(conn, "ai_spent", 0) or 0)
                    self.notice(conn, "budget", f"iCloud index: the AI budget (USD {AI_BUDGET_USD:.2f}) is used up (USD {spent:.2f} spent). Images, scans, video frames and speech are waiting; names and text documents keep being indexed. Raising AI_BUDGET_USD in k8s/apps/icloud-index.yaml (DE0CH/jarvis2) resumes them.")
            except Exception as e:
                if conn.in_transaction: conn.execute("ROLLBACK")
                auth = isinstance(e, remote.AuthError)
                if not auth and f["kind"] not in ("text",):
                    try: remote.probe()
                    except remote.AuthError as ae: auth, e = True, ae
                    except Exception: pass
                if auth:
                    conn.execute("UPDATE files SET tries=max(tries-1, 0) WHERE id=?", (f["id"],))
                    self.auth_failed(conn, e); continue
                msg = f"{type(e).__name__}: {e}"[:500]
                log(f"failed {f['path']}: {msg}")
                if not isinstance(e, (ValueError, KeyError)): log(traceback.format_exc()[-800:])
                conn.execute("UPDATE files SET state='error', error=? WHERE id=?", (msg, f["id"]))  # the try was counted at pick
                self.status["lastError"] = f"{f['path']}: {msg}"
                if "rclone serve" in msg or "Connection refused" in msg: self.server.restart()
            finally:
                shutil.rmtree(WORK, ignore_errors=True)
            time.sleep(THROTTLE_S)

    # ------------------------------------------------------------ embedder
    def embed_loop(self):
        conn = self.conn()
        while not self.stop:
            rows = conn.execute("""SELECT c.hash, c.text, f.path FROM chunks c JOIN files f ON f.id=c.file_id
                                   WHERE NOT EXISTS (SELECT 1 FROM emb e WHERE e.hash=c.hash) GROUP BY c.hash LIMIT 64""").fetchall()
            if not rows:
                time.sleep(60); continue
            try:
                vecs, cost = ai.embed([r["path"].rsplit("/", 1)[-1] + "\n" + r["text"] for r in rows])
            except ai.Fatal as e:
                self.status["embedError"] = str(e)[:300]; log(f"embedding failed: {e}"); time.sleep(1800); continue
            except Exception as e:
                self.status["embedError"] = str(e)[:300]; time.sleep(120); continue
            self.status["embedError"] = None
            import numpy as np
            conn.execute("BEGIN IMMEDIATE")
            for r, v in zip(rows, vecs):
                conn.execute("INSERT OR REPLACE INTO emb(hash, vec) VALUES(?,?)", (r["hash"], np.asarray(v, dtype=np.float16).tobytes()))
            conn.execute("COMMIT")
            D.kv_add(conn, "embed_spent", cost)
            if self.searcher: self.searcher.dirty = True

    def start(self):
        def keep(fn):
            while not self.stop:  # a bug in one loop must not stop indexing for good
                try: fn()
                except Exception:
                    log(f"{fn.__name__} crashed, restarting in 60s:\n{traceback.format_exc()[-1500:]}")
                    self.status["lastError"] = f"{fn.__name__}: {traceback.format_exc().splitlines()[-1]}"[:500]
                    time.sleep(60)
        for fn in (self.lister_loop, self.worker_loop, self.embed_loop):
            threading.Thread(target=keep, args=(fn,), daemon=True, name=fn.__name__).start()
