"""Offline tests: a local folder stands in for iCloud (rclone treats it the same), the AI and the
embeddings are faked. Run: cd services/icloud-index && python3 -m unittest discover -s tests -v
(needs rclone, ffmpeg and the Python deps of requirements.txt; the image build runs it)."""
import os, shutil, subprocess, sys, tempfile, unittest, zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from icloud_index import ai, db as D, extract as X, indexer as I, remote, search as S  # noqa: E402

CALLS = []


def fake_image(jpg, hint):
    CALLS.append(("image", hint))
    return {"text": "漢基國際學校 中學畢業證書", "description": "Scan of a high school diploma", "keywords_zh": "畢業證書"}, 0.001


def fake_embed(texts, query=False):
    import hashlib
    out = []
    for t in texts:  # a bag-of-characters vector: similar texts land close, enough for ranking tests
        v = [0.0] * ai.EMBED_DIMS
        for ch in t.lower():
            v[int(hashlib.md5(ch.encode()).hexdigest(), 16) % ai.EMBED_DIMS] += 1
        n = sum(x * x for x in v) ** 0.5 or 1
        out.append([x / n for x in v])
    return out, 0.0


class IndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.root = os.path.join(self.tmp, "drive"); os.makedirs(self.root + "/Documents/证件")
        from PIL import Image
        Image.new("RGB", (400, 300), "white").save(self.root + "/Documents/证件/diploma.jpg")
        with zipfile.ZipFile(self.root + "/Documents/lease.docx", "w") as z:
            z.writestr("word/document.xml", "<w:p><w:t>Tenancy agreement, Walton Street</w:t></w:p>")
        open(self.root + "/Documents/notes.txt", "w").write("深圳湾口岸通关时间\n")
        open(self.root + "/Documents/app.exe", "wb").write(b"MZ")
        self.db = os.path.join(self.tmp, "i.db")
        import socket; sk = socket.socket(); sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]; sk.close()
        self.patches = [mock.patch.object(remote, "REMOTE", self.root), mock.patch.object(remote, "SERVE_PORT", port), mock.patch.object(I, "WORK", os.path.join(self.tmp, "work")),
                        mock.patch.object(I, "AI_BUDGET_USD", 1.0), mock.patch.object(ai, "read_image", fake_image), mock.patch.object(ai, "embed", fake_embed),
                        mock.patch.object(I, "THROTTLE_S", 0), mock.patch.object(S, "rerank", side_effect=RuntimeError("no rerank offline"))]
        for p in self.patches: p.start()
        CALLS.clear()
        self.idx = I.Indexer(self.db); self.conn = self.idx.conn()

    def tearDown(self):
        self.idx.server.stop()
        for p in self.patches: p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def drain(self):
        while True:
            f = self.conn.execute("SELECT * FROM files WHERE state='new' ORDER BY prio LIMIT 1").fetchone()
            if not f: break
            parts, note, cost, ckey = self.idx.process(self.conn, f); self.idx.store(self.conn, f, parts, note, cost, ckey)
        rows = self.conn.execute("SELECT c.hash, c.text, f.path FROM chunks c JOIN files f ON f.id=c.file_id").fetchall()
        import numpy as np
        for r in rows:
            v, _ = ai.embed([r["text"]]); self.conn.execute("INSERT OR REPLACE INTO emb VALUES(?,?)", (r["hash"], np.asarray(v[0], np.float16).tobytes()))

    def search(self, q, **k):
        s = S.Searcher(self.db); s.dirty = True; s.loaded_at = 0
        return [h["path"] for h in s.search({"q": q, "limit": 5, **k})["hits"]]

    def test_index_search_and_changes(self):
        self.assertTrue(self.idx.relist()); self.drain()
        st = dict(self.conn.execute("SELECT path, state FROM files").fetchall())
        self.assertEqual(st["Documents/app.exe"], "done")  # name only
        self.assertEqual(len(CALLS), 1)
        self.assertEqual(self.search("畢業證書")[0], "Documents/证件/diploma.jpg")
        self.assertEqual(self.search("walton street")[0], "Documents/lease.docx")
        self.assertEqual(self.search("口岸")[0], "Documents/notes.txt")
        self.assertIn("Documents/app.exe", self.search("app.exe", mode="keyword"))
        self.assertEqual(self.search("证件", mode="keyword")[0], "Documents/证件/diploma.jpg")  # folder name
        self.assertEqual(self.search("walton", under="Documents/证件", mode="keyword"), [])
        # a duplicate of an image costs nothing (content cache)
        shutil.copy(self.root + "/Documents/证件/diploma.jpg", self.root + "/Documents/copy.jpg")
        self.assertTrue(self.idx.relist()); self.drain()
        self.assertEqual(len(CALLS), 1)
        # edited -> re-read; deleted -> gone
        open(self.root + "/Documents/notes.txt", "w").write("罗湖口岸\n")
        os.remove(self.root + "/Documents/lease.docx")
        self.assertTrue(self.idx.relist()); self.drain()
        self.assertEqual(self.search("罗湖", mode="keyword"), ["Documents/notes.txt"])
        self.assertEqual(self.search("walton", mode="keyword"), [])

    def test_rename_keeps_text_without_rereading(self):
        items = [{"path": "A/x.jpg", "fid": "FILE::1", "size": 10, "mtime": "2020-01-01T00:00:00Z"}]
        with mock.patch.object(remote, "list_files", lambda: iter(items)):
            self.idx.relist()
        fid = self.conn.execute("SELECT id FROM files").fetchone()[0]
        self.idx.store(self.conn, {"id": fid, "path": "A/x.jpg"}, [("", "vision", "a red bicycle")], None, 0.001, "s:abc")
        items[0] = dict(items[0], path="B/renamed.jpg")
        with mock.patch.object(remote, "list_files", lambda: iter(items)):
            self.idx.relist()
        rows = self.conn.execute("SELECT path, state FROM files").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("B/renamed.jpg", "done")])
        self.assertEqual(self.search("bicycle", mode="keyword"), ["B/renamed.jpg"])

    def test_partial_listing_never_mass_deletes(self):
        many = [{"path": f"f{i}.txt", "fid": f"F{i}", "size": 1, "mtime": "2020"} for i in range(1200)]
        with mock.patch.object(remote, "list_files", lambda: iter(many)):
            self.idx.relist()
        with mock.patch.object(remote, "list_files", lambda: iter(many[:10])):
            self.assertFalse(self.idx.relist())
        self.assertEqual(self.conn.execute("SELECT count(*) FROM files").fetchone()[0], 1200)

    def test_budget_exhausted_waits(self):
        with mock.patch.object(I, "AI_BUDGET_USD", 0.0), mock.patch("icloud_index.notify.dm") as dm:
            self.idx.relist()
            f = self.conn.execute("SELECT * FROM files WHERE kind='image'").fetchone()
            with self.assertRaises(X.NeedBudget):
                self.idx.process(self.conn, f)

    def test_out_of_credit_notifies_once(self):
        def broke(jpg, hint): raise ai.Fatal("402", billing=True)
        for i in range(3):
            shutil.copy(self.root + "/Documents/证件/diploma.jpg", self.root + f"/Documents/scan{i}.png")
            open(self.root + f"/Documents/scan{i}.png", "ab").write(bytes([i]))  # distinct content, no cache hits
        with mock.patch.object(ai, "read_image", broke), mock.patch("icloud_index.notify.dm") as dm:
            self.idx.relist()
            import threading, time
            t = threading.Thread(target=self.idx.worker_loop, daemon=True); t.start()
            for _ in range(300):  # rclone serve's first start can take seconds
                if dm.call_count and self.conn.execute("SELECT 1 FROM files WHERE state='new' AND kind='image'").fetchone() is None: break
                time.sleep(0.1)
            self.idx.stop = True; self.idx.wake.set(); t.join(10)
            self.assertEqual(dm.call_count, 1)
            self.assertGreater(self.conn.execute("SELECT count(*) FROM files WHERE state='wait-ai'").fetchone()[0], 0)
            # credit back: the next retry reads them and clears the notice
            D.kv_set(self.conn, "billing_retry_at", 0)
        self.idx.stop = False
        t = threading.Thread(target=self.idx.worker_loop, daemon=True); t.start()
        for _ in range(300):
            if self.conn.execute("SELECT count(*) FROM files WHERE state='wait-ai'").fetchone()[0] == 0: break
            time.sleep(0.1)
        self.idx.stop = True; self.idx.wake.set(); t.join(10)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM files WHERE state='wait-ai'").fetchone()[0], 0)
        self.assertIsNone(D.kv_get(self.conn, "notice:billing"))

    def test_a_file_that_kills_the_process_is_given_up_after_max_tries(self):
        self.idx.relist()
        doc = self.conn.execute("SELECT id FROM files WHERE path='Documents/lease.docx'").fetchone()[0]
        self.conn.execute("UPDATE files SET state='done' WHERE id<>?", (doc,))
        import threading, time
        def die(conn, f): raise SystemExit("simulated out-of-memory kill")  # the process dies mid-read
        for _ in range(I.MAX_TRIES):
            with mock.patch.object(self.idx, "process", die):
                t = threading.Thread(target=lambda: self.assertRaises(SystemExit, self.idx.worker_loop), daemon=True); t.start(); t.join(10)
        self.assertEqual(self.conn.execute("SELECT state, tries FROM files WHERE id=?", (doc,)).fetchone()[:], ("new", I.MAX_TRIES))
        t = threading.Thread(target=self.idx.worker_loop, daemon=True); t.start()
        time.sleep(2); self.idx.stop = True; self.idx.wake.set(); t.join(10)
        state, err = self.conn.execute("SELECT state, error FROM files WHERE id=?", (doc,)).fetchone()
        self.assertEqual(state, "error"); self.assertIn("stopped the indexer", err)

    def test_huge_images_are_refused_or_decoded_small(self):
        from PIL import Image
        Image.new("RGB", (3000, 2000), "white").save(self.tmp + "/big.png"); Image.new("RGB", (3000, 2000), "white").save(self.tmp + "/big.jpg")
        with mock.patch.object(X, "MAX_IMAGE_PIXELS", 2_000_000), mock.patch.object(X, "IMG_MAX_SIDE", 400):
            with self.assertRaises(ValueError): X.open_image(self.tmp + "/big.png")
            self.assertLess(X.open_image(self.tmp + "/big.jpg").width, 3000)

    def test_seed_and_backup_through_the_storage_box(self):
        from icloud_index import backup as B
        import http.server, threading
        files = {}
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def p(self): return urllib.parse.unquote(self.path[1:])
            def do_GET(self):
                b = files.get(self.p())
                self.send_response(200 if b is not None else 404); self.end_headers(); self.wfile.write(b or b"")
            def do_PUT(self):
                files[self.p()] = self.rfile.read(int(self.headers["Content-Length"])); self.send_response(201); self.end_headers()
            def do_DELETE(self):
                self.send_response(204 if files.pop(self.p(), None) is not None else 404); self.end_headers()
            def do_MOVE(self):
                files[urllib.parse.unquote(urllib.parse.urlparse(self.headers["Destination"]).path[1:])] = files.pop(self.p()); self.send_response(201); self.end_headers()
        import urllib.parse
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        env = {"STORAGEBOX_HOST": f"127.0.0.1:{srv.server_address[1]}", "STORAGEBOX_USER": "u", "STORAGEBOX_PASSWORD": "p", "STORAGEBOX_SCHEME": "http", "SEED_NAME": "index.db"}
        quiet = lambda *a: None
        import gzip, subprocess
        kp = subprocess.run(["age-keygen"], capture_output=True, text=True).stdout
        pub = [l.split(": ")[1] for l in kp.splitlines() if l.startswith("# public key")][0]
        env.update(BACKUP_AGE_RECIPIENT=pub, BACKUP_AGE_KEY=kp)
        try:
            fresh = self.tmp + "/fresh.db"
            with self.assertRaises(B.NoSeed): B.seed(fresh, {**env, "SEED_REQUIRED": "1"}, quiet)
            self.assertEqual(B.seed(fresh, env, quiet), "none")
            # the one-time plain import copy: read only with SEED_PLAIN_OK
            files[f"{B.DIR}/index.db.gz"] = gzip.compress(open(self.db, "rb").read())
            self.assertEqual(B.seed(fresh, env, quiet), "none")
            self.assertEqual(B.seed(fresh, {**env, "SEED_PLAIN_OK": "1"}, quiet), "seeded"); os.remove(fresh)
            D.kv_add(self.conn, "ai_spent", 12.5)
            self.assertTrue(B.backup(self.db, env, quiet))
            self.assertNotIn(f"{B.DIR}/index.db.gz", files)  # the plain copy is gone
            self.assertTrue(files[f"{B.DIR}/index.db.gz.age"].startswith(b"age-encryption.org/v1"))
            with self.assertRaises(B.NoSeed): B.seed(fresh, {**env, "BACKUP_AGE_KEY": ""}, quiet)
            self.assertEqual(B.seed(fresh, {**env, "SEED_REQUIRED": "1"}, quiet), "seeded")
            self.assertEqual(float(D.kv_get(D.connect(fresh), "ai_spent")), 12.5)  # the budget ledger travels with it
            self.assertEqual(B.seed(fresh, env, quiet), "exists")
        finally:
            srv.shutdown()

    def test_cjk_query_parsing(self):
        pq = S.parse_query('深圳湾口岸 "Walton Street" ferry')
        self.assertIn('"深 圳"', pq["words"]); self.assertIn('"walton street"', pq["phrases"]); self.assertIn('"ferry"', pq["words"])

    def test_kinds(self):
        self.assertEqual(X.kind_of("Documents/a.PDF", 10)[0], "pdf")
        self.assertEqual(X.kind_of("Backup/x/.anaconda/lib/a.py", 10), ("other", 9))
        self.assertEqual(X.kind_of("Videos/a.MOV", 10)[0], "video")


if __name__ == "__main__":
    unittest.main()
