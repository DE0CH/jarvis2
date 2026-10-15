"""The writer lease and the replica handover (lease.py, server.py Replica): only the holder writes."""
import json, os, shutil, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from icloud_index import db as D, indexer as I, lease as L, server as SV  # noqa: E402


class Clock:
    def __init__(self): self.t = 1_800_000_000.0
    def __call__(self): return self.t


class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.db = os.path.join(self.tmp, "i.db"); D.connect(self.db).close()
        self.clock = Clock()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lease(self, name):
        return L.Lease(D.connect(self.db), holder=name, now=self.clock)

    def test_one_holder_release_and_lapse(self):
        a, b = self.lease("a"), self.lease("b")
        self.assertTrue(a.try_acquire()); self.assertFalse(b.try_acquire())
        self.clock.t += 30; self.assertTrue(a.try_acquire())  # renewal
        self.clock.t += 30; self.assertFalse(b.try_acquire())  # renewed: still a's
        a.release(); self.assertTrue(b.try_acquire()); self.assertFalse(a.try_acquire())
        self.assertFalse(a.held()); self.assertTrue(b.held())
        # b dies (no release): the lease lapses after the TTL
        self.clock.t += L.TTL_S - 1; self.assertFalse(a.try_acquire())
        self.clock.t += 2; self.assertTrue(a.try_acquire()); self.assertFalse(b.held())

    def test_release_by_non_holder_is_a_no_op(self):
        a, b = self.lease("a"), self.lease("b")
        a.try_acquire(); b.release()
        self.assertEqual(a.current()["holder"], "a")

    def test_previous_run(self):
        a, b = self.lease("a"), self.lease("b")
        a.run_started({"started": L.iso(self.clock.t)}); b.run_started({"started": L.iso(self.clock.t)})
        self.assertIsNone(b.previous_run())
        a.run_ended("SIGTERM (rollout, scale-down or drain)")
        self.assertEqual(b.previous_run()["pod"], "a")
        self.assertIn("SIGTERM", b.previous_run()["ended"]["how"])
        # a pod that went silent counts as killed
        self.clock.t += 10
        c = self.lease("c"); c.run_started({"started": L.iso(self.clock.t)}); self.clock.t += 600
        b.heartbeat(); self.assertEqual(b.previous_run()["pod"], "c")
        self.assertIn("no clean exit", b.previous_run()["ended"]["how"])


class FenceTest(unittest.TestCase):
    """An indexer whose replica isn't the writer never writes and never spends."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.db = os.path.join(self.tmp, "i.db")
        self.p = mock.patch.object(I, "WORK", os.path.join(self.tmp, "work")); self.p.start()
        self.idx = I.Indexer(self.db); self.conn = self.idx.conn()
        self.conn.execute("INSERT INTO files(path, size, mtime, ext, kind, state) VALUES('a/b.txt', 3, '2026-01-01T00:00:00Z', 'txt', 'text', 'new')")
        self.f = self.conn.execute("SELECT * FROM files").fetchone()
        self.idx.fence = lambda: False

    def tearDown(self):
        self.p.stop(); shutil.rmtree(self.tmp, ignore_errors=True)

    def snapshot(self):
        return ([tuple(r) for r in self.conn.execute("SELECT * FROM files")], self.conn.execute("SELECT count(*) FROM chunks").fetchone()[0],
                D.kv_get(self.conn, "ai_spent"))

    def test_store_listing_embedding_and_ai_refused(self):
        before = self.snapshot()
        with self.assertRaises(I.Stopped):
            self.idx.store(self.conn, self.f, [("", "text", "hello")], None, 0.0, "k")
        spent = []
        ctx = I.Ctx(self.idx, self.conn, self.f["id"])
        with mock.patch.object(I, "AI_BUDGET_USD", 10.0), self.assertRaises(I.Stopped):
            ctx.ai("k", "vision", lambda: spent.append(1) or ({"t": "x"}, 0.5))
        self.assertEqual(spent, [])  # the paid call never ran
        with mock.patch.object(I.remote, "list_files", return_value=iter([{"path": "n.txt", "fid": "1", "size": 1, "mtime": "2026-01-01T00:00:00Z"}])):
            with self.assertRaises(I.Stopped):
                self.idx.relist()
        self.conn.execute("INSERT INTO chunks(file_id, part, src, text, hash) VALUES(?, '', 'text', 'x', 'h1')", (self.f["id"],))
        with mock.patch.object(I.ai, "embed", side_effect=AssertionError("a non-writer embedded")):
            self.idx.stop = False
            with self.assertRaises(I.Stopped):
                self.idx.embed_loop()
        self.conn.execute("DELETE FROM chunks")
        self.assertEqual(self.snapshot(), before)

    def test_worker_stop_gives_the_try_back(self):
        calls = []
        def process(conn, f):
            calls.append(1); return [("", "text", "hi")], None, 0.0, "k"
        self.idx.process = process
        with self.assertRaises(I.Stopped):
            self.idx.fence = lambda: bool(calls) is False  # passes the pick, then the lease is gone before the store
            self.idx.worker_loop()
        self.assertEqual(self.conn.execute("SELECT tries, state FROM files").fetchone()[:], (0, "new"))
        self.assertEqual(self.conn.execute("SELECT count(*) FROM chunks").fetchone()[0], 0)


class ReplicaTest(unittest.TestCase):
    """Two replicas on one database: one writer; a clean stop hands the lease over; a reader never indexes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.db = os.path.join(self.tmp, "i.db"); D.connect(self.db).close()
        self.started = []
        self.p = [mock.patch.object(I.Indexer, "start", lambda idx: self.started.append(idx)),
                  mock.patch.object(I, "WORK", os.path.join(self.tmp, "work"))]
        for p in self.p: p.start()

    def tearDown(self):
        for p in self.p: p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def replica(self, name):
        return SV.Replica(self.db, tick_s=3600, drain_ms=0, holder=name)

    def test_handover(self):
        a = self.replica("a"); a.start()
        b = self.replica("b"); b.start()
        self.assertTrue(a.writer); self.assertFalse(b.writer)
        self.assertIsNotNone(a.idx); self.assertIsNone(b.idx)
        self.assertEqual(len(self.started), 1)  # only the writer runs an indexer
        self.assertTrue(a.fence()); self.assertFalse(b.fence())
        # a reader's /relist and /retry are requests the writer takes at its next tick
        b.lease.request("relist"); a.tick(); self.assertTrue(a.idx.relist_now.is_set())
        self.assertIsNone(b.lease.read("relist_at"))
        st = b.status(); self.assertEqual(st["replica"]["role"], "reader"); self.assertEqual(st["writer"]["holder"], "a")
        # a rollout stops a: lease released, its indexer stopped, nothing more written by it
        idx_a = a.idx
        a.shutdown()
        self.assertFalse(a.writer); self.assertTrue(idx_a.stop); self.assertFalse(a.fence())
        self.assertIsNone(b.lease.current())
        b.tick()
        self.assertTrue(b.writer); self.assertIsNotNone(b.idx); self.assertTrue(b.fence())
        st = b.status()
        self.assertEqual(st["replica"]["role"], "writer")
        self.assertEqual(st["previousReplica"]["pod"], "a"); self.assertIn("SIGTERM", st["previousReplica"]["ended"]["how"])
        # a's ticks after its stop change nothing
        a.tick(); self.assertFalse(a.writer); self.assertEqual(b.lease.current()["holder"], "b")

    def test_lost_lease_stops_the_indexer(self):
        a = self.replica("a"); a.start()
        b = self.replica("b"); b.start()
        # a stops renewing (frozen); its lease lapses and b takes it
        clock = Clock(); clock.t = 4_000_000_000.0
        b.lease.now = clock
        self.assertTrue(b.lease.try_acquire())  # far in the future: a's lease has lapsed
        a.lease.now = clock
        idx_a = a.idx
        a.tick()
        self.assertFalse(a.writer); self.assertTrue(idx_a.stop); self.assertIsNone(a.idx)

    def test_index_version_reloads_readers(self):
        a = self.replica("a"); a.start(); b = self.replica("b"); b.start()
        b.searcher.dirty = False
        a.changed(); b.tick()
        self.assertTrue(b.searcher.dirty)

    def test_ready_turns_off_on_shutdown(self):
        a = self.replica("a"); a.start()
        self.assertTrue(a.ready and not a.draining)
        a.shutdown()
        self.assertTrue(a.draining)


class SeedLockTest(unittest.TestCase):
    def test_second_seeder_finds_the_database(self):
        from icloud_index import backup
        tmp = tempfile.mkdtemp()
        try:
            db = os.path.join(tmp, "i.db")
            calls = []
            def fake(db_file, env, log):
                calls.append(1); open(db_file, "w").close(); return "seeded"
            with mock.patch.object(backup, "_seed", side_effect=fake):
                self.assertEqual(backup.seed(db, {}), "seeded")
                self.assertEqual(backup.seed(db, {}), "exists")
            self.assertEqual(calls, [1])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
