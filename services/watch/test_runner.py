import os
import time
import threading
import unittest

import runner


class RunnerTest(unittest.TestCase):
    def test_exit_and_output(self):
        r = runner.run_check("echo found it; echo oops >&2; exit 3", "x", 10)
        self.assertEqual(r["exit"], 3)
        self.assertEqual(r["stdout"], "found it\n")
        self.assertEqual(r["stderr"], "oops\n")
        self.assertFalse(r["timedOut"])

    def test_clean_env(self):
        os.environ["SOME_SECRET"] = "s3cret"
        r = runner.run_check('env; [ "$HOME" = "$PWD" ] && [ "$TMPDIR" = "$PWD" ] && echo home-ok', "named", 10)
        self.assertNotIn("SOME_SECRET", r["stdout"])
        self.assertIn("WATCH_NAME=named", r["stdout"])
        self.assertIn("home-ok", r["stdout"])

    def test_timeout_kills_the_group(self):
        t0 = time.monotonic()
        r = runner.run_check("sleep 30 & sleep 30", "x", 1)
        self.assertTrue(r["timedOut"])
        self.assertEqual(r["exit"], 124)
        self.assertLess(time.monotonic() - t0, 10)

    def test_output_capped(self):
        r = runner.run_check("head -c 100000 /dev/zero | tr '\\0' a", "x", 10)
        self.assertEqual(len(r["stdout"]), runner.STDOUT_CAP)

    def test_tmpdir_removed(self):
        r = runner.run_check("pwd", "x", 10)
        self.assertFalse(os.path.exists(r["stdout"].strip()))


if __name__ == "__main__":
    unittest.main()


class DrainTest(unittest.TestCase):
    def test_readyz_and_drain(self):
        import http.client
        srv = runner.ThreadingHTTPServer(("127.0.0.1", 0), runner.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]

        def get(path):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5); c.request("GET", path); r = c.getresponse(); r.read(); return r.status, r.getheader("Connection")
        self.assertEqual(get("/readyz")[0], 200)
        runner._draining.set()
        try:
            st, conn = get("/readyz")
            self.assertEqual(st, 503); self.assertEqual(conn, "close")
            self.assertEqual(get("/healthz")[0], 200)  # still alive while draining
            old = runner.DRAIN_S; runner.DRAIN_S = 0
            t = threading.Thread(target=runner.drain_and_stop, args=(srv,)); t.start(); t.join(5)
            runner.DRAIN_S = old
            self.assertFalse(t.is_alive())
        finally:
            runner._draining.clear()
