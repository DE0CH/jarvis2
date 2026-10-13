import os
import time
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
