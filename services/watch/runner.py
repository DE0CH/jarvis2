"""Watch check runner (k8s/apps/watch.yaml): runs a session's watch check script (bash) and answers its exit code and
output. The router (router/watches.go) is its only caller and decides everything else: when a check is due, what an
exit means, the delivery into the session.

It holds nothing: no secrets, no service account, no volume, and its NetworkPolicy lets it reach only DNS and the public
internet (not the router, the core or anything else on the box). A check gets a clean environment (PATH, HOME and
TMPDIR = a throwaway directory, LANG, WATCH_NAME), a hard timeout, capped output, and its process group is killed
when it ends; while no check runs, every other process in the container is killed too, so nothing a check starts
outlives it for long.

  POST /run {"script": "...", "name": "x", "timeout": 90}  ->  {"exit": n, "stdout": "...", "stderr": "...", "timedOut": b, "ms": n}
  GET  /healthz
"""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_SCRIPT = 64 * 1024
MAX_TIMEOUT = 90
STDOUT_CAP = 16 * 1024
STDERR_CAP = 4 * 1024
PARALLEL = int(os.environ.get("WATCH_PARALLEL", "4"))

_slots = threading.BoundedSemaphore(PARALLEL)
_inflight = 0
_lock = threading.Lock()


def run_check(script, name, timeout):
    d = tempfile.mkdtemp(prefix="watch-")
    try:
        path = os.path.join(d, "check.sh")
        with open(path, "w") as f:
            f.write(script)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": d, "TMPDIR": d, "LANG": "C.UTF-8", "WATCH_NAME": name}
        t0 = time.monotonic()
        p = subprocess.Popen(["/bin/bash", path], cwd=d, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _killpg(p.pid)
            out, err = p.communicate()
        _killpg(p.pid)  # whatever it left running in its group
        code = 124 if timed_out else p.returncode
        if code is not None and code < 0:
            code = 128 - code
        return {"exit": code, "stdout": out[:STDOUT_CAP].decode("utf-8", "replace"), "stderr": err[-STDERR_CAP:].decode("utf-8", "replace"),
                "timedOut": timed_out, "ms": int((time.monotonic() - t0) * 1000)}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _killpg(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def reap_strays():
    """No check runs: every process but this one goes (a check that left its group with setsid)."""
    me = os.getpid()
    for e in os.listdir("/proc"):
        if e.isdigit() and int(e) not in (me, 1):
            try:
                os.kill(int(e), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        global _inflight
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_SCRIPT + 4096:
            return self._send(413, {"error": "too large"})
        try:
            b = json.loads(self.rfile.read(n) or b"{}")
            script, name = str(b.get("script") or ""), str(b.get("name") or "")[:40]
            timeout = max(1, min(MAX_TIMEOUT, int(b.get("timeout") or MAX_TIMEOUT)))
        except Exception:
            return self._send(400, {"error": "bad JSON"})
        if not script.strip() or len(script.encode()) > MAX_SCRIPT:
            return self._send(400, {"error": "script is empty or too long"})
        if not _slots.acquire(timeout=30):
            return self._send(503, {"error": "busy"})
        try:
            with _lock:
                _inflight += 1
            res = run_check(script, name, timeout)
        finally:
            with _lock:
                _inflight -= 1
                if _inflight == 0:
                    reap_strays()
            _slots.release()
        self._send(200, res)


def main():
    port = int(os.environ.get("PORT", "8095"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
