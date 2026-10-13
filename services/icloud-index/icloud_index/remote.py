"""iCloud Drive through rclone's iclouddrive backend — the same saved session sessions use
(ICLOUD_RCLONE_CONF in the default store, see the icloud-drive skill).

  - the [icloud] section is mounted from the env-default Secret as a file (/secrets/icloud.conf);
    k8s refreshes that file when the store changes, so a re-login from any session reaches the pod
    without a restart. rclone rewrites cookies in its OWN copy on the PVC (RCLONE_CONFIG), which is
    re-seeded from the Secret whenever the Secret holds a different trust token (a new login).
  - listing: `rclone lsjson -R`, streamed line by line (one JSON object per line).
  - reading: one long-lived `rclone serve http` on localhost; files are fetched from it with HTTP,
    and ffmpeg reads videos from it with range requests, so a 22 GB video never touches the disk.

ICLOUD_REMOTE (default "icloud:") may be a local directory in tests.
"""
import json, os, re, shutil, subprocess, threading, time, urllib.error, urllib.parse, urllib.request

REMOTE = os.environ.get("ICLOUD_REMOTE", "icloud:")
CONF = os.environ.get("RCLONE_CONFIG", "/data/rclone.conf")
SECRET_FILE = os.environ.get("ICLOUD_CONF_FILE", "/secrets/icloud.conf")
SERVE_PORT = int(os.environ.get("RCLONE_SERVE_PORT", "8081"))
AUTH_ERR = re.compile(r"trust.?token|2fa|two-factor|authenticat|unauthori[sz]ed|\b401\b|\b421\b|session.*(expired|invalid)|requires? (re)?login|missing.*(password|apple)", re.I)


class AuthError(Exception):
    """The saved iCloud session no longer works: a person must log in again (icloud-drive skill)."""


def _token(text):
    m = re.search(r"^trust_token\s*=\s*(.+)$", text or "", re.M)
    return m.group(1).strip() if m else ""


def sync_conf():
    """Seed/refresh the PVC's rclone.conf from the Secret when the Secret carries a new login."""
    if not REMOTE.endswith(":"):
        return
    try:
        secret = open(SECRET_FILE).read()
    except OSError:
        secret = os.environ.get("ICLOUD_RCLONE_CONF", "")
    if not secret.strip():
        return
    try:
        mine = open(CONF).read()
    except OSError:
        mine = ""
    if _token(secret) and _token(secret) != _token(mine):
        os.makedirs(os.path.dirname(CONF) or ".", exist_ok=True)
        with open(CONF + ".tmp", "w") as f:
            f.write(secret.strip() + "\n")
        os.chmod(CONF + ".tmp", 0o600)
        os.replace(CONF + ".tmp", CONF)


def _env():
    return {**os.environ, "RCLONE_CONFIG": CONF}


def probe():
    """Raises AuthError when the session is dead, RuntimeError on other failures."""
    sync_conf()
    r = subprocess.run(["rclone", "lsf", "--max-depth", "1", "--dirs-only", REMOTE], capture_output=True, text=True, timeout=300, env=_env())
    if r.returncode != 0:
        msg = (r.stderr or r.stdout)[-400:]
        if AUTH_ERR.search(msg):
            raise AuthError(msg)
        raise RuntimeError(msg)


def list_files():
    """Yields {path, fid, size, mtime} for every file. Raises AuthError / RuntimeError on failure."""
    sync_conf()
    p = subprocess.Popen(["rclone", "lsjson", "-R", "--files-only", "--no-mimetype", REMOTE],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env())
    err = []
    t = threading.Thread(target=lambda: err.extend(p.stderr), daemon=True); t.start()
    for line in p.stdout:
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        o = json.loads(line)
        yield {"path": o["Path"], "fid": o.get("ID") or "", "size": o.get("Size") or 0, "mtime": o.get("ModTime") or ""}
    p.wait(); t.join(5); p.stdout.close(); p.stderr.close()
    if p.returncode != 0:
        msg = "".join(err)[-600:]
        if AUTH_ERR.search(msg):
            raise AuthError(msg)
        raise RuntimeError(f"rclone lsjson failed ({p.returncode}): {msg}")


class Server:
    """One `rclone serve http` subprocess, restarted when it dies."""

    def __init__(self):
        self.proc = None; self.lock = threading.Lock()

    def ensure(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return
            sync_conf()
            self.proc = subprocess.Popen(["rclone", "serve", "http", REMOTE, "--addr", f"127.0.0.1:{SERVE_PORT}", "--read-only",
                                          "--dir-cache-time", "5m", "--log-level", "ERROR"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=_env())
            for _ in range(60):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{SERVE_PORT}/", timeout=60).read(1)
                    return
                except Exception:
                    time.sleep(1)

    def restart(self):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try: self.proc.wait(10)
                except Exception: self.proc.kill()
            self.proc = None
        self.ensure()

    def url(self, path):
        self.ensure()
        return f"http://127.0.0.1:{SERVE_PORT}/" + urllib.parse.quote(path)

    def fresh_url(self, path):
        """The URL, after making sure serve's directory cache knows the file: a file added or changed
        after its folder was cached is a 404 until the cache expires, so on a 404 restart serve once."""
        u = self.url(path)
        try:
            urllib.request.urlopen(urllib.request.Request(u, method="HEAD"), timeout=300).close()
        except urllib.error.HTTPError as e:
            if e.code != 404: raise
            self.restart(); u = self.url(path)
        return u

    def download(self, path, dest, max_bytes=None):
        """Copies the file to dest; returns its size. Raises on failure (the caller probes for auth)."""
        with urllib.request.urlopen(self.fresh_url(path), timeout=600) as r, open(dest, "wb") as f:
            n = 0
            while True:
                b = r.read(1 << 20)
                if not b: break
                n += len(b); f.write(b)
                if max_bytes and n > max_bytes:
                    raise ValueError(f"larger than {max_bytes} bytes")
        return n

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


def have_rclone():
    return shutil.which("rclone") is not None
