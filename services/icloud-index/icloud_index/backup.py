"""The index's copy on the Storage Box (claude-records/.jarvis2-services/<name>.gz).

The index is expensive to rebuild (weeks of reading iCloud and the AI budget, whose ledger `ai_spent` lives in
it), so:
  seed(db_file)   before the database is opened: a missing database is restored from the copy. With
                  SEED_REQUIRED=1 (the default in k8s) a missing copy is an error, not a fresh start: a fresh
                  index would forget what the budget already paid for and spend it again.
  backup(db_file) SQLite's online backup -> gzip -> PUT <name>.gz.part -> MOVE <name>.gz; every
                  BACKUP_INTERVAL_H hours (backup_loop).
env: STORAGEBOX_HOST/USER/PASSWORD (STORAGEBOX_SCHEME for tests), SEED_NAME (default: the db file's name)."""
import base64, gzip, os, shutil, sqlite3, tempfile, threading, time, urllib.error, urllib.parse, urllib.request

DIR = "claude-records/.jarvis2-services"


class NoSeed(Exception):
    pass


def _dav(env):
    h, u, p = env.get("STORAGEBOX_HOST"), env.get("STORAGEBOX_USER"), env.get("STORAGEBOX_PASSWORD")
    if not (h and u and p):
        return None
    auth = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    base = f"{env.get('STORAGEBOX_SCHEME', 'https')}://{h}/"
    return auth, lambda path: base + urllib.parse.quote(path)


def seed(db_file, env=os.environ, log=print):
    if os.path.exists(db_file):
        return "exists"
    required = env.get("SEED_REQUIRED", "") in ("1", "true")
    d = _dav(env)
    if not d:
        if required: raise NoSeed("SEED_REQUIRED and no Storage Box credentials")
        return "none"
    auth, url = d
    name = env.get("SEED_NAME") or os.path.basename(db_file)
    try:
        r = urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz"), headers={"Authorization": auth}), timeout=3600)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            if required: raise NoSeed(f"SEED_REQUIRED and no {DIR}/{name}.gz on the Storage Box")
            return "none"
        raise
    tmp = db_file + ".seed"
    with r, gzip.GzipFile(fileobj=r) as g, open(tmp, "wb") as f:
        shutil.copyfileobj(g, f, 1 << 22)
    os.replace(tmp, db_file)
    log(f"seeded {db_file} from the Storage Box ({os.path.getsize(db_file)} bytes)")
    return "seeded"


def backup(db_file, env=os.environ, log=print):
    d = _dav(env)
    if not d:
        return False
    auth, url = d
    name = env.get("SEED_NAME") or os.path.basename(db_file)
    work = tempfile.mkdtemp(prefix="backup-")
    raw, gz = os.path.join(work, name), os.path.join(work, name + ".gz")
    try:
        src, dst = sqlite3.connect(db_file, timeout=120), sqlite3.connect(raw)
        src.backup(dst); src.close(); dst.close()
        with open(raw, "rb") as f, gzip.open(gz, "wb", compresslevel=3) as g:
            shutil.copyfileobj(f, g, 1 << 22)
        os.remove(raw)
        size = os.path.getsize(gz)
        with open(gz, "rb") as f:
            urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz.part"), method="PUT", data=f,
                                   headers={"Authorization": auth, "Content-Length": str(size)}), timeout=3600).read()
        urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz.part"), method="MOVE",
                               headers={"Authorization": auth, "Destination": url(f"{DIR}/{name}.gz"), "Overwrite": "T"}), timeout=600).read()
        log(f"backup: {name}.gz ({size} bytes) on the Storage Box")
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)


def backup_loop(db_file, env=os.environ, log=print):
    h = float(env.get("BACKUP_INTERVAL_H", "24") or 0)
    if h <= 0 or not _dav(env):
        return

    def run():
        time.sleep(600)
        while True:
            try: backup(db_file, env, log)
            except Exception as e: log(f"backup failed: {type(e).__name__}: {e}")
            time.sleep(h * 3600)
    threading.Thread(target=run, daemon=True, name="backup").start()
