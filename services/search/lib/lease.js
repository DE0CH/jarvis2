// Several search replicas share ONE SQLite file on the volume (k8s/apps/search.yaml: replicas, RollingUpdate). They
// all serve queries; exactly one, the WRITER, crawls, embeds and backs up. Who writes is a lease row in the database
// itself (kv 'writer' = {holder, until}), taken and renewed inside BEGIN IMMEDIATE, so the handover needs nothing
// but the file every replica already opens:
//   - a replica that is stopping (SIGTERM: a rollout, a drain) stops its index run at the next group and releases
//     the lease, so the next replica takes it within one tick;
//   - a replica that died (OOM kill, crash) stops renewing, and the lease lapses after TTL_MS.
// The writer bumps kv 'index_version' after every run that changed the index; readers reload their vectors when
// it moves. POST /reindex on a reader leaves kv 'reindex_at' for the writer.
// kv 'run:<pod>' keeps each replica's start, last heartbeat (with memory) and how it ended, so /status can say
// why the previous copy went away even when the kill left the process no time to say so.
const os = require("os");

const TTL_MS = 45000;

class Lease {
  constructor(db, { holder = os.hostname(), ttlMs = TTL_MS, now = Date.now } = {}) {
    this.db = db; this.holder = holder; this.ttlMs = ttlMs; this.now = now;
    this.get = db.prepare("SELECT v FROM kv WHERE k = ?");
    this.put = db.prepare("INSERT INTO kv(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v");
    this.del = db.prepare("DELETE FROM kv WHERE k = ?");
  }

  read(k) { const r = this.get.get(k); if (!r) return null; try { return JSON.parse(r.v); } catch { return r.v; } }
  write(k, v) { this.put.run(k, JSON.stringify(v)); }

  current() { return this.read("writer"); }

  // takes or renews the lease; true when this replica is the writer afterwards
  tryAcquire() {
    return this.db.transaction(() => {
      const cur = this.read("writer"), t = this.now();
      if (cur && cur.holder !== this.holder && cur.until > t) return false;
      this.write("writer", { holder: this.holder, since: cur && cur.holder === this.holder ? cur.since : new Date(t).toISOString(), until: t + this.ttlMs });
      return true;
    }).immediate();
  }

  release() {
    this.db.transaction(() => { const cur = this.read("writer"); if (cur && cur.holder === this.holder) this.del.run("writer"); }).immediate();
  }

  indexVersion() { return +(this.read("index_version") || 0); }
  bumpIndexVersion() { this.db.transaction(() => this.write("index_version", this.indexVersion() + 1)).immediate(); }

  requestReindex(full) { this.write("reindex_at", { at: new Date(this.now()).toISOString(), full: !!full }); }
  takeReindex() { return this.db.transaction(() => { const r = this.read("reindex_at"); if (r) this.del.run("reindex_at"); return r; }).immediate(); }

  // run records -------------------------------------------------------------------------------------------------
  runs() { return this.db.prepare("SELECT k, v FROM kv WHERE k LIKE 'run:%'").all().map((r) => { try { return JSON.parse(r.v); } catch { return null; } }).filter(Boolean); }
  runStarted(info) {
    // records older than a week, or of pods that ended cleanly a day ago, are dropped
    const t = this.now();
    for (const r of this.runs()) {
      const seen = Date.parse(r.lastSeen || r.started || 0);
      if (r.pod !== this.holder && (t - seen > 7 * 864e5 || (r.ended && t - seen > 864e5))) this.del.run(`run:${r.pod}`);
    }
    // the same pod again = k8s restarted this container: its previous run had no clean exit unless it recorded one
    const mine = this.read(`run:${this.holder}`);
    const restartedAfter = mine ? { started: mine.started, lastSeen: mine.lastSeen, ended: mine.ended || { how: "no clean exit: killed (OOM kill or crash)", lastMemory: mine.memory || null } } : null;
    this.write(`run:${this.holder}`, { pod: this.holder, ...info, lastSeen: info.started, restarts: mine ? (mine.restarts || 0) + 1 : 0, restartedAfter });
  }
  heartbeat(extra) { const r = this.read(`run:${this.holder}`) || { pod: this.holder }; this.write(`run:${this.holder}`, { ...r, ...extra, lastSeen: new Date(this.now()).toISOString() }); }
  runEnded(how) { this.heartbeat({ ended: { at: new Date(this.now()).toISOString(), how } }); }

  // the latest replica other than this one that is gone: ended cleanly (how) or went silent (no heartbeat for 2 min:
  // killed — an OOM kill, a crash, the node — with its last memory reading)
  previousRun() {
    const t = this.now();
    const gone = this.runs().filter((r) => r.pod !== this.holder && (r.ended || t - Date.parse(r.lastSeen) > 120000));
    gone.sort((a, b) => Date.parse((b.ended && b.ended.at) || b.lastSeen) - Date.parse((a.ended && a.ended.at) || a.lastSeen));
    const r = gone[0];
    if (!r) return null;
    return { pod: r.pod, started: r.started, lastSeen: r.lastSeen, ended: r.ended ? r.ended : { how: "no clean exit: killed (OOM kill, crash or node loss) — see the logs for the reason", lastMemory: r.memory || null } };
  }
}

module.exports = { Lease, TTL_MS };
