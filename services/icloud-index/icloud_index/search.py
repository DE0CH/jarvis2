"""File search: names + content keywords + meaning, fused per FILE and reranked.

  names leg     names_fts over every file's name and folders — works for every file from the moment
                it is listed (videos, archives, anything)
  content leg   BM25 over the extracted text (documents, OCR of scans and photos, video frames, speech)
  semantic leg  the query's embedding against every chunk's (cross-language: "graduation" finds 畢業證書)
  fusion        reciprocal-rank fusion per file, then a cross-encoder rerank of the head

The query syntax is the transcript search's: "quoted" = must appear verbatim; loose words rank;
a CJK run is matched as a phrase (<= 2 chars) or by its overlapping bigrams.
"""
import json, os, re, threading, time, urllib.request

import numpy as np

from . import ai, db as D

LEG = 150
RERANK_HEAD = 40
RRF_K = 60
RERANK_MODEL = os.environ.get("RERANK_MODEL", "cohere/rerank-4-fast")
CJK_RUN = re.compile(r"[぀-ヿ㐀-䶿一-鿿豈-﫿가-힯]+")
STOP = set("a an and are as at be but by did do does for from had has have how i in is it its my of on or our so that the their them then there this to was we were what when where which who why will with you your file files find".split())


def parse_query(q):
    phrases = re.findall(r'"([^"]+)"', q or "")
    rest = re.sub(r'"[^"]+"', " ", q or "")
    words = [w for w in rest.split() if w]
    def fts(t):
        toks = re.findall(r"\w+", D.cjk_space(t).lower())
        toks = [x for x in toks if x != "_"]
        return '"' + " ".join(toks) + '"' if toks else None
    loose = []
    for w in words:
        last = 0
        for m in CJK_RUN.finditer(w):
            if m.start() > last: loose.append(w[last:m.start()])
            run = m.group(0)
            loose += [run] if len(run) <= 2 else [run[i:i + 2] for i in range(len(run) - 1)]
            last = m.end()
        if last < len(w): loose.append(w[last:])
    kw = [x for x in loose if x.lower() not in STOP] or loose
    hl = [t for t in phrases + words + kw if len(t) > 1 or CJK_RUN.search(t)]
    return {"phrases": [p for p in map(fts, phrases) if p], "words": list(dict.fromkeys(p for p in map(fts, kw) if p)), "highlight": list(dict.fromkeys(hl))}


def snippet(text, terms, width=300):
    low = text.lower(); pos = []
    for t in terms:
        i = low.find(t.lower()); n = 0
        while i != -1 and n < 50: pos.append(i); i = low.find(t.lower(), i + 1); n += 1
    if not pos: return text[:width] + ("…" if len(text) > width else "")
    pos.sort(); best, bn = pos[0], 0
    for i, p in enumerate(pos):
        n = sum(1 for q in pos[i:] if q < p + width * 0.8)
        if n > bn: bn, best = n, p
    s = max(0, best - width // 5); e = min(len(text), s + width)
    return ("…" if s else "") + text[s:e] + ("…" if e < len(text) else "")


def rerank(query, docs):
    j = ai.post("/rerank", {"model": RERANK_MODEL, "query": query, "documents": docs, "top_n": len(docs)}, tries=2, timeout=20)
    return [(r["index"], r["relevance_score"]) for r in j.get("results", [])]


class Searcher:
    def __init__(self, db_file):
        self.db = D.connect(db_file); self.lock = threading.Lock()
        self.hashes, self.matrix, self.dirty, self.loaded_at = [], np.zeros((0, ai.EMBED_DIMS), np.float16), True, 0
        self.index = {}  # hash -> row in matrix
        self.qcache = {}

    def load(self):
        """The vectors in memory (the iCloud index has ~750k: 750 MB as float16). Never fetchall() them (a list of
        750k blobs on top of the matrix took the pod past its memory limit on every start and every reload, the
        Jarvis 1 crash loop); the first load streams rows into a preallocated matrix, later loads append only the
        hashes not loaded yet, into spare capacity (an embedding that went away stays as an unmatched row until the
        next restart: harmless, the chunk join drops it)."""
        d = ai.EMBED_DIMS
        if not self.hashes:
            n = self.db.execute("SELECT count(*) FROM emb").fetchone()[0]
            m = np.zeros((int(n * 1.1) + 1024, d), np.float16); hs = []; idx = {}
            for r in self.db.execute("SELECT hash, vec FROM emb"):
                if len(hs) >= m.shape[0]: m = np.concatenate([m, np.zeros((len(hs) // 4 + 1024, d), np.float16)])
                v = np.frombuffer(r[1], np.float16)
                if v.shape[0] == d: m[len(hs)] = v
                idx[r[0]] = len(hs); hs.append(r[0])
            self.matrix, self.hashes, self.index = m, hs, idx
        else:
            new = [h for (h,) in self.db.execute("SELECT hash FROM emb") if h not in self.index]
            need = len(self.hashes) + len(new)
            if need > self.matrix.shape[0]:
                grown = np.zeros((int(need * 1.1) + 1024, d), np.float16); grown[:len(self.hashes)] = self.matrix[:len(self.hashes)]
                self.matrix = grown
            for i in range(0, len(new), 500):
                part = new[i:i + 500]
                for h, b in self.db.execute(f"SELECT hash, vec FROM emb WHERE hash IN ({','.join('?' * len(part))})", part):
                    v = np.frombuffer(b, np.float16)
                    if v.shape[0] == d: self.matrix[len(self.hashes)] = v
                    self.index[h] = len(self.hashes); self.hashes.append(h)
        self.dirty, self.loaded_at = False, time.time()

    def maybe_load(self):
        if self.dirty and time.time() - self.loaded_at > 60:
            with self.lock:
                if self.dirty: self.load()

    # ---- filters on the files table
    def filter_sql(self, o, alias="f"):
        w, p = [], []
        if o.get("kind"): ks = o["kind"].split(","); w.append(f"{alias}.kind IN ({','.join('?' * len(ks))})"); p += ks
        if o.get("ext"): es = [e.lower().lstrip(".") for e in o["ext"].split(",")]; w.append(f"{alias}.ext IN ({','.join('?' * len(es))})"); p += es
        if o.get("under"): w.append(f"{alias}.path LIKE ? ESCAPE '\\'"); p.append(o["under"].strip("/").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "/%")
        if o.get("after"): w.append(f"{alias}.mtime >= ?"); p.append(o["after"])
        if o.get("before"): w.append(f"{alias}.mtime <= ?"); p.append(o["before"] + "T99")
        return ("".join(" AND " + x for x in w), p)

    def _fts(self, table, rank, match, where, params, join):
        try:
            return [r[0] for r in self.db.execute(f"SELECT {join} FROM {table} {where[0]} WHERE {table} MATCH ?{where[1]} ORDER BY {rank} LIMIT {LEG}", (match, *params))]
        except Exception as e:
            print(f"fts failed ({match}): {e}", flush=True); return []

    def _leg(self, pq, run):
        must = " AND ".join(pq["phrases"])
        if not pq["words"]: return run(must) if must else []
        allw = run(" AND ".join(x for x in [must] + pq["words"] if x))
        if len(allw) >= LEG or len(pq["words"]) == 1: return allw
        anyw = run((f"({must}) AND ({' OR '.join(pq['words'])})") if must else " OR ".join(pq["words"]))
        return allw + [x for x in anyw if x not in set(allw)]

    def search(self, o):
        t0 = time.time(); q = o["q"]; pq = parse_query(q); fw, fp = self.filter_sql(o); notes = []
        mode = o.get("mode", "hybrid"); timing = {}
        names = self._leg(pq, lambda m: self._fts("names_fts", "bm25(names_fts, 4.0, 1.0)", m, ("JOIN files f ON f.id = names_fts.rowid", fw), fp, "f.id")) if mode != "semantic" else []
        if not names and mode != "semantic" and len(q) >= 2:  # a fragment of a name ("zjd", "IMG_28")
            names = [r[0] for r in self.db.execute(f"SELECT f.id FROM files f WHERE f.path LIKE ?{fw} ORDER BY length(f.path) LIMIT {LEG}", ("%" + q.strip('"') + "%", *fp))]
        content = []
        if mode != "semantic":
            cids = self._leg(pq, lambda m: self._fts("chunks_fts", "bm25(chunks_fts)", m, ("JOIN chunks c ON c.id = chunks_fts.rowid JOIN files f ON f.id = c.file_id", fw), fp, "c.id"))
            content = cids
        timing["keyword"] = round((time.time() - t0) * 1000)
        sem = []
        if mode != "keyword":
            self.maybe_load()
            if len(self.hashes):
                try:
                    t = time.time(); qv = self.qcache.get(q)
                    if qv is None:
                        qv = np.asarray(ai.embed([q], query=True)[0][0], np.float32); self.qcache[q] = qv
                        if len(self.qcache) > 200: self.qcache.pop(next(iter(self.qcache)))
                    timing["embed"] = round((time.time() - t) * 1000)
                    n = len(self.hashes); scores = np.concatenate([self.matrix[i:min(i + 50000, n)].astype(np.float32) @ qv for i in range(0, n, 50000)])
                    top = np.argsort(-scores)[:LEG * 3]
                    hs = [self.hashes[i] for i in top]; sc = {self.hashes[i]: float(scores[i]) for i in top}
                    rows = self.db.execute(f"SELECT c.id, c.hash FROM chunks c JOIN files f ON f.id=c.file_id WHERE c.hash IN ({','.join('?' * len(hs))}){fw}", (*hs, *fp)).fetchall() if hs else []
                    sem = [r[0] for r in sorted(rows, key=lambda r: -sc[r[1]])][:LEG]
                except Exception as e:
                    notes.append(f"semantic leg unavailable: {e}")
        # chunk ranks -> file ranks (a file's best chunk represents it)
        best_chunk, fused, via = {}, {}, {}
        def add_files(file_ids, leg):
            for r, fid in enumerate(file_ids):
                fused[fid] = fused.get(fid, 0) + 1 / (RRF_K + r + 1); via.setdefault(fid, []).append(leg)
        def chunk_files(cids):
            if not cids: return []
            m = dict(self.db.execute(f"SELECT id, file_id FROM chunks WHERE id IN ({','.join('?' * len(cids))})", cids).fetchall())
            out = []
            for c in cids:
                f = m.get(c)
                if f is None: continue
                best_chunk.setdefault(f, c)
                if f not in out: out.append(f)
            return out
        add_files(names, "name")
        add_files(chunk_files(content), "content")
        sem_files = chunk_files(sem)
        if pq["phrases"]:  # "quoted" is a hard filter: meaning alone can't satisfy it
            ok = set(names) | set(chunk_files(content)); sem_files = [f for f in sem_files if f in ok]
        add_files(sem_files, "semantic")
        ranked = sorted(fused, key=lambda f: -fused[f])
        total = len(ranked)
        head = ranked[:max(RERANK_HEAD, o.get("limit", 10))]
        rows = {r["id"]: r for r in self.db.execute(f"SELECT * FROM files WHERE id IN ({','.join('?' * len(head))})", head)} if head else {}
        chunks = {r["id"]: r for r in self.db.execute(f"SELECT * FROM chunks WHERE id IN ({','.join('?' * len(best_chunk))})", list(best_chunk.values()))} if best_chunk else {}
        scores = {f: fused[f] for f in head}; reranked = False
        if o.get("rerank", True) and mode != "keyword" and len(head) > 1:
            try:
                t = time.time(); part = head[:RERANK_HEAD]
                docs = [(rows[f]["path"] + "\n" + (chunks[best_chunk[f]]["text"] if f in best_chunk else ""))[:2000] for f in part]
                rr = rerank(q, docs); timing["rerank"] = round((time.time() - t) * 1000)
                scores = {part[i]: s for i, s in rr}; head = sorted(part, key=lambda f: -scores.get(f, -1)) + head[RERANK_HEAD:]; reranked = True
            except Exception as e:
                notes.append(f"rerank unavailable: {e}")
        hits = []
        for f in head[:o.get("limit", 10)]:
            r = rows[f]; c = chunks.get(best_chunk.get(f))
            hits.append({"path": r["path"], "size": r["size"], "mtime": r["mtime"], "kind": r["kind"], "state": r["state"], "note": r["note"],
                         "score": round(float(scores.get(f, 0)), 4), "via": via.get(f, []),
                         "part": c["part"] if c else None, "src": c["src"] if c else None,
                         "snippet": snippet(c["text"], pq["highlight"]) if c else None, "text": c["text"] if (c and o.get("full")) else None})
        return {"query": q, "mode": mode, "reranked": reranked, "total": total, "hits": hits, "notes": notes, "timing": timing, "tookMs": round((time.time() - t0) * 1000)}

    def file(self, path):
        r = self.db.execute("SELECT * FROM files WHERE path=?", (path,)).fetchone()
        if not r: return None
        cs = [dict(c) for c in self.db.execute("SELECT part, src, text FROM chunks WHERE file_id=? ORDER BY id", (r["id"],))]
        return {**{k: r[k] for k in r.keys() if k not in ("id", "seen")}, "chunks": cs}
