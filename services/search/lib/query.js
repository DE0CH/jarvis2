// Hybrid retrieval: BM25 (FTS5) + dense vectors, fused with reciprocal-rank fusion, then a
// cross-encoder rerank of the fused head.
//   keyword leg   precise on names, commands, error strings, ids — and on 中文 substrings
//   semantic leg  paraphrases and cross-language ("train ticket" finds 火车票)
//   rerank        reads query + passage together; fixes the ordering either leg gets wrong
// Vectors live in memory as ONE Int8Array (rows × dims) with a per-row scale: 1 byte per dimension, so ~50k chunks ×
// 1024 dims is 51 MB instead of 205 MB as Float32. The Float32 load (every row's blob in one array, then a copy each)
// reached 761 MB RSS on its first reload at 50k chunks — the limit was 768Mi — and blocked the event loop for tens of
// seconds, failing readiness (2026-10-15). Now the load pages through the rows, yielding between pages (234 MB peak in
// the same test). The int8 scan only picks candidates: the best LEG × OVERSAMPLE are rescored with their exact float
// vectors read from SQLite, so the semantic leg's ranking and scores are exact. A full scan costs about what the
// Float32 one did, so there is still no ANN index to maintain.
const { cjkSpace } = require("./db");
const { embedQuery, rerank, blobToVec, EMBED_MODEL, EMBED_DIMS } = require("./embed");

const LEG = 120;         // candidates per leg
const OVERSAMPLE = 4;    // int8 candidates per exact slot
const RERANK_HEAD = 40;  // fused candidates handed to the reranker
const RRF_K = 60;
const TOOL_PRIOR = 0.97;
const NEAR_DUP = 0.93;   // cosine above which two hits say the same thing (a file written, then read back; a record and the heredoc that wrote it)
const CJK_RUN = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]+/gu;
// not worth marking in a snippet (they still count for ranking, where BM25 discounts them anyway)
const STOP = new Set("a an and are as at be but by did do does for from had has have how i in is it its my of on or our so that the their them then there this to was we were what when where which who why will with you your".split(" "));
const HAS_CJK = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;

// "quoted phrases" must match; loose words rank. Every term becomes an FTS5 phrase of its
// alphanumeric sub-tokens (LOBSTER_TOKEN -> "lobster token", 车票 -> "车 票"), which also keeps
// user input out of FTS5's query syntax.
function parseQuery(q) {
  const phrases = [], words = [];
  const rest = String(q || "").replace(/"([^"]+)"/g, (_, p) => { phrases.push(p); return " "; });
  for (const w of rest.split(/\s+/)) if (w) words.push(w);
  const toFts = (t) => { const toks = cjkSpace(t).toLowerCase().match(/[\p{L}\p{N}]+/gu); return toks ? `"${toks.join(" ")}"` : null; };
  // 中文 is typed without spaces, so one "word" may be a whole sentence (火车票余票查询接口): as a
  // single phrase it would only match verbatim. Loose CJK runs longer than 2 characters are
  // searched as their overlapping bigrams (火车 车票 票余 …) — the classic CJK retrieval unit;
  // BM25 then ranks passages by how many of them they contain. A quoted run stays exact.
  const loose = [];
  for (const w of words) {
    let last = 0;
    for (const m of w.matchAll(CJK_RUN)) {
      if (m.index > last) loose.push(w.slice(last, m.index));
      const run = m[0];
      if (run.length <= 2) loose.push(run); else for (let i = 0; i + 2 <= run.length; i++) loose.push(run.slice(i, i + 2));
      last = m.index + run.length;
    }
    if (last < w.length) loose.push(w.slice(last));
  }
  const highlight = [...phrases, ...words.filter((w) => !STOP.has(w.toLowerCase())), ...loose.filter((w) => !STOP.has(w.toLowerCase()))].filter((t) => t.length > 1 || HAS_CJK.test(t));
  return { phrases: phrases.map(toFts).filter(Boolean), words: [...new Set(loose.map(toFts).filter(Boolean))], highlight: [...new Set(highlight)] };
}

class Searcher {
  constructor(db, log = console.log) {
    this.qcache = new Map(); // query text -> vector (the same query is re-run on every filter change)
    this.db = db; this.log = log; this.ids = []; this.rowOf = new Map(); this.q8 = new Int8Array(0); this.scale = new Float32Array(0);
    this.q = {
      byIds: (n) => db.prepare(`SELECT c.id, c.sid, c.dir, c.title, c.source, c.kind, c.date, c.ts, c.file, c.line_from lineFrom, c.line_to lineTo, c.text FROM chunks c WHERE c.id IN (${Array(n).fill("?").join(",")})`),
      session: db.prepare("SELECT sid, title, dir, source, machine_id machineId, date, first_ts firstTs, last_ts lastTs, model FROM sessions WHERE sid = ?"),
      chunk: db.prepare("SELECT id, sid, file, dir, title, kind, ts, line_from lineFrom, line_to lineTo, text FROM chunks WHERE id = ?"),
      vecsByIds: (n) => db.prepare(`SELECT c.id, e.vec FROM chunks c JOIN emb e ON e.hash = c.hash AND e.model = ? WHERE c.id IN (${Array(n).fill("?").join(",")})`),
    };
    this.loading = null; this.reloadAgain = false; // load() is async: the caller awaits the first one
  }

  // reads the vectors page by page (PAGE rows, yielding to the event loop between pages, so a reload never stalls
  // the requests this replica is serving) into a fresh int8 matrix, then swaps it in; one load at a time (a request
  // for another during a load runs once more after it)
  load() {
    if (this.loading) { this.reloadAgain = true; return this.loading; }
    this.loading = this._load().finally(() => { this.loading = null; if (this.reloadAgain) { this.reloadAgain = false; this.load(); } });
    return this.loading;
  }

  async _load() {
    const t0 = Date.now(), d = EMBED_DIMS, PAGE = 2000;
    const n = this.db.prepare("SELECT count(*) n FROM chunks c JOIN emb e ON e.hash = c.hash AND e.model = ?").get(EMBED_MODEL).n;
    const q8 = new Int8Array(n * d), scale = new Float32Array(n), ids = new Array(n), rowOf = new Map();
    const page = this.db.prepare("SELECT c.id, e.vec FROM chunks c JOIN emb e ON e.hash = c.hash AND e.model = ? WHERE c.id > ? ORDER BY c.id LIMIT ?");
    let i = 0, last = -1;
    while (i < n) {
      const rows = page.all(EMBED_MODEL, last, Math.min(PAGE, n - i));
      if (!rows.length) break;
      for (const r of rows) {
        const v = blobToVec(r.vec);
        if (v.length === d) scale[i] = quantize(v, q8, i * d);
        ids[i] = r.id; rowOf.set(r.id, i); i++; last = r.id;
      }
      await new Promise((res) => setImmediate(res));
    }
    // rows deleted during the load leave the tail short; rows added wait for the next load
    this.q8 = i === n ? q8 : q8.subarray(0, i * d); this.scale = i === n ? scale : scale.subarray(0, i); this.ids = i === n ? ids : ids.slice(0, i); this.rowOf = rowOf;
    this.log(`vectors loaded: ${i} in ${Date.now() - t0} ms (${Math.round(this.q8.byteLength / 1048576)} MB int8)`);
  }

  // id -> exact Float32Array, read from SQLite (into `into`, skipping what it already has)
  exactVecs(ids, into = new Map()) {
    const need = [...new Set(ids)].filter((id) => !into.has(id));
    for (let k = 0; k < need.length; k += 500) {
      const part = need.slice(k, k + 500);
      for (const r of this.q.vecsByIds(part.length).all(EMBED_MODEL, ...part)) into.set(r.id, blobToVec(r.vec));
    }
    return into;
  }

  // SQL filter shared by both legs -> { where, params }
  //   states    the session's CURRENT state (live / paused / archive — the group's freshest copy, what
  //             a hit reports as `state`), so a running session is found by all of its conversation,
  //             including the part first indexed from its pause snapshot or the archive it was restored from
  //   archived  only text read from an archive dir (a destroyed session's copy, whatever it is doing now)
  filter({ kinds, after, before, session, states, archived }) {
    const w = [], p = [];
    if (kinds && kinds.length) { w.push(`c.kind IN (${kinds.map(() => "?").join(",")})`); p.push(...kinds); }
    if (after) { w.push("c.date >= ?"); p.push(after); }
    if (before) { w.push("c.date <= ?"); p.push(before); }
    if (states && states.length) { w.push(`COALESCE((SELECT s.source FROM sessions s WHERE s.sid = c.sid), c.source) IN (${states.map(() => "?").join(",")})`); p.push(...states); }
    if (archived) w.push("c.dir IS NOT NULL");
    if (session) { w.push("(c.sid = ? OR c.dir LIKE ? OR c.title LIKE ?)"); p.push(session, `%${session}%`, `%${session}%`); }
    return { where: w.length ? " AND " + w.join(" AND ") : "", params: p };
  }

  keywordLeg(pq, f) {
    const run = (match) => {
      try { return this.db.prepare(`SELECT c.id FROM chunks_fts JOIN chunks c ON c.id = chunks_fts.rowid WHERE chunks_fts MATCH ?${f.where} ORDER BY bm25(chunks_fts, 1.0, 3.0) LIMIT ${LEG}`).all(match, ...f.params).map((r) => r.id); }
      catch (e) { this.log(`fts query failed (${match}): ${e.message}`); return []; }
    };
    const must = pq.phrases.join(" AND ");
    if (!pq.words.length) return must ? run(must) : [];
    // all words first (precise), then any word (recall) for what is left of the leg
    const all = run([must, ...pq.words].filter(Boolean).join(" AND "));
    if (all.length >= LEG || pq.words.length === 1) return all;
    const any = run(must ? `(${must}) AND (${pq.words.join(" OR ")})` : pq.words.join(" OR "));
    const seen = new Set(all);
    return all.concat(any.filter((id) => !seen.has(id))).slice(0, LEG);
  }

  // -> [{id, score}] best first, exact cosine scores; `vecs` collects the exact vectors read (dedupe reuses them)
  semanticLeg(qvec, f, hasFilter, vecs = new Map()) {
    const n = this.ids.length, d = EMBED_DIMS, m = this.q8, scale = this.scale, approx = new Float32Array(n);
    for (let i = 0, o = 0; i < n; i++, o += d) { let s = 0; for (let j = 0; j < d; j++) s += m[o + j] * qvec[j]; approx[i] = s * scale[i]; }
    let allowed = null;
    if (hasFilter) allowed = new Set(this.db.prepare(`SELECT c.id FROM chunks c WHERE 1=1${f.where}`).all(...f.params).map((r) => r.id));
    const idx = [];
    for (let i = 0; i < n; i++) if (!allowed || allowed.has(this.ids[i])) idx.push(i);
    idx.sort((a, b) => approx[b] - approx[a]);
    const cand = idx.slice(0, LEG * OVERSAMPLE).map((i) => this.ids[i]);
    this.exactVecs(cand, vecs);
    return cand.filter((id) => vecs.has(id)).map((id) => ({ id, score: dot(vecs.get(id), qvec) })).sort((a, b) => b.score - a.score).slice(0, LEG);
  }

  async search(opts) {
    const t0 = Date.now();
    const { q, limit = 10, mode = "hybrid", rerank: wantRerank = true, group = false } = opts;
    const pq = parseQuery(q), f = this.filter(opts), hasFilter = !!f.where;
    const timing = {}, notes = [];
    const kw = mode === "semantic" ? [] : this.keywordLeg(pq, f);
    timing.keyword = Date.now() - t0;
    let sem = []; const vecs = new Map();
    if (mode !== "keyword" && this.ids.length) {
      try { const t = Date.now(); let qv = this.qcache.get(q); if (!qv) { qv = await embedQuery(q); this.qcache.set(q, qv); if (this.qcache.size > 200) this.qcache.delete(this.qcache.keys().next().value); } timing.embed = Date.now() - t; sem = this.semanticLeg(qv, f, hasFilter, vecs); }
      catch (e) { notes.push(`semantic leg unavailable: ${e.message}`); }
    }
    // reciprocal-rank fusion; with "must" phrases the keyword leg is a hard filter
    const fused = new Map();
    kw.forEach((id, r) => fused.set(id, (fused.get(id) || 0) + 1 / (RRF_K + r + 1)));
    const kwSet = new Set(kw);
    sem.forEach(({ id }, r) => { if (pq.phrases.length && !kwSet.has(id)) return; fused.set(id, (fused.get(id) || 0) + 1 / (RRF_K + r + 1)); });
    let ranked = [...fused.entries()].sort((a, b) => b[1] - a[1]).map(([id, score]) => ({ id, score }));
    const total = ranked.length;
    const want = group ? Math.max(limit * 4, RERANK_HEAD) : Math.max(limit, 1);
    let head = ranked.slice(0, Math.max(RERANK_HEAD, want));
    const rows = new Map(head.length ? this.q.byIds(head.length).all(...head.map((h) => h.id)).map((r) => [r.id, r]) : []);
    head = head.filter((h) => rows.has(h.id));
    let reranked = false;
    if (wantRerank && mode !== "keyword" && head.length > 1) {
      try {
        const t = Date.now(), part = head.slice(0, RERANK_HEAD);
        const rr = await rerank(q, part.map((h) => { const r = rows.get(h.id); return `Session: ${r.title}\n${r.text}`.slice(0, 2400); }), part.length);
        timing.rerank = Date.now() - t;
        // a small prior for what was SAID / RECORDED over raw tool output, to break near-ties
        const top = rr.map((x) => ({ id: part[x.index].id, score: x.score * (rows.get(part[x.index].id).kind === "tool" ? TOOL_PRIOR : 1) })).sort((a, b) => b.score - a.score);
        const got = new Set(top.map((x) => x.id));
        head = top.concat(head.filter((h) => !got.has(h.id))); reranked = true;
      } catch (e) { notes.push(`rerank unavailable: ${e.message}`); }
    }
    head = this.dedupe(head, vecs);
    const semScore = new Map(sem.map((s) => [s.id, s.score]));
    const sessions = new Map();
    const sess = (sid) => { if (!sid) return null; if (!sessions.has(sid)) sessions.set(sid, this.q.session.get(sid) || null); return sessions.get(sid); };
    const hits = head.map((h) => {
      const r = rows.get(h.id), s = sess(r.sid);
      return {
        id: r.id, score: +h.score.toFixed(4), via: [kwSet.has(r.id) && "keyword", semScore.has(r.id) && "semantic"].filter(Boolean), kind: r.kind, date: r.date, ts: r.ts,
        title: (s && s.title) || r.title, sid: r.sid, dir: (s && s.dir) || r.dir, state: (s && s.source) || r.source, machineId: s && s.machineId, file: r.file, lines: [r.lineFrom, r.lineTo],
        snippet: snippet(r.text, pq.highlight), text: opts.full ? r.text : undefined,
      };
    });
    const out = { query: q, mode, reranked, total, tookMs: 0, timing, notes, terms: pq.highlight };
    if (group) {
      const by = new Map(); // keyed by archive dir first: a session's records (docs) sit there too
      for (const h of hits) { const k = h.dir || h.sid || h.file; if (!by.has(k)) by.set(k, { title: h.title, sid: h.sid, dir: h.dir, state: h.state, machineId: h.machineId, date: h.date, score: h.score, hits: [] }); const g = by.get(k); g.count = (g.count || 0) + 1; if (g.hits.length < 3) g.hits.push(h); }
      out.sessions = [...by.values()].slice(0, limit);
    } else out.hits = hits.slice(0, limit);
    out.tookMs = Date.now() - t0;
    return out;
  }

  // keep the best-ranked of any group of near-identical passages (exact vectors)
  dedupe(head, vecs = new Map()) {
    this.exactVecs(head.map((h) => h.id), vecs);
    const kept = [], keptVecs = [];
    for (const h of head) {
      const v = vecs.get(h.id);
      if (!v || v.length !== EMBED_DIMS) { kept.push(h); continue; }
      if (!keptVecs.some((k) => dot(k, v) > NEAR_DUP)) { kept.push(h); keptVecs.push(v); }
    }
    return kept;
  }

  // the conversation around a hit: chunks of the same transcript (both streams, in file order)
  // or of the same doc
  context(id, before = 3, after = 3) {
    const c = this.q.chunk.get(id);
    if (!c) return null;
    const key = c.sid ? ["sid", c.sid] : ["file", c.file];
    const cols = "id, kind, ts, line_from lineFrom, line_to lineTo, text";
    const prev = this.db.prepare(`SELECT ${cols} FROM chunks WHERE ${key[0]} = ? AND (line_from < ? OR (line_from = ? AND id < ?)) ORDER BY line_from DESC, id DESC LIMIT ?`).all(key[1], c.lineFrom, c.lineFrom, c.id, before).reverse();
    const next = this.db.prepare(`SELECT ${cols} FROM chunks WHERE ${key[0]} = ? AND (line_from > ? OR (line_from = ? AND id > ?)) ORDER BY line_from, id LIMIT ?`).all(key[1], c.lineFrom, c.lineFrom, c.id, after);
    return { session: c.sid ? this.q.session.get(c.sid) : { title: c.title, dir: c.dir }, file: c.file, chunks: [...prev, { id: c.id, kind: c.kind, ts: c.ts, lineFrom: c.lineFrom, lineTo: c.lineTo, text: c.text, hit: true }, ...next] };
  }
}

function dot(a, b) { let s = 0; for (let j = 0; j < a.length; j++) s += a[j] * b[j]; return s; }

// v (unit Float32) -> q8[o..o+d) as round(v / max|v| * 127); returns the row's scale (max|v| / 127)
function quantize(v, q8, o) {
  let mx = 0;
  for (let j = 0; j < v.length; j++) { const a = Math.abs(v[j]); if (a > mx) mx = a; }
  if (!mx) return 0;
  const k = 127 / mx;
  for (let j = 0; j < v.length; j++) q8[o + j] = Math.round(v[j] * k);
  return mx / 127;
}

// ~320 chars around the densest cluster of query terms (the chunk's start when nothing matches
// literally — a purely semantic hit)
function snippet(text, terms, width = 320) {
  const lower = text.toLowerCase(), pos = [];
  for (const t of terms) { const tl = t.toLowerCase(); let i = -1, n = 0; while ((i = lower.indexOf(tl, i + 1)) !== -1 && n++ < 50) pos.push(i); }
  if (!pos.length) return text.length > width ? text.slice(0, width) + "…" : text;
  pos.sort((a, b) => a - b);
  let best = pos[0], bestN = 0;
  for (let i = 0; i < pos.length; i++) { let n = 0; for (let j = i; j < pos.length && pos[j] < pos[i] + width * 0.8; j++) n++; if (n > bestN) { bestN = n; best = pos[i]; } }
  const start = Math.max(0, best - Math.floor(width * 0.2)), end = Math.min(text.length, start + width);
  return (start ? "…" : "") + text.slice(start, end) + (end < text.length ? "…" : "");
}

module.exports = { Searcher, parseQuery, snippet, quantize, dot };
