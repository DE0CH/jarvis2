// Embeddings + reranking through OpenRouter (key OPENROUTER_API — the same one sessions use).
//   POST /api/v1/embeddings  {model, input:[…], dimensions}   (OpenAI-compatible)
//   POST /api/v1/rerank      {model, query, documents:[…]}    (Cohere-compatible)
// Qwen3-Embedding is instruction-aware: a QUERY is embedded with a task instruction, documents
// are embedded bare — that asymmetry is worth several points of recall.
const EMBED_MODEL = process.env.EMBED_MODEL || "qwen/qwen3-embedding-8b";
const EMBED_DIMS = +(process.env.EMBED_DIMS || 1024);
const RERANK_MODEL = process.env.RERANK_MODEL || "cohere/rerank-4-fast";
const QUERY_INSTRUCT = "Instruct: Given a search query, retrieve passages from past AI-assistant work sessions (conversations, commands run and their output, task records) that are relevant to the query\nQuery: ";
const BASE = process.env.OPENROUTER_BASE || "https://openrouter.ai/api/v1";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function post(pathname, body, { tries = 5, timeoutMs = 120000 } = {}) {
  const key = process.env.OPENROUTER_API;
  if (!key) throw new Error("OPENROUTER_API is not set");
  let err;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(BASE + pathname, { method: "POST", signal: AbortSignal.timeout(timeoutMs), headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const text = await r.text();
      let j = null; try { j = JSON.parse(text); } catch { /* an HTML error page */ }
      if (r.ok && j && !j.error) return j;
      err = new Error(`${pathname} -> ${r.status} ${(j && j.error && (j.error.message || JSON.stringify(j.error))) || text.slice(0, 200)}`);
      // 402 = out of credit: retrying cannot help, and Deyao has to top up
      if (r.status === 401 || r.status === 402 || r.status === 400) { err.fatal = true; err.billing = r.status === 402; throw err; }
    } catch (e) { if (e.fatal) throw e; err = e; }
    await sleep(1500 * 2 ** i);
  }
  throw err;
}

function normalize(v) {
  const out = new Float32Array(v.length); let n = 0;
  for (let i = 0; i < v.length; i++) n += v[i] * v[i];
  n = Math.sqrt(n) || 1;
  for (let i = 0; i < v.length; i++) out[i] = v[i] / n;
  return out;
}

// texts -> Float32Array[] (unit length, EMBED_DIMS)
async function embedDocs(texts) {
  const j = await post("/embeddings", { model: EMBED_MODEL, input: texts, dimensions: EMBED_DIMS });
  const data = (j.data || []).slice().sort((a, b) => a.index - b.index);
  if (data.length !== texts.length) throw new Error(`embeddings: asked for ${texts.length}, got ${data.length}`);
  return data.map((d) => normalize(d.embedding.slice(0, EMBED_DIMS)));
}
async function embedQuery(q) {
  const j = await post("/embeddings", { model: EMBED_MODEL, input: [QUERY_INSTRUCT + q], dimensions: EMBED_DIMS }, { tries: 3, timeoutMs: 20000 });
  return normalize(j.data[0].embedding.slice(0, EMBED_DIMS));
}
// -> [{index, score}] best first
async function rerank(query, documents, topN) {
  const j = await post("/rerank", { model: RERANK_MODEL, query, documents, top_n: topN }, { tries: 2, timeoutMs: 20000 });
  return (j.results || []).map((r) => ({ index: r.index, score: r.relevance_score }));
}

const vecToBlob = (v) => Buffer.from(v.buffer, v.byteOffset, v.byteLength);
const blobToVec = (b) => new Float32Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));

module.exports = { embedDocs, embedQuery, rerank, vecToBlob, blobToVec, EMBED_MODEL, EMBED_DIMS, RERANK_MODEL };
