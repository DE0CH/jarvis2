// Transcript (.jsonl) / text artefact -> search chunks. Pure functions + one streaming reader;
// no database, no network — so the chunking is testable on its own (test/search.test.js).
//
// A transcript yields TWO chunk streams, each in conversation order:
//   msg   what Deyao and Claude said (user prompts, assistant text, trimmed thinking)
//   tool  what Claude did (tool_use input + its tool_result, both trimmed; images/base64 dropped)
// Chunking is deterministic from the top of the file, so re-extracting a transcript that has
// grown reproduces the earlier chunks byte for byte and their embeddings are reused by hash.
const fs = require("fs");
const readline = require("readline");
const crypto = require("crypto");

const CHUNK_CHARS = 1800;      // target chunk size (~450 tokens EN, ~1100 tokens 中文)
const OVERLAP_CHARS = 200;     // when ONE segment is longer than a chunk and has to be split
const THINKING_CHARS = 700;
const TOOL_INPUT_CHARS = 900;
const TOOL_RESULT_CHARS = 1100;

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 32);

// head + tail of a long text: a command's useful output is usually its start (what it did) and
// its end (the result / the error)
function trim(text, max) {
  const t = String(text || "");
  if (t.length <= max) return t;
  const head = Math.floor(max * 0.6), tail = max - head;
  return `${t.slice(0, head)}\n…[${t.length - max} chars trimmed]…\n${t.slice(-tail)}`;
}

// long unbroken base64/hex runs (inline images, tokens, minified blobs) are noise for both BM25
// and the embedder
const stripBlobs = (t) => String(t || "").replace(/[A-Za-z0-9+/=_-]{200,}/g, "[blob]");

// harness-injected text inside a user message: not something anyone said
function stripInjected(t) {
  return String(t || "")
    .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, "")
    .replace(/<local-command-stdout>[\s\S]*?<\/local-command-stdout>/g, "")
    .replace(/<command-(name|message|args)>[\s\S]*?<\/command-\1>/g, (m) => m.replace(/<[^>]+>/g, " "))
    .trim();
}

function toolInputText(name, input) {
  if (!input || typeof input !== "object") return "";
  const i = input;
  if (name === "Bash") return `${i.description ? `# ${i.description}\n` : ""}$ ${i.command || ""}`;
  if (name === "Write") return `${i.file_path}\n${i.content || ""}`;
  if (name === "Edit") return `${i.file_path}\n- ${i.old_string || ""}\n+ ${i.new_string || ""}`;
  if (name === "Read") return String(i.file_path || "");
  if (name === "Agent" || name === "Task") return `${i.description || ""}\n${i.prompt || ""}`;
  if (name === "AskUserQuestion") return (i.questions || []).map((q) => `${q.question} [${(q.options || []).map((o) => o.label).join(" | ")}]`).join("\n");
  return Object.entries(i).map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
}

function toolResultText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b) => (b && b.type === "text" ? b.text : b && b.type === "image" ? "[image]" : "")).filter(Boolean).join("\n");
}

// One JSONL entry -> segments [{stream, label, text}] (+ title/meta side info)
function entrySegments(e, toolNames) {
  const segs = [];
  const m = e && e.message;
  if (!m || (e.type !== "user" && e.type !== "assistant")) return segs;
  if (e.isMeta || e.isCompactSummary) return segs; // injected context / a summary of turns already indexed
  const side = e.isSidechain ? "subagent " : "";
  const blocks = typeof m.content === "string" ? [{ type: "text", text: m.content }] : (m.content || []);
  for (const b of blocks) {
    if (!b || typeof b !== "object") continue;
    if (b.type === "text") {
      const t = e.type === "user" ? stripInjected(b.text) : String(b.text || "").trim();
      if (t) segs.push({ stream: "msg", label: `${side}${e.type === "user" ? "Deyao" : "Claude"}`, text: stripBlobs(t) });
    } else if (b.type === "thinking") {
      const t = String(b.thinking || "").trim();
      if (t) segs.push({ stream: "msg", label: `${side}Claude (thinking)`, text: trim(stripBlobs(t), THINKING_CHARS) });
    } else if (b.type === "tool_use") {
      toolNames.set(b.id, b.name);
      const t = toolInputText(b.name, b.input).trim();
      if (t) segs.push({ stream: "tool", label: `${side}${b.name}`, text: trim(stripBlobs(t), TOOL_INPUT_CHARS) });
      // a question put to Deyao is conversation too
      if (b.name === "AskUserQuestion" && t) segs.push({ stream: "msg", label: "Claude asks", text: trim(t, TOOL_INPUT_CHARS) });
    } else if (b.type === "tool_result") {
      const name = toolNames.get(b.tool_use_id) || "tool";
      const t = stripBlobs(toolResultText(b.content)).trim();
      if (!t) continue;
      if (name === "AskUserQuestion") segs.push({ stream: "msg", label: "Deyao answers", text: trim(t, TOOL_RESULT_CHARS) });
      else segs.push({ stream: "tool", label: `→ ${name}${b.is_error ? " ERROR" : ""}`, text: trim(t, TOOL_RESULT_CHARS) });
    }
  }
  return segs;
}

// Packs segments into chunks of ~CHUNK_CHARS; a segment longer than a chunk is split with overlap.
class Packer {
  constructor(kind, out) { this.kind = kind; this.out = out; this.parts = []; this.len = 0; this.from = 0; this.to = 0; this.ts = null; }
  add(label, text, line, ts) {
    const pieces = [];
    if (text.length <= CHUNK_CHARS) pieces.push(text);
    else for (let i = 0; i < text.length; i += CHUNK_CHARS - OVERLAP_CHARS) pieces.push(text.slice(i, i + CHUNK_CHARS));
    for (const p of pieces) {
      const part = `[${label}] ${p}`;
      if (this.len && this.len + part.length > CHUNK_CHARS) this.flush();
      if (!this.len) { this.from = line; this.ts = ts; }
      this.parts.push(part); this.len += part.length + 2; this.to = line;
    }
  }
  flush() {
    if (!this.len) return;
    const text = this.parts.join("\n\n");
    this.out.push({ kind: this.kind, text, hash: sha(text), lineFrom: this.from, lineTo: this.to, ts: this.ts });
    this.parts = []; this.len = 0;
  }
}

// Jarvis's peer-message deliveries (lib/peer.js) run a headless `claude -p` whose transcript
// lands next to the real one: pure plumbing, never worth a hit.
const RELAY_RE = /^You are a delivery relay\./;

// Stream a transcript file. `skipUuid(uuid)` lets the indexer drop entries another file already
// owns (a restored / resumed conversation is archived again with its whole history).
async function extractTranscript(file, { skipUuid } = {}) {
  const chunks = [], uuids = [], toolNames = new Map();
  const msg = new Packer("msg", chunks), tool = new Packer("tool", chunks);
  const meta = { title: null, sessionId: null, firstTs: null, lastTs: null, cwd: null, model: null, relay: false, entries: 0 };
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  let line = 0, firstUser = true;
  for await (const raw of rl) {
    line++;
    if (!raw || raw[0] !== "{") continue;
    let e; try { e = JSON.parse(raw); } catch { continue; } // a torn last line of a live transcript
    if (e.type === "ai-title" && e.aiTitle) meta.title = meta.customTitle || e.aiTitle;
    if (e.type === "custom-title" && e.customTitle) meta.title = meta.customTitle = e.customTitle;
    if (e.sessionId && !meta.sessionId) meta.sessionId = e.sessionId;
    if (e.cwd && !meta.cwd) meta.cwd = e.cwd;
    if (e.type === "assistant" && e.message && e.message.model && !meta.model) meta.model = e.message.model;
    if (e.type !== "user" && e.type !== "assistant") continue;
    if (firstUser && e.type === "user") {
      firstUser = false;
      const c = e.message && e.message.content;
      const t = typeof c === "string" ? c : ((c || []).find((b) => b && b.type === "text") || {}).text || "";
      if (RELAY_RE.test(t)) { meta.relay = true; rl.close(); break; }
    }
    if (e.timestamp) { if (!meta.firstTs) meta.firstTs = e.timestamp; meta.lastTs = e.timestamp; }
    if (e.uuid) { if (skipUuid && skipUuid(e.uuid)) { toolUseNames(e, toolNames); continue; } uuids.push(e.uuid); }
    meta.entries++;
    for (const s of entrySegments(e, toolNames)) (s.stream === "msg" ? msg : tool).add(s.label, s.text, line, e.timestamp || null);
  }
  msg.flush(); tool.flush();
  chunks.sort((a, b) => a.lineFrom - b.lineFrom || (a.kind === "msg" ? -1 : 1));
  return { meta, chunks, uuids };
}
// keep tool ids -> names known even for skipped entries, so a later (owned) result is labelled
function toolUseNames(e, toolNames) {
  const c = e.message && e.message.content;
  if (Array.isArray(c)) for (const b of c) if (b && b.type === "tool_use") toolNames.set(b.id, b.name);
}

// A text artefact (record.md, a report, a support-chat transcript) -> doc chunks, split on
// paragraph boundaries.
function htmlToText(html) {
  return html.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<\/(p|div|li|h\d|tr|section)>|<br\s*\/?>/gi, "\n\n")
    .replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ").replace(/ ?\n\s*\n\s*/g, "\n\n").trim();
}
function extractDoc(name, content) {
  let text = /\.html?$/i.test(name) ? htmlToText(content) : content;
  text = stripBlobs(text).trim();
  const chunks = [];
  if (!text) return chunks;
  const p = new Packer("doc", chunks);
  let n = 0;
  for (const para of text.split(/\n\s*\n/)) { n++; if (para.trim()) p.add(name, para.trim(), n, null); }
  p.flush();
  return chunks;
}

module.exports = { extractTranscript, extractDoc, entrySegments, trim, stripInjected, htmlToText, CHUNK_CHARS };
