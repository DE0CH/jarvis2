#!/usr/bin/env python3
"""Export the OpenCode conversations of this session's Paseo agents as Claude-Code-shaped
transcripts, so everything downstream that reads ~/.claude/projects/*/*.jsonl — live transcript
sync, the pause snapshot, the Destroy archive, the search index, the dashboard title/tail —
works for an OpenCode session exactly as it does for a Claude one.

  ~/.paseo/agents/<cwd slug>/<agent id>.json   (Paseo: title + the OpenCode session id)
  `opencode export <ses_…>`                     (OpenCode: messages + parts)
      -> ~/.claude/projects/<cwd slug>/<agent id>.jsonl

One file per agent, rewritten whole (atomically) only when the conversation changed. Entry
uuids are derived from the OpenCode message ids, so re-exports and restored sessions dedupe in
the search index. Usage: opencode-transcript.py <working dir>   (one pass; the caller loops).
"""
import glob, hashlib, json, os, subprocess, sys, uuid
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
PASEO_HOME = os.environ.get("PASEO_HOME") or os.path.join(HOME, ".paseo")
NS = uuid.UUID("6f1d3c52-5b0e-4a57-9c39-0d3f2f6f2a11")


def iso(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def blocks(role, parts):
    """OpenCode parts -> Claude content blocks. A tool part carries call + result together; the
    result is returned separately so it can go into the user-side entry Claude transcripts use."""
    content, results = [], []
    for p in parts:
        t = p.get("type")
        if t == "text" and (p.get("text") or "").strip():
            content.append({"type": "text", "text": p["text"]})
        elif t == "reasoning" and (p.get("text") or "").strip():
            content.append({"type": "thinking", "thinking": p["text"]})
        elif t == "file":
            content.append({"type": "text", "text": "[attached file: %s]" % (p.get("filename") or p.get("url", "")[:80])})
        elif t == "tool":
            st = p.get("state") or {}
            cid = p.get("callID") or p.get("id") or ""
            content.append({"type": "tool_use", "id": cid, "name": p.get("tool") or "tool", "input": st.get("input") or {}})
            if st.get("status") in ("completed", "error"):
                out = st.get("output") if st.get("status") == "completed" else st.get("error")
                results.append({"type": "tool_result", "tool_use_id": cid, "content": str(out or ""),
                                **({"is_error": True} if st.get("status") == "error" else {})})
    return content, results


def convert(agent, export, cwd):
    sid = agent["id"]
    info = export.get("info") or {}
    lines, parent = [], None

    def entry(kind, mid, suffix, ts, message):
        nonlocal parent
        e = {"type": kind, "uuid": str(uuid.uuid5(NS, f"{mid}:{suffix}")), "parentUuid": parent, "sessionId": sid,
             "timestamp": ts, "cwd": cwd, "harness": "opencode", "message": message}
        parent = e["uuid"]
        lines.append(e)

    for m in export.get("messages") or []:
        mi = m.get("info") or {}
        role, mid = mi.get("role"), mi.get("id") or ""
        ts = iso((mi.get("time") or {}).get("created"))
        content, results = blocks(role, m.get("parts") or [])
        if role == "user":
            if content:
                entry("user", mid, "u", ts, {"role": "user", "content": content})
        elif role == "assistant":
            model = "/".join(x for x in (mi.get("providerID"), mi.get("modelID")) if x)
            if content:
                entry("assistant", mid, "a", ts, {"role": "assistant", "model": model, "content": content})
            if results:
                entry("user", mid, "r", iso((mi.get("time") or {}).get("completed")) or ts, {"role": "user", "content": results})
    title = (agent.get("title") or "").strip() or (info.get("title") or "").strip()
    if title:
        lines.append({"type": "ai-title", "aiTitle": title, "sessionId": sid})
    return lines


def main():
    if len(sys.argv) > 1:
        wd = os.path.abspath(sys.argv[1])
    else:  # the session's working dir, as the entrypoint picks it: the single repo, else ~/workspace
        wd = os.path.join(HOME, "workspace")
        dirs = [e.path for e in os.scandir(wd) if e.is_dir()] if os.path.isdir(wd) else []
        if len(dirs) == 1:
            wd = dirs[0]
    outdir = os.path.join(HOME, ".claude", "projects", "".join(c if c.isalnum() else "-" for c in wd))
    os.makedirs(outdir, exist_ok=True)
    for f in glob.glob(os.path.join(PASEO_HOME, "agents", "*", "*.json")):
        try:
            agent = json.load(open(f))
        except Exception:
            continue
        ses = ((agent.get("persistence") or {}).get("sessionId")) or ((agent.get("runtimeInfo") or {}).get("sessionId"))
        if agent.get("provider") != "opencode" or not ses or agent.get("internal"):
            continue
        # unchanged since the last export (Paseo bumps updatedAt on every turn / title change)
        stamp = os.path.join(outdir, f".{agent['id']}.stamp")
        mark = f"{agent.get('updatedAt')}|{agent.get('title')}"
        dst = os.path.join(outdir, agent["id"] + ".jsonl")
        if os.path.exists(dst) and os.path.exists(stamp) and open(stamp).read() == mark:
            continue
        try:
            r = subprocess.run(["opencode", "export", ses], cwd=agent.get("cwd") or wd, capture_output=True, text=True, timeout=120)
            raw = r.stdout[r.stdout.index("{"):]
            export = json.loads(raw)
        except Exception as e:
            sys.stderr.write(f"[opencode-transcript] export of {ses} failed: {e}\n")
            continue
        body = "".join(json.dumps(l, ensure_ascii=False) + "\n" for l in convert(agent, export, agent.get("cwd") or wd))
        if os.path.exists(dst) and hashlib.sha256(open(dst, "rb").read()).digest() == hashlib.sha256(body.encode()).digest():
            open(stamp, "w").write(mark)
            continue
        tmp = dst + ".tmp"
        with open(tmp, "w", encoding="utf-8") as out:
            out.write(body)
        os.replace(tmp, dst)
        open(stamp, "w").write(mark)


if __name__ == "__main__":
    main()
