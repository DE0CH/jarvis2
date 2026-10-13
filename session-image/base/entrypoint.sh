#!/bin/bash
# Session container entrypoint (runs as user `claude` on a Fly Machine).
# Injected by Jarvis via Fly Machine env:
#   CLAUDE_CREDENTIALS      contents of ~/.claude/.credentials.json (OAuth; enables remote-control)
#   CLAUDE_ACCOUNT          minimal ~/.claude.json (oauthAccount + userID)  [optional]
#   SESSION_SECRETS_JSON    the chosen environment's secrets as a JSON object (-> ~/.secrets + env)
#   SESSION_REPOS           comma-separated git URLs to clone into ~/workspace
#   SESSION_CONTENT         comma-separated content store names, pulled into ~/content/<store>/ (content-sync)
#   SESSION_API_PROXY       "1": the supervisor runs claude through api-proxy.js (logs ~/artifacts/api-log)
#   SESSION_LABEL           session title; blank => the Claude session names itself
#   SESSION_PERMISSION_MODE auto | bypass
#   SESSION_PROMPT          [optional] first prompt, typed into the host once it is up (supervisor)
#   SESSION_ATTACHMENTS_JSON [optional] first-prompt attachments as [{name,isImage}] — the supervisor
#                           downloads them (SESSION_ATTACH_DAV_BASE/_DIR/_DAV_USER/_DAV_PASS point at
#                           their Storage Box staging dir) into ~/uploads and references them in the
#                           first message (images become inline [Image #N]); see session-supervisor.sh
#   SESSION_ONE_SHOT        "1" = one-shot: claude exits once SESSION_PROMPT is done and Jarvis
#                           archives + destroys the machine (see one_shot_watch in the supervisor)
#   SESSION_MODEL           model id (default claude-opus-5-5, see session-supervisor.sh)
# Fly itself sets FLY_MACHINE_ID. If the environment carries KUBE_SERVER + KUBE_TOKEN (+ KUBE_CA),
# a kubeconfig is written so the session can drive the controller cluster with kubectl.
#
# Boots are NOT all fresh: a paused session has NO machine — before releasing it Jarvis
# snapshots the transcript(s), ~/.claude.json, ~/workspace and ~/artifacts to
# claude-records/.paused/<session id>/ on the Storage Box (jarvis/lib/archive.js), and Start
# creates a new machine with SESSION_ID = that id; this script restores the snapshot so
# session-supervisor.sh can `claude --resume` the same conversation with the working tree exactly
# as it was (a first machine has no SESSION_ID: its FLY_MACHINE_ID is the session id). The same
# path restores a DESTROYED session: Jarvis seeds such a snapshot for a brand-new machine from
# the session's archive before its first start (transcripts + artifacts, no workspace/claude.json).
set -uo pipefail
HOME=/home/claude; cd "$HOME"
# ~/artifacts: anything the session puts (or symlinks) here is archived to the Storage Box by
# Jarvis when the session is destroyed (alongside the transcripts) — see CLAUDE.md.
mkdir -p "$HOME/.claude" "$HOME/workspace" "$HOME/artifacts"

# --- environment secrets ---------------------------------------------------
# Written shell-quoted so values with spaces/quotes/newlines (Fly tokens, PEM certs) survive
# `. ~/.secrets`. The old KEY=VALUE format silently dropped any value containing a space.
# First, because the pause-snapshot restore below needs the STORAGEBOX_* creds.
if [ -n "${SESSION_SECRETS_JSON:-}" ]; then
  python3 - <<'PY'
import json,os,shlex
d=json.loads(os.environ["SESSION_SECRETS_JSON"])
p=os.path.expanduser("~/.secrets")
with open(p,"w") as f:
    for k,v in d.items():
        if k.replace("_","").isalnum(): f.write(f"{k}={shlex.quote(str(v))}\n")
os.chmod(p,0o600)
PY
  set -a; . "$HOME/.secrets"; set +a
fi

# --- secret-store merge conflicts ------------------------------------------
# When a session is booted from SEVERAL secret stores (jarvis multi-select) that define the SAME
# key with DIFFERENT values, Jarvis picks one value at RANDOM and lists the clashing keys in
# SESSION_SECRET_CONFLICTS. Drop that list on disk so an agent inside can discover that an injected
# secret is ambiguous (a random one won this session) — look for ~/.session-secret-conflicts.json.
CONFLICTS_FILE="$HOME/.session-secret-conflicts.json"
rm -f "$CONFLICTS_FILE"
if [ -n "${SESSION_SECRET_CONFLICTS:-}" ]; then
  printf '%s\n' "$SESSION_SECRET_CONFLICTS" > "$CONFLICTS_FILE"
  chmod 600 "$CONFLICTS_FILE"
  echo "[entrypoint] WARN secret-store key conflicts across the selected stores (value chosen at random): see $CONFLICTS_FILE"
fi

# --- restore the pause snapshot (if this machine was paused) -----------------
# claude-records/.paused/<session id>/ holds what Jarvis snapshotted at pause time (or seeded
# for a Previous-restore): ~/.claude.json (fetched before the machineID merge below, so the same
# Remote Control identity is kept), the transcripts (staged in $RESTORE_DIR, placed under the project
# slug once the working dir is known, further down), ~/workspace, ~/artifacts, the harness state.
# /usr/local/bin/restore-snapshot does the fetching. Two ways to run it:
#   - the session's own secrets carry the Storage Box creds: run it here, now;
#   - they do not (a trimmed store; SESSION_RESTORE_VIA_JARVIS=1 from Jarvis): the JARVIS
#     runs it through Fly exec with the creds as exec-time environment only, right after the start —
#     wait for its ~/.restore-done marker (up to 5 min; a fresh machine gets "none" within seconds).
# Any failure => fresh session.
RESTORE_DIR="$HOME/.paused-restore"; rm -rf "$RESTORE_DIR"; rm -f "$HOME/.restore-done"
if [ -n "${STORAGEBOX_HOST:-}" ] && [ -n "${STORAGEBOX_USER:-}" ] && [ -n "${STORAGEBOX_PASSWORD:-}" ]; then
  /usr/local/bin/restore-snapshot || echo "[entrypoint] WARN restore-snapshot exited $?"
elif [ "${SESSION_RESTORE_VIA_JARVIS:-}" = 1 ]; then
  echo "[entrypoint] no Storage Box creds in this session; waiting for Jarvis's restore step"
  for _ in $(seq 1 150); do [ -e "$HOME/.restore-done" ] && break; sleep 2; done
  if [ -e "$HOME/.restore-done" ]; then echo "[entrypoint] jarvis restore step: $(cat "$HOME/.restore-done")"
  else echo "[entrypoint] WARN Jarvis's restore step never reported; continuing as a fresh session"; fi
else
  echo "[entrypoint] no Storage Box creds and no jarvis restore flagged; fresh session"
fi

# --- Claude auth -----------------------------------------------------------
if [ -n "${CLAUDE_CREDENTIALS:-}" ]; then
  printf '%s' "$CLAUDE_CREDENTIALS" > "$HOME/.claude/.credentials.json"
  chmod 600 "$HOME/.claude/.credentials.json"
fi
# machineID: reuse the one in ~/.claude.json when it was restored from a pause snapshot (same
# Remote Control identity in the Claude app instead of a new target); mint a fresh one on a
# brand-new machine. Existing ~/.claude.json fields (projects trust, etc.) are preserved, then
# the account + fixed flags are merged on top.
MID="$(tr -d - < /proc/sys/kernel/random/uuid)"
python3 - "$MID" <<'PY'
import json,os,sys
mid=sys.argv[1]; p=os.path.expanduser("~/.claude.json")
try: existing=json.load(open(p))
except Exception: existing={}
try: d=json.loads(os.environ.get("CLAUDE_ACCOUNT","") or "{}")
except Exception: d={}
if existing.get("machineID"): mid=existing["machineID"]
existing.update(d)
existing.update({"machineID":mid,"hasCompletedOnboarding":True,"hasUsedRemoteControl":True,
          "bypassPermissionsModeAccepted":True,"autoUpdates":False})
json.dump(existing,open(p,"w"))
PY

# --- kubeconfig for the controller cluster ----------------------------------
if [ -n "${KUBE_SERVER:-}" ] && [ -n "${KUBE_TOKEN:-}" ]; then
  mkdir -p "$HOME/.kube"; umask 077
  if [ -n "${KUBE_CA:-}" ]; then printf '%s\n' "$KUBE_CA" > "$HOME/.kube/ca.crt"; CA_LINE="    certificate-authority: $HOME/.kube/ca.crt"
  else CA_LINE="    insecure-skip-tls-verify: true"; fi
  cat > "$HOME/.kube/config" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: controller
  cluster:
    server: $KUBE_SERVER
$CA_LINE
users:
- name: claude-admin
  user:
    token: $KUBE_TOKEN
contexts:
- name: controller
  context: {cluster: controller, user: claude-admin}
current-context: controller
EOF
  umask 022
fi

# --- repos -----------------------------------------------------------------
# Repos come from JARVIS as git bundles (Jarvis fetches them with its own GitHub token, so a
# session needs none unless it wants to push):
#   - a hand-off session (no Jarvis access): Jarvis's in-machine step has already put them in
#     ~/.jarvis-delivery/repos/<name>.bundle (before ~/.restore-done, which the wait above covers);
#   - any other session: GET $JARVIS_URL/api/sessions/<id>/repos/<name>/bundle with its session token.
# origin then points at the real URL: pushing works when the session's store has a GITHUB_TOKEN.
DELIVERY="$HOME/.jarvis-delivery"
if [ -z "${SESSION_REPOS:-}" ]; then echo "[entrypoint] SESSION_REPOS is empty: no repo to clone (the session runs in an empty ~/workspace)"; fi
if [ -n "${SESSION_REPOS:-}" ]; then
  IFS=',' read -ra REPOS <<< "$SESSION_REPOS"
  for url in "${REPOS[@]}"; do
    url="$(echo "$url" | xargs)"; [ -z "$url" ] && continue
    name="$(basename "$url" .git)"
    if [ -d "$HOME/workspace/$name/.git" ]; then echo "[entrypoint] $name restored from the pause snapshot; not cloning"; continue; fi
    bundle="$DELIVERY/repos/$name.bundle"
    if [ ! -s "$bundle" ] && [ -n "${SESSION_API_TOKEN:-}" ] && [ -n "${JARVIS_URL:-}" ]; then
      mkdir -p "$DELIVERY/repos"
      curl -fsS --retry 3 --max-time 300 -o "$bundle" \
        -H "Authorization: Bearer $SESSION_API_TOKEN" -H "User-Agent: claude-session-entrypoint/1" \
        -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID:-}" -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET:-}" \
        "$JARVIS_URL/api/sessions/${SESSION_ID:-$FLY_MACHINE_ID}/repos/$name/bundle" \
        || { echo "[entrypoint] WARN could not download the $name bundle from Jarvis"; rm -f "$bundle"; }
    fi
    if [ ! -s "$bundle" ]; then echo "[entrypoint] WARN no bundle for $name: not cloned"; continue; fi
    echo "[entrypoint] cloning $name from the Jarvis bundle"
    if out="$(git clone -q "$bundle" "$HOME/workspace/$name" 2>&1)"; then
      git -C "$HOME/workspace/$name" remote set-url origin "$url"
      # make origin/<branch> refs match what the bundle carried, so `git status` is meaningful
      git -C "$HOME/workspace/$name" fetch -q "$bundle" "+refs/heads/*:refs/remotes/origin/*" 2>/dev/null || true
    else
      echo "[entrypoint] WARN clone from bundle failed: $name: $(printf '%s' "$out" | tr '\n' ' ')"
    fi
  done
fi

# --- content stores --------------------------------------------------------
# SESSION_CONTENT names the content stores picked for this session (Jarvis lib/content.js): each is
# downloaded into ~/content/<store>/ on EVERY boot (a Start after a pause pulls them fresh — local
# changes not pushed with `content-sync push` before the pause are gone). Through Jarvis with this
# session's token; a failure only leaves the folder missing (retry: `content-sync pull`).
# A hand-off session (no Jarvis access) gets them from Jarvis's in-machine step instead, in
# ~/.jarvis-delivery/content/<store>/ — read-only copies there, since content-sync push can't reach Jarvis.
if [ -n "${SESSION_CONTENT:-}" ]; then
  rm -rf "$HOME/content" "$HOME/.content-sync"
  if [ -d "$DELIVERY/content" ]; then
    mv "$DELIVERY/content" "$HOME/content" && echo "[entrypoint] content: delivered by Jarvis: $(ls "$HOME/content" | tr '\n' ' ')"
  else
    /usr/local/bin/content-sync pull --force 2>&1 | sed 's/^/[entrypoint] content: /' || true
  fi
fi
rm -rf "$DELIVERY"

# working dir = the single repo if there's exactly one, else the workspace root
WD="$HOME/workspace"
mapfile -t DIRS < <(find "$HOME/workspace" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
[ "${#DIRS[@]}" = "1" ] && WD="${DIRS[0]}"
# Several repos: claude only discovers CLAUDE.md / skills / settings / hooks from the cwd and
# its ancestors, so generate a workspace-level layer that links to every repo's own
# (see workspace-layer.sh). Regenerated on every boot, including resumes.
[ "$WD" = "$HOME/workspace" ] && [ "${#DIRS[@]}" -gt 1 ] && /usr/local/bin/workspace-layer.sh "$WD"

# --- place restored transcripts where claude looks for them ------------------
# ~/.claude/projects/<cwd slug>/<id>.jsonl — session-supervisor.sh then starts
# `claude --resume <newest id>`. The first-prompt marker is set so the supervisor does not type
# SESSION_PROMPT into the resumed conversation again.
if compgen -G "$RESTORE_DIR/*.jsonl" >/dev/null 2>&1; then
  PDIR="$HOME/.claude/projects/$(printf '%s' "$WD" | sed 's#[^A-Za-z0-9]#-#g')"
  mkdir -p "$PDIR"
  mv "$RESTORE_DIR"/*.jsonl "$PDIR"/
  touch "$HOME/.claude/.first-prompt-sent"
  echo "[entrypoint] resume ready: $(ls "$PDIR"/*.jsonl | wc -l) transcript(s) in $PDIR"
fi
rm -rf "$RESTORE_DIR"

# --- per-session start hooks --------------------------------------------------
# Background servers a session started (a tunnel page, a watcher) die when Jarvis pauses the machine.
# Executables in ~/artifacts/on-start/ come back with the pause snapshot and are run here, in the
# background, on every boot, so the session's pages return on Start. Log: <script>.log next to it.
if [ -d "$HOME/artifacts/on-start" ]; then
  for f in "$HOME"/artifacts/on-start/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    (cd "$WD" && setsid nohup "$f" >"$f.log" 2>&1 </dev/null &)
    echo "[entrypoint] on-start hook: $f"
  done
fi

exec /usr/local/bin/session-supervisor.sh "$WD"
