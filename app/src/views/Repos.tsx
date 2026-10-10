// Deyao's repos, in Settings (the router's list, GET api/repos / api/state `repos`). Each is a GitHub repo with
// its own deploy key: Add opens the shell's secure page (kind repo-key), where one Face ID lets the core make an
// SSH key, put it on the repo as a read/write deploy key and keep the private half in the store github-<repo>;
// Remove deletes both the same way. Sessions that include a repo's store clone, pull and push it over SSH. The
// picker lists what the router's read-only GitHub token can see (api/github/repos). On the web: view only.
import { useState } from "react";
import { Pressable, ScrollView, View } from "react-native";
import { api, ago, type GhRepo, type RepoEntry } from "../lib/api";
import { useStore, pend, refresh, settle, loadStores, toast } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { useTheme, radius } from "../theme";
import { Badge, Card, Flex, Heading, Lbl, Muted, P, Spinner, Text, TextField, ids } from "../ui/kit";
import { PButton } from "../ui/bits";
import { isWeb } from "../ui/overlays";

// owner/name from what was typed or picked: "owner/name", a GitHub https URL or git@github.com:owner/name
export function githubRepo(s: string): string {
  const m = s.trim().match(/^(?:https:\/\/github\.com\/|git@github\.com:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/);
  if (!m || m[2] === "." || m[2].includes("..")) return "";
  return m[1] + "/" + m[2];
}

// ---- GitHub repo picker: search box + a list of the repos the router's GitHub token can see ----
let cache: GhRepo[] | null = null;
function Picker({ onPick, disabled }: { onPick: (r: GhRepo) => void; disabled: boolean }) {
  const t = useTheme();
  const listed = useStore((s) => s.state.repos);
  const added = new Set((listed || []).map((r) => String(r.url).toLowerCase().replace(/\.git$/, "")));
  const [q, setQ] = useState(""), [open, setOpen] = useState(false), [hi, setHi] = useState(-1);
  const [repos, setRepos] = useState<GhRepo[] | null>(cache), [loading, setLoading] = useState(false), [error, setError] = useState<string | null>(null);
  async function load(fresh: boolean) {
    if (loading) return; setLoading(true); setError(null);
    try { const j = await api("GET", "api/github/repos" + (fresh ? "?refresh=1" : "")); cache = j.repos || []; setRepos(cache); }
    catch (e: any) { setError(e.message); }
    setLoading(false);
  }
  const all = repos || [], ql = q.trim().toLowerCase(), words = ql.split(/\s+/).filter(Boolean);
  const hit = (r: GhRepo) => words.every((w) => r.fullName.toLowerCase().includes(w) || (r.description || "").toLowerCase().includes(w) || (r.language || "").toLowerCase().includes(w));
  const m = all.filter(hit);
  // exact/prefix matches on the name float up; the API already orders by last push
  const rank = (r: GhRepo) => { const n = r.fullName.toLowerCase(), b = n.split("/")[1] || n; return b === ql ? 0 : b.startsWith(ql) ? 1 : n.includes(ql) ? 2 : 3; };
  if (ql) m.sort((a, b) => rank(a) - rank(b));
  const shown = m.slice(0, 40), hiIdx = Math.min(hi, shown.length - 1);
  const pick = (r: GhRepo) => { onPick(r); setQ(r.fullName); setHi(-1); setOpen(false); };
  const openIt = () => { if (!repos && !loading) load(false); setOpen(true); };
  const onKey = (e: any) => {
    const k = e.nativeEvent.key;
    if (k === "Escape") { setOpen(false); return; }
    if (!open && (k === "ArrowDown" || k === "ArrowUp")) { openIt(); return; }
    if (k === "ArrowDown") { e.preventDefault?.(); setHi(Math.min(hiIdx + 1, shown.length - 1)); }
    else if (k === "ArrowUp") { e.preventDefault?.(); setHi(Math.max(hiIdx - 1, -1)); }
    else if (k === "Enter") { e.preventDefault?.(); if (hiIdx >= 0) pick(shown[hiIdx]); else if (shown.length === 1) pick(shown[0]); }
  };
  const Note = ({ children }: { children: React.ReactNode }) => <View style={{ padding: 12 }}><P size={1} color="gray">{children}</P></View>;
  const retry = (label: string) => <Text size={1} style={{ color: t.accent.a[11] }} onPress={() => load(true)}>{label}</Text>;
  return (
    <View>
      <TextField id="repo-search" autoComplete="off" autoCapitalize="none" autoCorrect={false} placeholder="Search your GitHub repos…" value={q} disabled={disabled}
        onChangeText={(v) => { setQ(v); setOpen(true); }} onFocus={openIt} onKeyPress={onKey} />
      {open && (
        <View nativeID="repo-dd" style={{ marginTop: 4, backgroundColor: t.panel, borderWidth: 1, borderColor: t.gray.a[6], borderRadius: radius[4], maxHeight: 352, overflow: "hidden" }}>
          <ScrollView nestedScrollEnabled keyboardShouldPersistTaps="handled">
            {loading ? <Flex gap={2} align="center" p={3}><Spinner /><P size={1} color="gray">Loading your repos…</P></Flex>
              : error ? <Note>Couldn't list repos: {error} {retry("retry")}</Note>
              : <>
                {shown.map((r, i) => { const isAdded = added.has(r.htmlUrl.toLowerCase()); return (
                  <Pressable key={r.fullName} {...ids(undefined, { repoItem: r.fullName })} accessibilityState={{ disabled: isAdded }} disabled={isAdded} onPress={() => pick(r)} {...(isWeb ? { onPointerDown: (e: any) => e.preventDefault() } : {})}
                    style={({ pressed, hovered }: any) => ({ paddingHorizontal: 12, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: t.gray.a[4], opacity: isAdded ? 0.5 : 1, backgroundColor: i === hiIdx || hovered || pressed ? t.accent.a[3] : "transparent" })}>
                    <Flex gap={1} align="center" wrap>
                      <P size={2} weight="medium">{r.fullName}</P>
                      {r.private && <Badge>private</Badge>}{r.fork && <Badge>fork</Badge>}{r.archived && <Badge>archived</Badge>}{isAdded && <Badge>added</Badge>}
                    </Flex>
                    <P size={1} color="gray" lines={1}>{r.description || ""}{r.description ? " · " : ""}{r.language ? r.language + " · " : ""}pushed {r.pushedAt ? ago(r.pushedAt) : "?"}</P>
                  </Pressable>); })}
                {m.length > 40 && <Note>{m.length - 40} more — keep typing to narrow down</Note>}
                {!m.length ? <Note>{all.length ? "No match." : "No repos visible to the router's GitHub token."} {retry("refresh list")}</Note> : <Note>{all.length} repos · {retry("refresh list")}</Note>}
              </>}
          </ScrollView>
        </View>
      )}
    </View>
  );
}

// the shell's secure page for a repo's key; `done` once the core answered (the list follows the router's poll)
function openKeyPage(action: "add" | "remove", repo: string, key: string, after?: () => void) {
  pend(key, action === "add" ? "Adding…" : "Removing…");
  requestSecure("repo-key", { action, repo, sensitive: false }, (r) => {
    pend(key, null);
    if (r.result !== "done") return;
    toast(action === "add" ? `${repo}: deploy key added.` : `${repo}: deploy key and store removed.`, "ok");
    refresh(false); loadStores(); settle(30000); after?.();
  });
}

function RepoRow({ x }: { x: RepoEntry }) {
  const stores = useStore((s) => s.stores);
  const store = stores.items.find((s) => s.name === x.store);
  // the core's store list says whether the key is there (a Recover brings no repo keys back: make it again)
  const missing = stores.loaded && !store;
  const sensitive = store ? store.sensitive : !!x.sensitive;
  return (
    <Card data={{ repo: x.name }} mt={2}>
      <Flex justify="space-between" align="flex-start" gap={2}>
        <View style={{ flex: 1 }}>
          <Flex gap={1} align="center" wrap><Heading size={3}>{x.repo}</Heading>{sensitive && <Badge color="red">Sensitive</Badge>}{missing && <Badge color="amber">No key</Badge>}</Flex>
          <Muted id={"repo-key-" + x.name}>{missing ? `The store ${x.store} isn't in the core: make the key again.` : `Deploy key in ${x.store}${x.fingerprint ? " · " + x.fingerprint : ""}`}</Muted>
        </View>
        {hasShell && <Flex gap={2}>
          {missing && <PButton pkey={"repo:" + x.repo} size={1} onPress={() => openKeyPage("add", x.repo, "repo:" + x.repo)} label="Make key" id={"repo-makekey-" + x.name} />}
          <PButton pkey={"repo-rm:" + x.repo} size={1} variant="soft" color="gray" onPress={() => openKeyPage("remove", x.repo, "repo-rm:" + x.repo)} label="Remove" id={"repo-remove-" + x.name} />
        </Flex>}
      </Flex>
    </Card>
  );
}

/** Settings → Repos: the list, and Add (the app only: it needs Face ID) */
export function ReposCard() {
  const repos = useStore((s) => s.state.repos) || [];
  const busy = useStore((s) => s.pending.has("repo:add"));
  // a controlled input: typed text survives the poll-driven re-renders
  const [text, setText] = useState("");
  function add() {
    if (busy) return;
    const repo = githubRepo(text);
    if (!repo) { toast("A GitHub repo: owner/name or its URL.", "error"); return; }
    openKeyPage("add", repo, "repo:add", () => setText(""));
  }
  return (
    <Card data={{ settings: "repos" }} id="repos">
      <Heading size={3} mb={1}>Repos</Heading>
      <Muted>Each repo has its own deploy key on GitHub (read and push, that repo only), kept in its store github-&lt;repo&gt;. A session that includes the store clones, pulls and pushes the repo over SSH.</Muted>
      {repos.length ? repos.map((x) => <RepoRow key={x.repo} x={x} />) : <P size={2} color="gray" mt={3} id="repos-none">No repos yet.</P>}
      {hasShell ? <>
        <Lbl>Add repo — pick one of yours</Lbl>
        <Picker disabled={busy} onPick={(r) => setText(r.fullName)} />
        <Lbl>Or type it</Lbl>
        <TextField id="repo-url" keyboardType="url" autoComplete="off" autoCapitalize="none" autoCorrect={false} placeholder="owner/name or https://github.com/owner/name" value={text} disabled={busy} onChangeText={setText} onSubmitEditing={add} />
        <Flex mt={3}><PButton pkey="repo:add" onPress={add} label="Add repo" id="repo-add-go" /></Flex>
        <Muted mt={2}>Adding asks for Face ID: the core uses the GitHub token in the store github-deploy-keys for that one request.</Muted>
      </> : <Muted mt={3}>Adding or removing a repo needs Face ID: use the Jarvis 2 app on the iPhone.</Muted>}
    </Card>
  );
}

