// Deyao's repo list (the router's own, GET/POST/DELETE api/repos), picked from in New session: a session clones
// each picked repo with its own per-repo token from its stores. The picker lists what the router's read-only
// GitHub token can see (api/github/repos). Jarvis 1's Repos tab.
import { useState } from "react";
import { Pressable, ScrollView, View } from "react-native";
import { api, ago, type GhRepo } from "../lib/api";
import { useStore, pendUntil, ask, toast } from "../lib/store";
import { useTheme, radius } from "../theme";
import { Badge, Card, Flex, Heading, Lbl, Muted, P, Spinner, Text, TextField, ids } from "../ui/kit";
import { PButton, useCoolAfterShift } from "../ui/bits";
import { Cards } from "../ui/cards";
import { isWeb } from "../ui/overlays";

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

export function Repos() {
  const repos = useStore((s) => s.state.repos) || [];
  const pending = useStore((s) => s.pending);
  const cool = useCoolAfterShift(repos.map((x) => x.name).sort().join("|"));
  // controlled inputs: typed text and an open picker survive the poll-driven re-renders
  const [url, setUrl] = useState(""), [alias, setAlias] = useState(""), [ph, setPh] = useState("auto from URL");
  const busy = pending.has("repo:add");
  async function del(n: string) {
    if (!(await ask({ title: `Remove "${n}" from this list?`, detail: "This only forgets the entry here — nothing on GitHub is deleted or changed.", action: "Remove", danger: true }))) return;
    await pendUntil("repo:" + n, "Removing…", () => api("DELETE", "api/repos/" + encodeURIComponent(n)), (s) => !(s.repos || []).some((r) => r.name === n));
  }
  async function add() {
    if (busy) return;
    if (!url.trim()) { toast("Repo URL required.", "error"); return; }
    const u = url.trim(), same = (x: string) => x.toLowerCase().replace(/\.git$/, "") === u.toLowerCase().replace(/\.git$/, "");
    await pendUntil("repo:add", "Adding…", async () => { await api("POST", "api/repos", { url: u, name: alias.trim() }); setUrl(""); setAlias(""); setPh("auto from URL"); },
      (s) => (s.repos || []).some((r) => same(r.url)));
  }
  const wideMax = { maxWidth: 720 };
  return (
    <>
      {repos.length ? <Cards>{repos.map((x) => (
        <Card key={x.name} dim={pending.has("repo:" + x.name)} data={{ repo: x.name }}>
          <Flex justify="space-between" align="flex-start" gap={2}><Heading size={3} style={{ flex: 1 }}>{x.name}</Heading><PButton pkey={"repo:" + x.name} variant="soft" color="gray" onPress={() => del(x.name)} label="Remove" cool={cool} /></Flex>
          <Muted>{x.url}</Muted>
        </Card>))}</Cards> : <P size={3} color="gray" align="center" mt={6} mb={6}>No repos yet.</P>}
      <Card mt={3} id="repo-add" style={wideMax}>
        <Lbl mt={0}>Add repo — pick one of yours</Lbl>
        <Picker disabled={busy} onPick={(r) => { setUrl(r.url); setPh(r.fullName.split("/")[1]); }} />
        <Lbl>Git URL (any host)</Lbl>
        <TextField id="repo-url" keyboardType="url" autoComplete="off" autoCapitalize="none" autoCorrect={false} placeholder="https://github.com/owner/repo.git" value={url} disabled={busy} onChangeText={setUrl} onSubmitEditing={add} />
        <Lbl>Alias (optional)</Lbl>
        <TextField id="repo-title" autoComplete="off" autoCapitalize="none" autoCorrect={false} placeholder={ph} value={alias} disabled={busy} onChangeText={setAlias} onSubmitEditing={add} />
        <Flex mt={3}><PButton pkey="repo:add" onPress={add} label="Add repo" id="repo-add-go" /></Flex>
        <Muted mt={2}>The picker lists every repo the router's GitHub token can see. A session clones a repo only with a token for it in one of its stores (the setup session writes those).</Muted>
      </Card>
    </>
  );
}
