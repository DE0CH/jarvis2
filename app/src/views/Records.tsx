// Previous sessions (GET api/records): the destroyed ones, from the router's index of what it archived to
// the Storage Box. Restore starts a NEW session line with the record's options whose first machine restores
// the archived snapshot — like any new session, the iPhone approves it first (the approval opens by itself
// in the app). Transcript reads the archive's end; Remove takes it off the list; Delete permanently also
// deletes its archive.
import { useEffect } from "react";
import { api, ago, newId, HARNESS, sessionTitle, storesOf, type Approval, type Rec } from "../lib/api";
import { useStore, getStore, loadRecords, pend, refresh, refreshUntil, setTab, settle, ask, askText, toast, failed, exclusive } from "../lib/store";
import { hasShell } from "../lib/shell";
import { review } from "./Sessions";
import { Button, Card, Flex, Heading, Muted, P, Pill, Spinner } from "../ui/kit";
import { LastMessage, PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";

const recTitle = (r: Rec) => r.archive?.title || sessionTitle(r);

export const restore = (r: Rec) => exclusive("r:" + r.id, async () => {
  const again = (r.restored || []).length ? ` It was already restored ${ago(r.restored![r.restored!.length - 1].at)} — this starts another copy.` : "";
  const ok = await ask({ title: `Restore “${recTitle(r)}”?`, detail: `Starts a new session with the same stores, harness, model and size, whose first machine restores the archived snapshot (files and conversation). The iPhone approves it like a new session.${again}`, action: "Restore" });
  if (!ok) return;
  const key = "r:" + r.id;
  pend(key, "Restoring…");
  try {
    const j = await api<{ id: string }>("POST", `api/records/${r.id}/restore`, { requestId: newId() });
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.session === j.id)) || s.sessions.some((x) => x.id === j.id && x.state !== "approval"), 60000);
    if (getStore().tab === "records") setTab("sessions");
    if (a && hasShell) review(a);
    else toast(hasShell ? "Restore requested — approve it at the top of the session list." : "Restore requested. Approve it in the Jarvis 2 app on the iPhone.", "ok");
    settle(120000);
  } catch (e: any) { failed(e); }
  finally { await loadRecords(); pend(key, null); }
});

// off the list (the archive stays), or for good (the archive too) — irreversible, so the title is typed
const remove = (r: Rec, purge: boolean) => exclusive("r:" + r.id, async () => {
  const t = recTitle(r);
  if (purge) {
    const ok = await askText({ title: `Delete “${t}” permanently?`, danger: true, action: "Delete permanently",
      detail: `Deletes its archive on the Storage Box — transcript${(r.archive?.transcripts || []).length === 1 ? "" : "s"}, artifacts, the signed snapshot and the Discord export — and takes it off this list. It can't be restored afterwards.${(r.restored || []).length ? " Sessions restored from it are separate and are not touched." : ""}`,
      input: { heading: "Delete permanently", label: "Type the session's title to confirm", placeholder: t, match: t } });
    if (ok === null) return;
  } else if (!(await ask({ title: `Remove “${t}” from the list?`, detail: "Its archive stays on the Storage Box; only the list entry goes.", action: "Remove", danger: true }))) return;
  pend("r:" + r.id, purge ? "Deleting…" : "Removing…");
  try { await api("DELETE", `api/records/${encodeURIComponent(r.id)}${purge ? "?purge=1" : ""}`); toast(`${purge ? "Deleted" : "Removed"} “${t}”.`, "ok"); }
  catch (e: any) { failed(e); }
  finally { await loadRecords(); pend("r:" + r.id, null); }
});

export function Records() {
  const r = useStore((s) => s.records);
  const policy = useStore((s) => s.policy);
  const pending = useStore((s) => s.pending);
  const models = useStore((s) => s.models);
  useEffect(() => { loadRecords(); }, []);
  if (!r.loaded) return r.err ? <P size={2} color="red">{r.err}</P> : <Flex gap={2} align="center" mt={4}><Spinner /><Muted>Loading previous sessions…</Muted></Flex>;
  const list = [...r.items].sort((a, b) => String(b.destroyedAt || b.created || "").localeCompare(String(a.destroyedAt || a.created || "")));
  if (!list.length) return <P size={3} color="gray" align="center" mt={8} mb={8}>{"No previous sessions yet.\nA session you destroy is listed here and can be restored from its archive."}</P>;
  return (
    <>
      {!!r.err && <P size={2} color="red" mb={2}>{r.err}</P>}
      <Cards>
        {list.map((m) => {
          const n = (m.restored || []).length, busy = pending.has("r:" + m.id), a = m.archive;
          // an archive indexed by hand (POST api/records) has no machine-signed snapshot: nothing Jarvis 2 can restore
          const signed = !!a?.signer;
          return (
            <Card key={m.id} data={{ record: m.id }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                <Heading size={3} style={{ flex: 1 }}>{recTitle(m)}</Heading>
                {n ? <Pill kind="ok">{"restored" + (n > 1 ? ` ×${n}` : "")}</Pill> : <Pill kind="dim">destroyed</Pill>}
              </Flex>
              <Muted>{[m.destroyedAt ? "destroyed " + ago(m.destroyedAt) : "", m.created ? "created " + new Date(m.created).toLocaleDateString() : ""].filter(Boolean).join(" · ")}</Muted>
              <Muted>{[storesOf(m, policy).length ? "stores: " + storesOf(m, policy).join(", ") : "no stores", HARNESS[m.harness || ""] || m.harness, models.find((x) => x.id === m.model)?.label || m.model, m.size, m.permissionMode === "bypass" ? "skip permissions" : "", m.live?.oneShot ? "was one-shot" : ""].filter(Boolean).join(" · ")}</Muted>
              <Muted>{a ? `${a.transcripts.length} transcript${a.transcripts.length === 1 ? "" : "s"} · ${a.artifacts} artifact file${a.artifacts === 1 ? "" : "s"}` : m.archiveError ? "not archived: " + m.archiveError : "no archive"}</Muted>
              {a && !signed && <Muted>Indexed by hand: no signed snapshot, so it can't be restored here.</Muted>}
              {a?.last && <LastMessage last={a.last} />}
              <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }}>
                {a && signed && <PButton pkey={"r:" + m.id} id={"restore-" + m.id} onPress={() => restore(m)} label="Restore" />}
                {a && <Button variant="soft" color="gray" id={"rtail-" + m.id} disabled={busy} onPress={() => openPage("transcript", { title: recTitle(m), note: "Destroyed " + ago(m.destroyedAt), path: `api/records/${m.id}/tail`, action: signed ? { label: "Restore", run: () => restore(m) } : undefined })}>Transcript</Button>}
                <Button variant="soft" color="gray" id={"rremove-" + m.id} disabled={busy} onPress={() => remove(m, false)}>Remove</Button>
                {a && <Button variant="soft" color="red" id={"rpurge-" + m.id} disabled={busy} onPress={() => remove(m, true)}>Delete</Button>}
              </Flex>
            </Card>
          );
        })}
      </Cards>
    </>
  );
}
