// A running session's stores (docs/API.md "Sessions"): Drop narrows its main grant in place to the stores kept
// (POST api/sessions/:id/narrow, the identity edge: no phone); Add asks the iPhone for one more store
// (POST api/requests/add-store, an approval in the Inbox, then an unlock of it).
import { useEffect, useState } from "react";
import { api, CORE_STORE, DEPLOY_KEY_TOKEN_STORE, harnessStoreSet, sessionTitle, storesOf } from "../lib/api";
import { narrowStores } from "../lib/addons";
import { useStore, loadStores, refresh, refreshUntil, settle, toast, failed } from "../lib/store";
import { Button, CheckboxCards, Flex, Lbl, Muted, Pill, RadioCards, Row, Rows, Spinner } from "../ui/kit";
import { BtnLabel } from "../ui/bits";
import { Page } from "../ui/page";

export type SessionStoresSpec = { id: string };

export function SessionStoresPage({ spec }: { spec: SessionStoresSpec }) {
  const sid = spec.id;
  const m = useStore((s) => s.state.sessions.find((x) => x.id === sid));
  const policy = useStore((s) => s.policy), stores = useStore((s) => s.stores);
  useEffect(() => { loadStores(); }, []);
  const own = m ? storesOf(m, policy) : [];
  const [keep, setKeep] = useState<string[] | null>(null);
  const kept = keep ?? own;
  const dropped = own.filter((n) => !kept.includes(n));
  const hidden = harnessStoreSet(policy);
  const addable = stores.items.filter((s) => s.name !== CORE_STORE && s.name !== DEPLOY_KEY_TOKEN_STORE && !hidden.has(s.name) && !(m?.stores || []).includes(s.name));
  const [add, setAdd] = useState(""), [busy, setBusy] = useState<string | null>(null);
  const running = m?.state === "started";

  async function drop() {
    if (!m || !dropped.length) return;
    // the harness's stores stay: the router keeps them (they are not Deyao's to drop here)
    const all = (m.stores || []).filter((n) => !dropped.includes(n));
    setBusy("Dropping…");
    try {
      await narrowStores(sid, all);
      await refreshUntil((s) => { const x = s.sessions.find((y) => y.id === sid); return !x || !dropped.some((n) => (x.stores || []).includes(n)); }, 20000);
      setKeep(null); toast("Stores dropped.", "ok");
    } catch (e) { failed(e); }
    setBusy(null);
  }
  async function ask() {
    if (!add) return;
    setBusy("Sending…");
    try {
      await api("POST", "api/requests/add-store", { session: sid, store: add });
      toast("Sent to the Inbox: approve it in the Jarvis 2 app.", "ok"); setAdd(""); refresh(false); settle(5000);
    } catch (e) { failed(e); }
    setBusy(null);
  }
  return (
    <Page title="Stores" id="session-stores-page">
      <Rows mt={2}>
        <Row label="Session" id="ss-session">{m ? sessionTitle(m) : sid}</Row>
        {!running && <Row label="State" id="ss-state">{m?.state || "gone"}</Row>}
      </Rows>
      <Lbl>Keep</Lbl>
      {own.length ? <CheckboxCards id="ss-keep" value={kept} onChange={setKeep} options={own.map((n) => ({ value: n, title: n }))} />
        : <Muted>No stores of its own.</Muted>}
      <Flex mt={2} gap={2} align="center">
        <Button id="ss-drop" color="red" variant="soft" disabled={!running || !dropped.length || !!busy} onPress={drop}>{busy === "Dropping…" ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Drop"}</Button>
        {!!dropped.length && <Pill kind="bad">{`${dropped.length} to drop`}</Pill>}
      </Flex>
      <Muted mt={1}>Takes effect now; getting one back needs the iPhone.</Muted>
      <Lbl>Add</Lbl>
      {addable.length ? <RadioCards id="ss-add" value={add} onChange={setAdd} options={addable.map((s) => ({ value: s.name, title: s.name, sub: s.sensitive ? <Pill kind="bad">sensitive</Pill> : undefined }))} />
        : stores.loaded ? <Muted>No other stores.</Muted> : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>}
      <Flex mt={2}><Button id="ss-ask" disabled={!running || !add || !!busy} onPress={ask}>{busy === "Sending…" ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Ask the iPhone"}</Button></Flex>
    </Page>
  );
}
