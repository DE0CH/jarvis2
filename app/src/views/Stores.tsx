// The secret stores (GET api/stores), shown as listed with what each store and key is for (editable in
// place: ui/storedocs.tsx). Unlocking, locking and marking a store sensitive happen on the shell's secure page, which
// checks secrets' signatures itself; the web page only shows the list, and each store's earlier versions with a
// "Propose restore" that files an Inbox request (ui/storeversions.tsx).
import { useEffect } from "react";
import { useStore, loadStores, refresh } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, Card, Flex, Heading, Muted, P, Pill, Spinner } from "../ui/kit";
import { Cards } from "../ui/cards";
import { CORE_STORE, harnessStoreSet } from "../lib/api";
import { StoreDocs } from "../ui/storedocs";
import { StoreVersions } from "../ui/storeversions";

export function Stores() {
  const r = useStore((s) => s.stores);
  const harness = harnessStoreSet(useStore((s) => s.policy));
  useEffect(() => { loadStores(); }, []);
  const manage = () => requestSecure("stores", {}, () => { loadStores(); refresh(false); });
  return (
    <>
      <Flex align="center" gap={2} mb={3}>
        <Muted style={{ flex: 1 }}>{hasShell ? "Unlock and lock with Face ID." : "Unlock and lock in the iPhone app."}</Muted>
        {hasShell && <Button id="stores-manage" onPress={manage}>Unlock / lock…</Button>}
      </Flex>
      {!r.loaded ? (r.err ? <P size={2} color="red">{r.err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>)
        : !r.items.length ? <P size={3} color="gray" align="center" mt={8} mb={8}>No stores.</P>
        : <Cards>
          {r.items.filter((s) => s.name !== CORE_STORE).map((s) => (
            <Card key={s.name} data={{ store: s.name }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                <Heading size={3} style={{ flex: 1 }}>{s.name}</Heading>
                <Flex gap={1} wrap justify="flex-end" style={{ flexShrink: 1 }}>{s.sensitive && <Pill kind="bad">sensitive</Pill>}{s.unlocked ? <Pill kind="ok">unlocked</Pill> : <Pill kind="dim">locked</Pill>}{s.empty && <Pill kind="dim">empty</Pill>}{harness.has(s.name) && <Pill kind="info">harness</Pill>}{s.keysFrom === "recorded" && <Pill kind="dim">recorded</Pill>}</Flex>
              </Flex>
              <StoreDocs store={s} edit />
              {!s.name.startsWith("github-") || s.name === "github-deploy-keys" ? <StoreVersions store={s.name} /> : null}
            </Card>
          ))}
        </Cards>}
      {!!r.err && r.loaded && <P size={2} color="red" mt={2}>{r.err}</P>}
    </>
  );
}
