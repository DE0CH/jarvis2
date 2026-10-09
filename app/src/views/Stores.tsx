// The core's secret stores (POST api/core/stores), shown as listed. Unlocking, locking and marking a
// store sensitive happen on the shell's secure page, which checks the core's signatures itself; the web
// page only shows the list.
import { useEffect } from "react";
import { useStore, loadStores, refresh } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, Card, Flex, Heading, Muted, P, Pill, Spinner } from "../ui/kit";
import { Cards } from "../ui/cards";
import { CORE_STORE } from "../lib/api";

export function Stores() {
  const r = useStore((s) => s.stores);
  useEffect(() => { loadStores(); }, []);
  const manage = () => requestSecure("stores", {}, () => { loadStores(); refresh(false); });
  return (
    <>
      <Flex align="center" gap={2} mb={3}>
        <Muted style={{ flex: 1 }}>{hasShell ? "Unlock and lock stores on the secure page (Face ID)." : "Unlocking and locking happen in the Jarvis 2 app on the iPhone."}</Muted>
        {hasShell && <Button id="stores-manage" onPress={manage}>Unlock / lock…</Button>}
      </Flex>
      {!r.loaded ? (r.err ? <P size={2} color="red">{r.err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>)
        : !r.items.length ? <P size={3} color="gray" align="center" mt={8} mb={8}>The core holds no stores yet.</P>
        : <Cards>
          {r.items.map((s) => (
            <Card key={s.name} data={{ store: s.name }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                <Heading size={3} style={{ flex: 1 }}>{s.name === CORE_STORE ? "core — the core's own Fly token" : s.name}</Heading>
                <Flex gap={1}>{s.sensitive && <Pill kind="bad">sensitive</Pill>}{s.unlocked ? <Pill kind="ok">unlocked</Pill> : <Pill kind="dim">locked</Pill>}</Flex>
              </Flex>
              <Muted>{s.keys.length} key{s.keys.length === 1 ? "" : "s"}{s.keys.length ? ": " + s.keys.join(", ") : ""}</Muted>
            </Card>
          ))}
        </Cards>}
      {!!r.err && r.loaded && <P size={2} color="red" mt={2}>{r.err}</P>}
    </>
  );
}
