// Machines tab: every Fly machine in jarvis2-sessions (api/machines, router/machines.go), live from Fly, each
// with the session it belongs to or "No session", and "test" when it points at a test router (its JARVIS2_URL
// is not production's). Destroy only for a machine with no session; the router re-checks that and destroys it
// through the core's kill. Session machines are paused or destroyed as their session, never from here.
import { api, ago, REGION, sessionTitle, type Machine } from "../lib/api";
import { useStore, getStore, ask, exclusive, pend, failed, setTab, loadMachines, toast } from "../lib/store";
import { Card, Flex, Heading, Muted, P, Pill, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";

const shortImage = (img: string) => img.replace(/^ghcr\.io\/de0ch\//, "").replace(/@sha256:([0-9a-f]{12})[0-9a-f]+$/, "@sha256:$1…");
const stateKind = (s: string) => (s === "started" ? "ok" : s === "starting" || s === "created" || s === "replacing" ? "wait" : s === "failed" ? "bad" : "dim");
const routerHost = (u: string) => { try { return new URL(u).hostname; } catch { return u; } };

// reload until the list satisfies pred: two-phase, the card goes only when Fly no longer lists it
async function settleMachines(pred: (l: Machine[]) => boolean, maxMs = 30000) {
  const until = Date.now() + maxMs;
  for (;;) { await loadMachines(); if (pred(getStore().machines.items) || Date.now() > until) return; await new Promise((r) => setTimeout(r, 1500)); }
}

function destroyOrphan(m: Machine) {
  return exclusive("machine:" + m.id, async () => {
    const ok = await ask({ title: `Destroy machine ${m.id}?`, danger: true, action: "Destroy machine",
      detail: `${m.name || m.id} belongs to no session${m.test ? " (it points at a test router)" : ""}. The core destroys it on Fly with its disk; nothing of it is archived. It can't be undone.` });
    if (!ok) return;
    pend("machine:" + m.id, "Destroying…");
    try {
      await api("POST", "api/machines/" + encodeURIComponent(m.id) + "/destroy");
      await settleMachines((l) => !l.some((x) => x.id === m.id));
      if (getStore().machines.items.some((x) => x.id === m.id)) toast("Fly still lists the machine — it may take a moment to go.", "info");
    } catch (e: any) { failed(e, "Could not destroy: "); }
    finally { pend("machine:" + m.id, null); }
  });
}

export function Machines() {
  const ms = useStore((s) => s.machines), sessions = useStore((s) => s.state.sessions), pending = useStore((s) => s.pending);
  if (!ms.loaded) return ms.err ? <P size={2} color="red">{"Could not list machines: " + ms.err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading…</Muted></Flex>;
  const orphans = ms.items.filter((m) => !m.sessionId).length;
  return (
    <>
      <Muted>Every machine in the Fly app jarvis2-sessions: {ms.items.length} machine{ms.items.length === 1 ? "" : "s"}, {orphans ? `${orphans} with no session` : "all belong to sessions"}. A paused session has no machine.</Muted>
      {!!ms.err && <P size={2} color="red" mt={2}>{"Could not refresh: " + ms.err}</P>}
      <Cards mt={12}>
        {ms.items.map((m) => {
          const s = m.sessionId ? (sessions || []).find((x) => x.id === m.sessionId) : null;
          return (
            <Card key={m.id} dim={pending.has("machine:" + m.id)} data={{ machine: m.id, orphan: m.sessionId ? "0" : "1" }}>
              <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                <Heading size={3} style={{ flex: 1 }}>{m.id}</Heading>
                {m.test && <Pill kind="info">test</Pill>}
                <Pill kind={stateKind(m.state)}>{m.state || "unknown"}</Pill>
              </Flex>
              {m.sessionId
                ? <P size={2} mb={1} onPress={() => setTab("sessions")} data={{ sessionLink: m.sessionId }}><P size={2} color="gray">{m.current ? "Session: " : "Earlier machine of: "}</P><P size={2} color="blue">{(s ? sessionTitle(s) : m.sessionId) + " ›"}</P></P>
                : <P size={2} mb={1} color="amber" weight="medium">No session</P>}
              {!!m.name && <Muted>{m.name}</Muted>}
              <Muted>{[REGION[m.region] ? `${REGION[m.region]} (${m.region})` : m.region, [m.size, m.guest].filter(Boolean).join(" · ")].filter(Boolean).join(" · ")}</Muted>
              <Muted>{m.created ? "Created " + ago(m.created) + " · " + new Date(m.created).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "Created: unknown"}</Muted>
              <Muted>{m.routerUrl ? "Router: " + routerHost(m.routerUrl) + (m.test ? " (a test router)" : "") : "Router: none set"}</Muted>
              <P size={1} color="gray" mono mt={1} selectable>{shortImage(m.image) || "no image"}</P>
              {!m.sessionId && (m.noDestroy
                ? <Muted mt={2}>{"Destroy isn't offered: " + m.noDestroy + "."}</Muted>
                : <Flex gap={2} pt={3} style={{ marginTop: "auto" }}>
                    <PButton pkey={"machine:" + m.id} color="red" variant="soft" onPress={() => destroyOrphan(m)} label="Destroy" />
                  </Flex>)}
            </Card>
          );
        })}
      </Cards>
      {!ms.items.length && <Muted mt={2}>No machines: nothing is running or stopped in the app.</Muted>}
    </>
  );
}
