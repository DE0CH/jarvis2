// Machines tab: every Fly machine in every org Deyao has (api/machines, router/machines.go + flyorgs.go), grouped
// org → app, so a leak anywhere shows (Deyao, 2026-10-11). jarvis2-sessions is this Jarvis's own: each machine with
// the session it belongs to or "No session", and "test" when it points at a test router (its JARVIS2_URL is not
// production's); Destroy only for a machine with no session (the router re-checks and destroys it through the
// core's kill). Every other app and org is read-only: jarvis2-370 and kamyee read from Fly, personal from Jarvis 1's
// list. A machine that stands out (stopped, failed, stuck, no session, an app no Jarvis uses) or a volume attached
// to nothing shows why in amber, and the count heads the page.
import { api, ago, REGION, sessionTitle, type Machine, type FlyAppView, type FlyOrgView, type FlyVolumeView } from "../lib/api";
import { useStore, getStore, ask, exclusive, pend, failed, setTab, loadMachines, toast } from "../lib/store";
import { Callout, Card, Flex, Heading, Lbl, Muted, P, Pill, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";

const shortImage = (img: string) => img.replace(/^ghcr\.io\/de0ch\//, "").replace(/@sha256:([0-9a-f]{12})[0-9a-f]+$/, "@sha256:$1…");
const stateKind = (s: string) => (s === "started" ? "ok" : s === "starting" || s === "created" || s === "replacing" ? "wait" : s === "failed" ? "bad" : "dim");
const routerHost = (u: string) => { try { return new URL(u).hostname; } catch { return u; } };
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
const createdText = (c: string) => (c ? "Created " + ago(c) + " · " + new Date(c).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "Created: unknown");

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

function MachineCard({ org, a, m }: { org: string; a: FlyAppView; m: Machine }) {
  const sessions = useStore((s) => s.state.sessions), pending = useStore((s) => s.pending);
  const s = a.own && m.sessionId ? (sessions || []).find((x) => x.id === m.sessionId) : null;
  return (
    <Card id={"machine-" + m.id} dim={pending.has("machine:" + m.id)} data={{ machine: m.id, org, app: a.app, own: a.own ? "1" : "0", orphan: a.own && !m.sessionId ? "1" : "0", attention: m.attention ? "1" : "0" }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }}>{m.id}</Heading>
        {m.test && <Pill kind="info">test</Pill>}
        <Pill kind={stateKind(m.state)}>{m.state || "unknown"}</Pill>
      </Flex>
      {!!m.attention && <P size={2} mb={1} color="amber" weight="medium" id={"machine-attention-" + m.id}>{m.attention}</P>}
      {a.own && (m.sessionId
        ? <P size={2} mb={1} onPress={() => setTab("sessions")} id={"machine-session-" + m.id} data={{ sessionLink: m.sessionId }}><P size={2} color="gray">{m.current ? "Session: " : "Earlier machine of: "}</P><P size={2} color="blue">{(s ? sessionTitle(s) : m.sessionId) + " ›"}</P></P>
        : null)}
      {!a.own && !!m.otherSession && <Muted>{"Jarvis 1 session " + m.otherSession}</Muted>}
      {!!m.name && <Muted>{m.name}</Muted>}
      <Muted>{[REGION[m.region] ? `${REGION[m.region]} (${m.region})` : m.region, [m.size, m.guest].filter(Boolean).join(" · ")].filter(Boolean).join(" · ")}</Muted>
      <Muted>{createdText(m.created)}</Muted>
      {a.own && <Muted>{m.routerUrl ? "Router: " + routerHost(m.routerUrl) + (m.test ? " (a test router)" : "") : "Router: none set"}</Muted>}
      <P size={1} color="gray" mono mt={1} selectable>{shortImage(m.image) || "no image"}</P>
      {a.own && !m.sessionId && (m.noDestroy
        ? <Muted mt={2}>{"Destroy isn't offered: " + m.noDestroy + "."}</Muted>
        : <Flex gap={2} pt={3} style={{ marginTop: "auto" }}>
            <PButton pkey={"machine:" + m.id} color="red" variant="soft" onPress={() => destroyOrphan(m)} label="Destroy" />
          </Flex>)}
    </Card>
  );
}

function VolumeCard({ org, a, v }: { org: string; a: FlyAppView; v: FlyVolumeView }) {
  return (
    <Card data={{ volume: v.id, org, app: a.app, attention: v.attention ? "1" : "0" }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }}>{v.id}</Heading>
        <Pill kind="dim">volume</Pill>
      </Flex>
      {!!v.attention && <P size={2} mb={1} color="amber" weight="medium">{v.attention}</P>}
      <Muted>{[v.name, `${v.sizeGb} GB`, REGION[v.region] ? `${REGION[v.region]} (${v.region})` : v.region, v.attachedTo ? "attached to " + v.attachedTo : ""].filter(Boolean).join(" · ")}</Muted>
      <Muted>{createdText(v.created)}</Muted>
    </Card>
  );
}

function AppSection({ org, a }: { org: string; a: FlyAppView }) {
  const n = a.machines.length;
  return (
    <>
      <Flex gap={2} align="center" mt={4} wrap data={{ flyApp: a.app }}>
        <Heading size={3}>{a.app}</Heading>
        {a.own ? <Pill kind="info">this Jarvis</Pill> : <Pill kind="dim">read-only</Pill>}
        {!!a.status && <Muted>{a.status}</Muted>}
      </Flex>
      <Muted>{[a.label || "Not an app any Jarvis runs sessions in", plural(n, "machine") + (a.volumes.length ? ", " + plural(a.volumes.length, "volume") : "")].join(" · ")}</Muted>
      {!!a.error && <P size={2} color="red" mt={1}>{"Could not list this app: " + a.error}</P>}
      {(n > 0 || a.volumes.length > 0) && (
        <Cards mt={8}>
          {a.machines.map((m) => <MachineCard key={m.id} org={org} a={a} m={m} />)}
          {a.volumes.map((v) => <VolumeCard key={v.id} org={org} a={a} v={v} />)}
        </Cards>
      )}
    </>
  );
}

function OrgSection({ o }: { o: FlyOrgView }) {
  const machines = o.apps.reduce((t, a) => t + a.machines.length, 0);
  return (
    <Flex dir="column" mt={6} data={{ flyOrg: o.org }}>
      <Lbl mt={0}>{"Org " + o.org}</Lbl>
      <Muted>{`${plural(o.apps.length, "app")}, ${plural(machines, "machine")}${o.via && o.via !== "fly" ? " · via " + o.via : ""}`}</Muted>
      {!!o.error && <P size={2} color="red">{"Could not list this org: " + o.error}</P>}
      {!o.error && !o.apps.length && <Muted mt={1}>No apps in this org.</Muted>}
      {o.apps.map((a) => <AppSection key={a.app} org={o.org} a={a} />)}
    </Flex>
  );
}

export function Machines() {
  const ms = useStore((s) => s.machines), fo = useStore((s) => s.flyOrgs);
  if (!ms.loaded) return ms.err ? <P size={2} color="red">{"Could not list machines: " + ms.err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading…</Muted></Flex>;
  const total = fo.orgs.reduce((t, o) => t + o.apps.reduce((u, a) => u + a.machines.length, 0), 0);
  return (
    <>
      <Muted>Every Fly machine in {plural(fo.orgs.length, "org")} ({fo.orgs.map((o) => o.org).join(", ")}): {plural(total, "machine")}. Only a machine of jarvis2-sessions with no session can be destroyed here. A paused session has no machine.</Muted>
      {fo.attention > 0
        ? <Callout color="amber" mt={3} id="machines-attention" data={{ machinesAttention: String(fo.attention) }}>{`${fo.attention} ${fo.attention === 1 ? "thing stands" : "things stand"} out below (stopped, failed or unexplained).`}</Callout>
        : <Callout color="green" mt={3} id="machines-attention" data={{ machinesAttention: "0" }}>Nothing stands out.</Callout>}
      {!!fo.configError && <P size={2} color="red" mt={2}>{fo.configError}</P>}
      {!!ms.err && <P size={2} color="red" mt={2}>{"Could not refresh: " + ms.err}</P>}
      {fo.orgs.map((o) => <OrgSection key={o.org} o={o} />)}
    </>
  );
}
