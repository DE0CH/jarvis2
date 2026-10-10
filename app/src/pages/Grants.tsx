// A session's grants (docs/DESIGN.md "Grants"): which of the router's features may run commands in it, for
// how long. A new one is chosen here (the feature, minutes or a standing rule's end) and the shell's secure grant
// page only reviews that request: Allow (Face ID) or Deny. Here they are also listed and forgotten. Forgetting stops the router using one; the signed text itself stays valid on the machine
// until it ends.
import { useEffect, useState } from "react";
import { HOLDERS, holderTitle, sessionTitle, when, type Grant } from "../lib/api";
import { forgetGrant, loadGrants, requestGrant } from "../lib/grants";
import { RadioCards, Segmented } from "../ui/kit";
import { useStore, ask, exclusive, failed, pend } from "../lib/store";
import { hasShell } from "../lib/shell";
import { Button, Card, Flex, Heading, Lbl, Muted, P, Pill, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { Page } from "../ui/page";

export type GrantsSpec = { id: string };

export function GrantsPage({ spec }: { spec: GrantsSpec }) {
  const m = useStore((s) => s.state.sessions.find((x) => x.id === spec.id));
  const [list, setList] = useState<Grant[] | null>(null), [err, setErr] = useState("");
  const load = () => loadGrants(spec.id).then((g) => { setList(g); setErr(""); }, (e) => setErr(e.message));
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [spec.id]);
  const title = m ? sessionTitle(m) : spec.id;
  const forget = (g: Grant) => exclusive("g:" + g.id, async () => {
    if (!(await ask({ title: `Forget the ${holderTitle(g.holder)} ${g.kind === "rule" ? "standing rule" : "grant"}?`, detail: "The router stops using it at once. The signed text itself stays valid on the machine until it ends (" + new Date(g.ends).toLocaleString() + ").", action: "Forget", danger: true }))) return;
    pend("g:" + g.id, "Forgetting…");
    try { await forgetGrant(g); for (let i = 0; i < 10; i++) { const gs = await loadGrants(spec.id); setList(gs); if (!gs.some((x) => x.id === g.id)) break; } }
    catch (e: any) { failed(e); }
    finally { pend("g:" + g.id, null); }
  });
  const make = (kind: "grant" | "rule", holder?: string) => requestGrant(spec.id, title, { kind, holder: holder || m?.needsGrant || "terminal", minutes: 10 }, () => load());
  // the new request: which feature, then minutes or a standing rule until a date
  const [holder, setHolder] = useState(m?.needsGrant || "terminal"), [len, setLen] = useState("10"), [days, setDays] = useState("30");
  const review = () => len === "rule"
    ? requestGrant(spec.id, title, { holder, kind: "rule", until: new Date(Date.now() + Number(days) * 86400000).toISOString() }, () => load())
    : requestGrant(spec.id, title, { holder, kind: "grant", minutes: Number(len) }, () => load());
  return (
    <Page title="Grants" id="grants-page">
      <Muted mt={2}>{title}</Muted>
      <Muted mt={2}>Features of the router (terminal, scheduler, status, login repair, archive check) run commands in a session only while the phone allows it: a grant for up to 10 minutes, or a standing rule until a date (not for a session with a sensitive store). The session may also allow a feature itself.</Muted>
      {!!m?.needsGrant && <Card mt={4} data={{ needsGrant: m.needsGrant }}>
        <Heading size={3} mb={1}>{holderTitle(m.needsGrant)} was turned away</Heading>
        <Muted>The machine refused the {holderTitle(m.needsGrant).toLowerCase()} feature ({HOLDERS[m.needsGrant]?.sub || "a router feature"}).</Muted>
        {hasShell ? <Flex gap={2} mt={3} wrap>
          <Button id="grant-quick" onPress={() => make("grant", m.needsGrant)}>{`Allow ${holderTitle(m.needsGrant).toLowerCase()} for 10 minutes`}</Button>
          <Button id="grant-rule" variant="soft" onPress={() => make("rule", m.needsGrant)}>Make a standing rule</Button>
        </Flex> : <Muted mt={2}>Allow it in the Jarvis 2 app on the iPhone.</Muted>}
      </Card>}
      <Lbl>In force</Lbl>
      {err ? <P size={2} color="red">{err}</P>
        : !list ? <Flex gap={2} align="center"><Spinner /><Muted>Loading grants…</Muted></Flex>
        : !list.length ? <P size={3} color="gray" align="center" mt={4} mb={4} id="grants-none">No grants or standing rules.</P>
        : <Cards>{list.map((g) => (
          <Card key={g.id} data={{ grant: g.holder }}>
            <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
              <Heading size={3} style={{ flex: 1 }}>{holderTitle(g.holder)}</Heading>
              <Pill kind={g.kind === "rule" ? "info" : "ok"}>{g.kind === "rule" ? "standing rule" : "grant"}</Pill>
            </Flex>
            <Muted>{HOLDERS[g.holder]?.sub || ""}</Muted>
            <Muted>ends {when(g.ends)}</Muted>
            <Flex mt={3}><PButton pkey={"g:" + g.id} id={"grant-forget-" + g.holder} variant="soft" color="red" onPress={() => forget(g)} label="Forget" /></Flex>
          </Card>))}</Cards>}
      {hasShell && <><Lbl>New</Lbl>
        <RadioCards id="grant-holder" value={holder} onChange={setHolder} options={Object.entries(HOLDERS).map(([k, v]) => ({ value: k, title: v.title, sub: v.sub }))} />
        <Lbl>How long</Lbl>
        <Segmented id="grant-len" value={len} onChange={setLen} items={[["1", "1 min"], ["2", "2 min"], ["5", "5 min"], ["10", "10 min"], ["rule", "Standing rule"]]} />
        {len === "rule" && <><Muted mt={2}>For things that happen while you are away (wakeups, auto-pause). Not for a session with a sensitive store. Until:</Muted>
          <Segmented id="grant-days" style={{ marginTop: 8 }} value={days} onChange={setDays} items={[["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]]} /></>}
        <Flex mt={3}><Button id="grant-review" onPress={review}>Review and allow…</Button></Flex>
        <Muted mt={2}>The next screen (drawn by the Jarvis 2 shell) shows exactly what will be signed: Allow with Face ID, or Deny.</Muted></>}
      {!hasShell && <Muted mt={4}>Grants are signed in the Jarvis 2 app on the iPhone.</Muted>}
    </Page>
  );
}
