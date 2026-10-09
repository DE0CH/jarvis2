// A session's grants (docs/DESIGN.md "Grants"): which of the router's features may run commands in it, for
// how long. New ones are made on the shell's secure grant page (the phone signs them); here they are listed
// and forgotten. Forgetting stops the router using one; the signed text itself stays valid on the machine
// until it ends.
import { useEffect, useState } from "react";
import { HOLDERS, holderTitle, sessionTitle, when, type Grant } from "../lib/api";
import { forgetGrant, loadGrants, requestGrant } from "../lib/grants";
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
  return (
    <Page title="Grants" id="grants-page" right={hasShell ? <Button id="grant-new" onPress={() => make("grant")}>+ Allow…</Button> : undefined}>
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
        <Flex gap={2} wrap>
          <Button variant="soft" id="grant-new-grant" onPress={() => make("grant")}>Allow for minutes…</Button>
          <Button variant="soft" color="gray" id="grant-new-rule" onPress={() => make("rule")}>Make a standing rule…</Button>
        </Flex></>}
      {!hasShell && <Muted mt={4}>Grants are signed in the Jarvis 2 app on the iPhone.</Muted>}
    </Page>
  );
}
