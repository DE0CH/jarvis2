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
import { Button, Card, Flex, Heading, Lbl, Muted, P, Pill, Row, Rows, Spinner } from "../ui/kit";
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
    if (!(await ask({ title: g.kind === "rule" ? "Forget standing rule?" : "Forget grant?", rows: [
      { label: "Feature", value: holderTitle(g.holder) },
      { label: "Router stops", value: "Now" },
      { label: "Valid on machine", value: new Date(g.ends).toLocaleString() },
    ], action: "Forget", danger: true }))) return;
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
      <Rows mt={2}><Row label="Session" id="grants-session">{title}</Row></Rows>
      {!!m?.needsGrant && <Card mt={4} data={{ needsGrant: m.needsGrant }}>
        <Heading size={3} mb={1}>Feature turned away</Heading>
        <Rows>
          <Row label="Feature" id="grants-needs-feature">{holderTitle(m.needsGrant)}</Row>
          {!!HOLDERS[m.needsGrant]?.sub && <Row label="Does">{HOLDERS[m.needsGrant].sub}</Row>}
        </Rows>
        <Flex gap={2} mt={3} wrap>
          <Button id="grant-quick" onPress={() => make("grant", m.needsGrant)}>Allow 10 min</Button>
          <Button id="grant-rule" variant="soft" onPress={() => make("rule", m.needsGrant)}>Standing rule</Button>
        </Flex>
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
            <Rows>
              {!!HOLDERS[g.holder]?.sub && <Row label="Does">{HOLDERS[g.holder].sub}</Row>}
              <Row label="Ends" id={"grant-ends-" + g.holder}>{when(g.ends)}</Row>
            </Rows>
            <Flex mt={3}><PButton pkey={"g:" + g.id} id={"grant-forget-" + g.holder} variant="soft" color="red" onPress={() => forget(g)} label="Forget" /></Flex>
          </Card>))}</Cards>}
      {<><Lbl>New</Lbl>
        <RadioCards id="grant-holder" value={holder} onChange={setHolder} options={Object.entries(HOLDERS).map(([k, v]) => ({ value: k, title: v.title, sub: v.sub }))} />
        <Lbl>How long</Lbl>
        <Segmented id="grant-len" value={len} onChange={setLen} items={[["1", "1 min"], ["2", "2 min"], ["5", "5 min"], ["10", "10 min"], ["rule", "Standing rule"]]} />
        {len === "rule" && <><Lbl>Until</Lbl>
          <Segmented id="grant-days" value={days} onChange={setDays} items={[["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]]} />
          <Muted mt={2}>Not for a session with a sensitive store.</Muted></>}
        <Flex mt={3}><Button id="grant-review" onPress={review}>{hasShell ? "Review and allow…" : "Ask the iPhone…"}</Button></Flex>
        <Muted mt={2}>{hasShell ? "Allow with Face ID on the next screen." : "Goes to the iPhone app's Inbox."}</Muted></>}
    </Page>
  );
}
