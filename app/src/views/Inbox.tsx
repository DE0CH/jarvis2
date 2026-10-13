// The Inbox tab: everything waiting for the phone's Face ID that was asked for elsewhere (a session, the web page,
// Claude's setup session) — requests (repo keys, grants, unlocks) and the router's approvals (new session, resume on
// the latest image, add a store), and API calls a session's actions ask to run as Deyao (approved right on the card,
// web page or app). Each card: the action as its title (what will be signed, in short), who called
// which endpoint, and the caller's own reason (their words, unverified). Review opens the shell's secure page,
// which renders what is signed from the signed content itself; Deny drops it. The web page lists them and can deny.
import { ago, when, type InboxBatch, type InboxItem } from "../lib/api";
import { approveCall, denyBatch, denyRequest, inboxCall, inboxRows, inboxTitle } from "../lib/inbox";
import { useStore, refresh, settle, pendUntil, inboxLoose, useInboxCount } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Box, Button, Card, Flex, Heading, Lbl, Muted, Pill, P, Quote, Row, Rows } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";

const KIND: Record<string, string> = { "repo-key": "Repo key", grant: "Grant", unlock: "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "add-store": "Add a store", "api-call": "API call" };

/** open the entry's secure page; once it went through (or was denied there) the Inbox refreshes */
export function reviewRequest(it: InboxItem) {
  requestSecure(it.open.kind as any, { ...it.open.options, inboxId: it.id }, (r) => { if (r.result === "done") { refresh(false); settle(60000); } });
}

/** a batch: one card with the caller's summary (unverified) and every item as it is listed alone; approved on the
 * phone (one Face ID for all), denied here or there */
function BatchCard({ b }: { b: InboxBatch }) {
  const items = (useStore((s) => s.state.inbox) || []).filter((it) => it.batch === b.id);
  const approvals = useStore((s) => s.state.approvals), policy = useStore((s) => s.policy);
  const deny = () => pendUntil("b:" + b.id, "Denying…", () => denyBatch(b.id), (s) => !(s.inboxBatches || []).some((x) => x.id === b.id), 30000);
  return (
    <Card data={{ batch: b.id }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }} id={"batch-title-" + b.id}>{`${items.length + b.preparing} requests`}</Heading>
        <Pill kind="info">Batch</Pill>
      </Flex>
      <Rows id={"batch-rows-" + b.id}>
        <Row label="From" id={"batch-from-" + b.id}>{b.callerText}</Row>
        <Row label="Asked">{ago(b.created)}</Row>
        <Row label="Expires">{when(b.expires)}</Row>
        {b.preparing > 0 && <Row label="Being prepared">{String(b.preparing)}</Row>}
      </Rows>
      {!!b.summary && <Quote by={"Summary (from " + b.callerText + ", unverified)"} color="amber" lines={6} id={"batch-summary-" + b.id}>{b.summary}</Quote>}
      {items.map((it, n) => (
        <Box key={it.id} mt={2} data={{ request: it.id, requestKind: it.kind }}>
          <P size={2} weight="medium" id={"batch-item-" + b.id + "-" + (n + 1)}>{`${n + 1}. ${inboxTitle(it)}`}</P>
          <Rows>
            {inboxRows(it, approvals, policy).map((r) => <Row key={r.key} label={r.label}>{r.value}</Row>)}
            <Row label="Call" mono lines={2}>{inboxCall(it)}</Row>
          </Rows>
          {!!it.explanation && <Quote by="Reason (unverified)" color="amber" lines={3}>{it.explanation}</Quote>}
        </Box>
      ))}
      <Flex gap={2} pt={3} align="center">
        <Muted style={{ flex: 1 }}>Approve in the iPhone app: one Face ID for all.</Muted>
        <PButton pkey={"b:" + b.id} variant="soft" color="gray" onPress={deny} label="Deny all" id={"batch-deny-" + b.id} />
      </Flex>
    </Card>
  );
}

function RequestCard({ it }: { it: InboxItem }) {
  const approvals = useStore((s) => s.state.approvals), policy = useStore((s) => s.policy);
  const deny = () => pendUntil("q:" + it.id, "Denying…", () => denyRequest(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000);
  const approve = () => pendUntil("a:" + it.id, "Running…", () => approveCall(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000);
  return (
    <Card data={{ request: it.id, requestKind: it.kind }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }} id={"request-title-" + it.id}>{inboxTitle(it)}</Heading>
        <Pill kind="info">{KIND[it.kind] || it.kind}</Pill>
      </Flex>
      <Rows id={"request-rows-" + it.id}>
        {inboxRows(it, approvals, policy).map((r) => <Row key={r.key} label={r.label} id={"request-" + r.key + "-" + it.id}>{r.value}</Row>)}
        <Row label="From" id={"request-from-" + it.id}>{it.callerText}</Row>
        <Row label="Asked">{ago(it.created)}</Row>
        {!!it.expires && <Row label="Expires" id={"request-expires-" + it.id}>{when(it.expires)}</Row>}
        <Row label="Call" mono lines={2}>{inboxCall(it)}</Row>
      </Rows>
      {!!it.explanation && <Quote by={"Reason (from " + it.callerText + ", unverified)"} color="amber" lines={4} id={"request-reason-" + it.id}>{it.explanation}</Quote>}
      <Flex gap={2} pt={3} align="center">
        {it.kind === "api-call" ? <PButton pkey={"a:" + it.id} onPress={approve} label="Approve" id={"request-approve-" + it.id} />
          : hasShell ? <Button id={"request-review-" + it.id} onPress={() => reviewRequest(it)}>Review</Button>
          : <Muted style={{ flex: 1 }}>Approve in the iPhone app.</Muted>}
        <PButton pkey={"q:" + it.id} variant="soft" color="gray" onPress={deny} label="Deny" id={"request-deny-" + it.id} />
      </Flex>
    </Card>
  );
}

export function Inbox() {
  const all = useStore((s) => s.state.inbox) || [], batches = useStore((s) => s.state.inboxBatches) || [];
  const items = inboxLoose(all, batches);
  if (!items.length && !batches.length) return <P size={3} color="gray" align="center" mt={8} mb={8} id="inbox-empty">Nothing waiting for you.</P>;
  return (
    <Box data={{ group: "Inbox" }}>
      {!!batches.length && <>
        <Flex gap={2} align="center" mt={2}><Lbl mt={0}>Batches</Lbl><Pill kind="info">{String(batches.length)}</Pill></Flex>
        <Cards>{batches.map((b) => <BatchCard key={b.id} b={b} />)}</Cards>
      </>}
      {!!items.length && <>
        <Flex gap={2} align="center" mt={2}><Lbl mt={0}>Requests</Lbl><Pill kind="info">{String(items.length)}</Pill></Flex>
        <Cards>{items.map((it) => <RequestCard key={it.id} it={it} />)}</Cards>
      </>}
    </Box>
  );
}

/** the line at the top of Sessions while anything waits */
export function InboxNote({ onOpen }: { onOpen: () => void }) {
  const n = useInboxCount();
  if (!n) return null;
  return <Flex mb={3}><Button id="inbox-note" variant="soft" onPress={onOpen}><P size={2} weight="medium" color="blue">Inbox</P><Pill kind="info">{String(n)}</Pill><P size={2} color="blue">→</P></Button></Flex>;
}
