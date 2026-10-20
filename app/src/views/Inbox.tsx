// The Inbox tab: everything waiting for the phone's Face ID that was asked for elsewhere (a session, the web page,
// Claude's setup session) — requests (repo keys, grants, unlocks) and the router's approvals (new session, resume on
// the latest image, add a store), and API calls a session's actions ask to run as Deyao (Review opens the call's own
// page, pages/APICall.tsx: Approve runs it, and the page stays for the approvals the call brings about). Each card: the action as its title (what will be signed, in short), who called
// which endpoint, and the caller's own reason (their words, unverified). Review opens the shell's secure page,
// which renders what is signed from the signed content itself; Deny drops it. The web page lists them and can deny.
// Pending messages (lib/messages.ts) are listed per session: one entry with every message that waits to go into that
// session, each with its kind, who asked, the exact text and its expiry. Deliver is signed on the iPhone (Face ID per
// batch); the web page has no keys, so it can only deny them.
import { ago, when, type InboxBatch, type InboxItem, type State } from "../lib/api";
import { approvePeer, denyBatch, denyMessages, denyRequest, inboxCall, inboxRows, inboxTitle } from "../lib/inbox";
import { groupMessages, groupTitle, type MessageGroup, type MessageView } from "../lib/messages";
import { useStore, refresh, settle, pendUntil, inboxLoose, useInboxCount } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Box, Button, Card, Flex, Heading, Lbl, Muted, Pill, P, Quote, Row, Rows } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";

const KIND: Record<string, string> = { "repo-key": "Repo key", grant: "Grant", unlock: "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "add-store": "Add a store", "api-call": "API call", restore: "Restore store", "peer-message": "Peer message", message: "Message" };

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
          {it.kind === "api-call" && <Flex pt={1}><Button id={"request-review-" + it.id} onPress={() => openPage("call", { item: it })}>Review call</Button></Flex>}
          {it.kind === "peer-message" && <Flex pt={1}><PButton pkey={"q:" + it.id} onPress={() => pendUntil("q:" + it.id, "Delivering…", () => approvePeer(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000)} label="Deliver" id={"request-approve-" + it.id} /></Flex>}
        </Box>
      ))}
      <Flex gap={2} pt={3} align="center">
        <Muted style={{ flex: 1 }}>Approve in the iPhone app: one Face ID for all{items.some((x) => x.kind === "api-call" || x.kind === "peer-message") ? " (an API call or a peer message can also be approved here)" : ""}.</Muted>
        <PButton pkey={"b:" + b.id} variant="soft" color="gray" onPress={deny} label="Deny all" id={"batch-deny-" + b.id} />
      </Flex>
    </Card>
  );
}

function RequestCard({ it }: { it: InboxItem }) {
  const approvals = useStore((s) => s.state.approvals), policy = useStore((s) => s.policy);
  const deny = () => pendUntil("q:" + it.id, "Denying…", () => denyRequest(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000);
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
        {it.kind === "api-call" ? <Button id={"request-review-" + it.id} onPress={() => openPage("call", { item: it })}>Review</Button>
          : it.kind === "peer-message" ? <PButton pkey={"q:" + it.id} onPress={() => pendUntil("q:" + it.id, "Delivering…", () => approvePeer(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000)} label="Deliver" id={"request-approve-" + it.id} />
          : hasShell ? <Button id={"request-review-" + it.id} onPress={() => reviewRequest(it)}>Review</Button>
          : <Muted style={{ flex: 1 }}>Approve in the iPhone app.</Muted>}
        <PButton pkey={"q:" + it.id} variant="soft" color="gray" onPress={deny} label="Deny" id={"request-deny-" + it.id} />
      </Flex>
    </Card>
  );
}

// still waiting: in the Inbox, or pending in the state's messages
const stillPending = (s: State, ids: string[]) =>
  ids.some((id) => (s.inbox || []).some((x) => x.id === id) || (s.messages || []).some((x) => x.id === id && x.state === "pending"));

function MessageEntry({ m, n, deny }: { m: MessageView; n: number; deny?: () => void }) {
  return (
    <Box mt={2} data={{ message: m.id, messageKind: m.kind }} id={"message-" + m.id}>
      <P size={2} weight="medium" id={"message-label-" + m.id}>{n ? `${n}. ${m.kindLabel}` : m.kindLabel}</P>
      <Rows>
        <Row label="From" id={"message-from-" + m.id}>{m.from}</Row>
        <Row label="Asked">{ago(m.created)}</Row>
        {!!m.expires && <Row label="Expires" id={"message-expires-" + m.id}>{when(m.expires)}</Row>}
      </Rows>
      {/* the exact words that go into the session: in full, line breaks kept, selectable */}
      <Quote by="Text (exactly what is delivered)" color="blue" id={"message-text-" + m.id}>{m.text}</Quote>
      {!!m.note && <Muted mt={1} id={"message-note-" + m.id}>{m.note}</Muted>}
      {!!deny && <Flex pt={1}><PButton pkey={"msg:" + m.id} variant="soft" color="gray" size={1} onPress={deny} label="Deny this one" id={"message-deny-" + m.id} /></Flex>}
    </Box>
  );
}

/** one session's pending messages: listed together, denied together (or one by one); delivered on the iPhone */
function MessageGroupCard({ g }: { g: MessageGroup }) {
  const ids = g.messages.map((m) => m.id);
  const deny = (key: string, which: string[]) => pendUntil(key, "Denying…", () => denyMessages(which), (s) => !stillPending(s, which), 30000);
  const rules = g.messages.filter((m) => m.ruleable && m.ruleText).map((m) => m.ruleText).filter((t, i, a) => a.indexOf(t) === i);
  return (
    <Card data={{ messageGroup: g.session }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }} id={"message-group-title-" + g.session}>{groupTitle(g)}</Heading>
        <Pill kind="info">{g.messages.length === 1 ? "Message" : "Messages"}</Pill>
      </Flex>
      <Rows><Row label="Session" id={"message-group-session-" + g.session}>{g.sessionName}</Row></Rows>
      {g.messages.map((m, i) => <MessageEntry key={m.id} m={m} n={g.messages.length > 1 ? i + 1 : 0} deny={g.messages.length > 1 ? () => deny("msg:" + m.id, [m.id]) : undefined} />)}
      {!!rules.length && <Muted mt={2} id={"message-group-rules-" + g.session}>{`A rule can be made on the iPhone: ${rules.join("; ")}.`}</Muted>}
      <Flex gap={2} pt={3} align="center">
        <Muted style={{ flex: 1 }}>Deliver on the iPhone (Inbox): one Face ID for {g.messages.length === 1 ? "it" : "all of them"}.</Muted>
        <PButton pkey={"mg:" + g.session} variant="soft" color="gray" onPress={() => deny("mg:" + g.session, ids)} label={g.messages.length === 1 ? "Deny" : "Deny all"} id={"message-group-deny-" + g.session} />
      </Flex>
    </Card>
  );
}

export function Inbox() {
  const all = useStore((s) => s.state.inbox) || [], batches = useStore((s) => s.state.inboxBatches) || [];
  const pendingMessages = useStore((s) => s.state.messages) || [];
  const loose = inboxLoose(all, batches);
  const items = loose.filter((it) => it.kind !== "message");
  const groups = groupMessages(loose, pendingMessages);
  if (!items.length && !batches.length && !groups.length) return <P size={3} color="gray" align="center" mt={8} mb={8} id="inbox-empty">Nothing waiting for you.</P>;
  return (
    <Box data={{ group: "Inbox" }}>
      {!!batches.length && <>
        <Flex gap={2} align="center" mt={2}><Lbl mt={0}>Batches</Lbl><Pill kind="info">{String(batches.length)}</Pill></Flex>
        <Cards>{batches.map((b) => <BatchCard key={b.id} b={b} />)}</Cards>
      </>}
      {!!groups.length && <>
        <Flex gap={2} align="center" mt={2}><Lbl mt={0}>Messages</Lbl><Pill kind="info">{String(groups.reduce((n, g) => n + g.messages.length, 0))}</Pill></Flex>
        <Cards>{groups.map((g) => <MessageGroupCard key={g.session} g={g} />)}</Cards>
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
