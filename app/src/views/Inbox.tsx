// The Inbox tab: everything waiting for the phone's Face ID that was asked for elsewhere (a session, the web page,
// Claude's setup session) — requests (repo keys, grants, unlocks) and the router's approvals (new session, resume on
// the latest image, add a store). Each card: the action as its title (what will be signed, in short), who called
// which endpoint, and the caller's own reason (their words, unverified). Review opens the shell's secure page,
// which renders what is signed from the signed content itself; Deny drops it. The web page lists them and can deny.
import { View } from "react-native";
import { ago, when, type InboxItem } from "../lib/api";
import { denyRequest, inboxAction, inboxCall } from "../lib/inbox";
import { useStore, refresh, settle, pendUntil } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Box, Button, Card, Flex, Heading, Lbl, Muted, P, Pill, Text } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { useTheme } from "../theme";

const KIND: Record<string, string> = { "repo-key": "Repo key", grant: "Grant", unlock: "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "add-store": "Add a store" };

/** open the entry's secure page; once it went through (or was denied there) the Inbox refreshes */
export function reviewRequest(it: InboxItem) {
  requestSecure(it.open.kind as any, { ...it.open.options, inboxId: it.id }, (r) => { if (r.result === "done") { refresh(false); settle(60000); } });
}

function RequestCard({ it }: { it: InboxItem }) {
  const t = useTheme();
  const approvals = useStore((s) => s.state.approvals), policy = useStore((s) => s.policy);
  const deny = () => pendUntil("q:" + it.id, "Denying…", () => denyRequest(it), (s) => !(s.inbox || []).some((x) => x.id === it.id), 30000);
  return (
    <Card data={{ request: it.id, requestKind: it.kind }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }} id={"request-title-" + it.id}>{inboxAction(it, approvals, policy)}</Heading>
        <Pill kind="info">{KIND[it.kind] || it.kind}</Pill>
      </Flex>
      <Muted id={"request-from-" + it.id}>{"From " + it.callerText + " · " + ago(it.created)}</Muted>
      <Text size={1} mono style={{ color: t.gray.a[11], marginTop: 2 }} lines={2}>{inboxCall(it)}</Text>
      {!!it.explanation && <View style={{ borderLeftWidth: 2, borderLeftColor: t.c.amber.a[6], paddingLeft: 8, marginTop: 8 }}>
        <Text size={1} style={{ color: t.c.amber.a[11] }}>{"Reason given (unverified)"}</Text>
        <P size={2} color="gray" lines={2} style={{ fontStyle: "italic" }} id={"request-reason-" + it.id}>{it.explanation}</P>
      </View>}
      {!!it.expires && <Muted mt={1}>{"Goes away " + when(it.expires) + " if not answered"}</Muted>}
      <Flex gap={2} pt={3}>
        {hasShell ? <Button id={"request-review-" + it.id} onPress={() => reviewRequest(it)}>Review</Button>
          : <Muted style={{ flex: 1 }}>Approve it in the Jarvis 2 app on the iPhone.</Muted>}
        <PButton pkey={"q:" + it.id} variant="soft" color="gray" onPress={deny} label="Deny" id={"request-deny-" + it.id} />
      </Flex>
    </Card>
  );
}

export function Inbox() {
  const items = useStore((s) => s.state.inbox) || [];
  if (!items.length) return <P size={3} color="gray" align="center" mt={8} mb={8} id="inbox-empty">Nothing waiting for you.</P>;
  return (
    <Box data={{ group: "Inbox" }}>
      <P size={2} color="gray" mb={2}>{"Asked for by sessions, the web page or Claude. Review shows exactly what you would sign; nothing happens until you allow it with Face ID."}</P>
      <Lbl>{items.length === 1 ? "1 request" : `${items.length} requests`}</Lbl>
      <Cards>{items.map((it) => <RequestCard key={it.id} it={it} />)}</Cards>
    </Box>
  );
}

/** the line at the top of Sessions while anything waits */
export function InboxNote({ onOpen }: { onOpen: () => void }) {
  const n = (useStore((s) => s.state.inbox) || []).length;
  if (!n) return null;
  return <Flex mb={3}><Button id="inbox-note" variant="soft" onPress={onOpen}>{n === 1 ? "1 request waiting in the Inbox →" : `${n} requests waiting in the Inbox →`}</Button></Flex>;
}
