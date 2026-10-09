import { useRef } from "react";
import { View } from "react-native";
import { api, ago, challengeRequest, HARNESS, REGION, sessionTitle, storesOf, type Approval, type Session, type State } from "../lib/api";
import { useStore, getStore, pend, refresh, refreshUntil, pendUntil, settle, ask, toast, failed, exclusive } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Box, Button, Callout, Card, Flex, Heading, Lbl, Muted, P, Pill } from "../ui/kit";
import { BusyButton, PButton, useCoolAfterShift } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openMenu, mouse, type MenuItem } from "../ui/overlays";

const find = (s: State, id: string) => s.sessions.find((x) => x.id === id);
const MOVING: Record<string, string> = { starting: "starting…", approval: "waiting for approval", initialising: "initialising…", pausing: "pausing…", resuming: "resuming…", destroying: "destroying…" };

function SessionPill({ m }: { m: Session }) {
  if (m.state === "failed") return <Pill kind="bad">failed</Pill>;
  if (m.state === "paused") return <Pill kind="dim">paused</Pill>;
  if (m.state === "approval") return <Pill kind="info">needs approval</Pill>;
  if (MOVING[m.state]) return <Pill kind={m.state === "destroying" ? "bad" : "wait"} spin>{MOVING[m.state]}</Pill>;
  if (m.state === "started") {
    if (m.status === "busy") return <Pill kind="wait">working</Pill>;
    if (m.status === "waiting") return <Pill kind="bad">needs you</Pill>;
    return m.status ? <Pill kind="ok">{m.status}</Pill> : <Pill kind="ok">running</Pill>;
  }
  return <Pill kind="dim">{m.state}</Pill>;
}
const GROUPS = ["Running", "Paused", "Failed"] as const;
const groupOf = (m: Session): typeof GROUPS[number] => m.state === "paused" ? "Paused" : m.state === "failed" ? "Failed" : "Running";

// ---- actions (never optimistic: the pending label stays until the router confirms) ----
const pause = (id: string) => pendUntil("s:" + id, "Pausing…", () => api("POST", `api/sessions/${id}/pause`), (s) => find(s, id)?.state === "paused" || find(s, id)?.state === "failed", 120000);
const resume = (id: string) => pendUntil("s:" + id, "Resuming…", () => api("POST", `api/sessions/${id}/resume`, { upgrade: false }), (s) => ["started", "initialising", "failed"].includes(find(s, id)?.state || ""), 120000).then(() => settle(30000));

/** Open an approval on the shell's secure page (the app); the web page only points to the app. */
export function review(a: Approval) {
  if (!hasShell) { toast("Approvals happen in the Jarvis 2 app on the iPhone."); return; }
  requestSecure("approval", { approvalId: a.id }, (r) => { if (r.result === "done") { refresh(false); settle(60000); } });
}
// resume on the newest image: the router burns the old machine and asks for an approval
const upgrade = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const ok = await ask({ title: `Resume “${m ? sessionTitle(m) : id}” with the latest image?`, detail: "Starts the newest session image. The old machine is burned (it can never be resumed as it was), and the iPhone approves the new one.", action: "Resume with latest image" });
  if (!ok) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: true });
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.kind === "resume-upgrade" && x.session === id)) || find(s, id)?.state === "failed", 90000);
    if (a) review(a); else if (hasShell) toast("No approval appeared yet — it will show at the top of the list when it does.");
  } catch (e: any) { failed(e); }
  finally { pend("s:" + id, null); }
});
const destroy = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const ok = await ask({ title: `Destroy “${m ? sessionTitle(m) : id}”?`, detail: "Kills the machine (if running) and burns it: the session can never be resumed. It moves to Records.", action: "Destroy session", danger: true });
  if (!ok) return;
  pend("s:" + id, "Destroying…");
  try { await api("POST", `api/sessions/${id}/destroy`); await refreshUntil((s) => !find(s, id), 120000); }
  catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
const reject = (a: Approval) => pendUntil("a:" + a.id, "Rejecting…", () => api("POST", `api/approvals/${a.id}/reject`), (s) => !s.approvals.some((x) => x.id === a.id), 30000);

function menuItems(m: Session): MenuItem[] {
  const items: MenuItem[] = [];
  if (m.state === "paused") items.push({ label: "Resume with latest image", sub: "Newest session image; the iPhone approves", onClick: () => upgrade(m.id) });
  items.push({ label: "Destroy", sub: "Kill + burn the machine; the session moves to Records", danger: true, onClick: () => destroy(m.id) });
  return items;
}
function MoreButton({ m, cool }: { m: Session; cool: boolean }) {
  const ref = useRef<View>(null);
  return (
    <View ref={ref} collapsable={false}>
      <Button variant="soft" color="gray" disabled={cool} style={cool ? { opacity: 0.3 } : undefined} label="More actions" id={"more-" + m.id} onPress={() => openMenu(ref.current, menuItems(m))}>More ▾</Button>
    </View>
  );
}

const KIND_TITLE: Record<string, string> = { "new-session": "New session", "resume-upgrade": "Resume on the latest image", "add-store": "Add a store" };
function ApprovalCard({ a }: { a: Approval }) {
  const r = challengeRequest(a, useStore((s) => s.policy));
  const what = a.kind === "add-store" ? `Add ${r.addedStore || "?"}` : `Stores: ${r.stores.join(", ") || "none"} · ${HARNESS[r.harness] || r.harness}`;
  return (
    <Card data={{ approval: a.id }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }}>{a.label || KIND_TITLE[a.kind] || a.kind}</Heading>
        <Pill kind="info">{KIND_TITLE[a.kind] || a.kind}</Pill>
      </Flex>
      <Muted>{what}{a.created ? " · asked " + ago(a.created) : ""}</Muted>
      {r.sensitive.length > 0 && <Callout color="amber" mt={2}>{"Includes sensitive stores: " + r.sensitive.join(", ")}</Callout>}
      <Flex gap={2} pt={3}>
        {hasShell ? <Button id={"review-" + a.id} onPress={() => review(a)}>Review</Button> : <Muted style={{ flex: 1 }}>Approve it in the Jarvis 2 app on the iPhone.</Muted>}
        <PButton pkey={"a:" + a.id} variant="soft" color="gray" onPress={() => reject(a)} label="Reject" id={"reject-" + a.id} />
      </Flex>
    </Card>
  );
}

export function Sessions() {
  const sessions = useStore((s) => s.state.sessions);
  const approvals = useStore((s) => s.state.approvals);
  const pending = useStore((s) => s.pending);
  const policy = useStore((s) => s.policy);
  // within each group newest-first, so cards never swap between polls
  const list = [...sessions].sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")) || a.id.localeCompare(b.id));
  const cool = useCoolAfterShift(list.map((m) => m.id).join("|"));
  if (!list.length && !approvals.length) return <P size={3} color="gray" align="center" mt={8} mb={8}>{"No sessions.\n" + (mouse() ? "Click" : "Tap") + " “New session”."}</P>;
  return (
    <>
      {approvals.length > 0 && <Box data={{ group: "Approvals" }}><Lbl>Waiting for you</Lbl><Cards>{approvals.map((a) => <ApprovalCard key={a.id} a={a} />)}</Cards></Box>}
      {GROUPS.map((g) => {
        const inGroup = list.filter((m) => groupOf(m) === g);
        if (!inGroup.length) return null;
        return <Box key={g} data={{ group: g }}><Lbl>{g}</Lbl><Cards>
          {inGroup.map((m) => {
            const busy = pending.get("s:" + m.id) || null;
            const moving = !!MOVING[m.state] && m.state !== "initialising";
            const own = storesOf(m, policy);
            const line1 = [own.length ? "stores: " + own.join(", ") : "no stores", HARNESS[m.harness || ""] || m.harness, m.model].filter(Boolean).join(" · ");
            return (
              <Card key={m.id} dim={!!busy} data={{ session: m.id }} style={{ flex: 1 }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                  <Heading size={3} style={{ flex: 1 }}>{sessionTitle(m)}</Heading>
                  <SessionPill m={m} />
                </Flex>
                <Muted>{line1}</Muted>
                <Muted>{[REGION[m.region || ""] || m.region || "", m.guest || "", m.created ? "created " + ago(m.created) : "", m.pausedAt && m.state === "paused" ? "paused " + ago(m.pausedAt) : ""].filter(Boolean).join(" · ")}</Muted>
                {m.permissionMode === "bypass" && <Flex mt={1}><Pill kind="bad">skip perms</Pill></Flex>}
                {!!m.error && <P size={2} color="red" mt={1}>{m.error}</P>}
                <Flex gap={2} pt={3} style={{ marginTop: "auto" }} data={{ actions: "1" }}>
                  {busy ? <BusyButton variant="soft" color="gray" label={busy} />
                    : moving ? null
                    : <>
                      {(m.state === "started" || m.state === "initialising") && <PButton pkey={"s:" + m.id} id={"pause-" + m.id} variant="soft" onPress={() => pause(m.id)} label="Pause" />}
                      {m.state === "paused" && <PButton pkey={"s:" + m.id} id={"resume-" + m.id} color="green" onPress={() => resume(m.id)} label="Resume" />}
                      <MoreButton m={m} cool={cool} />
                    </>}
                </Flex>
              </Card>
            );
          })}
        </Cards></Box>;
      })}
    </>
  );
}
