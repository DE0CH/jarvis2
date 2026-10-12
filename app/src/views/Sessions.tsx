import { useRef } from "react";
import { Linking, View } from "react-native";
import { api, ago, isTaskLine, challengeRequest, cronEvery, holderTitle, HOLDERS, HARNESS, REGION, sessionTitle, storesOf, when, type Approval, type Session, type State } from "../lib/api";
import { useStore, setTab, getStore, pend, refresh, refreshUntil, pendUntil, settle, ask, askText, toast, failed, exclusive, BUSY_LABEL } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { requestGrant } from "../lib/grants";
import { canCopy, copyText } from "../lib/clipboard";
import { BadgeList, Box, Button, Callout, Card, Flex, Heading, Lbl, Muted, P, Pill, Quote, Row, Rows } from "../ui/kit";
import type { AskRow } from "../lib/store";
import { BusyButton, PButton, useCoolAfterShift } from "../ui/bits";
import { Cards } from "../ui/cards";
import { InboxNote } from "./Inbox";
import { openPage } from "../ui/page";
import { openMenu, type MenuItem } from "../ui/overlays";

const find = (s: State, id: string) => s.sessions.find((x) => x.id === id);
const MOVING: Record<string, string> = { starting: "starting…", approval: "waiting for approval", initialising: "initialising…", pausing: "pausing…", resuming: "resuming…", destroying: "destroying…" };
const hasSchedule = (m: Session) => !!(m.wakeups || []).length || !!(m.crons || []).length;
const clip = (t: string) => t.length > 90 ? t.slice(0, 90) + "…" : t;

// what the router is doing to this session right now (its lifecycle lock, or a mode / restart job), as a
// button label — seen on every device, not only the one that started it
export function serverBusy(m: Session): string | null {
  if (m.busy) return BUSY_LABEL[m.busy.kind] || "Working…";
  if (m.wake && !["done", "failed"].includes(m.wake.phase)) return BUSY_LABEL[m.wake.kind] || "Working…";
  return null;
}
// sessions the Claude app does not see: their primary action is the Remote page
const hasRemote = (m: Session) => m.harness === "opencode" || m.harness === "openclaw";
function SessionPill({ m }: { m: Session }) {
  const sb = serverBusy(m);
  if (sb && m.state !== "destroying") return <Pill kind="wait" spin>{sb.toLowerCase()}</Pill>;
  if (m.state === "failed") return <Pill kind="bad">failed</Pill>;
  if (m.state === "paused") return hasSchedule(m) ? <Pill kind="info">scheduled</Pill> : <Pill kind="dim">paused</Pill>;
  if (m.state === "approval") return <Pill kind="info">needs approval</Pill>;
  if (MOVING[m.state]) return <Pill kind={m.state === "destroying" ? "bad" : "wait"} spin>{m.waiting ? `${m.state}: ${m.waiting}` : MOVING[m.state]}</Pill>;
  if (m.state === "started") {
    if (m.oneShotDone) return <Pill kind="wait" spin>done · archiving…</Pill>;
    if (!m.status) return <Pill kind="wait" spin>booting…</Pill>;
    if (m.status === "busy") return <Pill kind="wait">working</Pill>;
    if (m.status === "waiting") return <Pill kind="bad">needs you</Pill>;
    if (m.status === "idle") return m.bgTasks ? <Pill kind="wait">{`idle · ${m.bgTasks} background`}</Pill> : <Pill kind="ok">idle</Pill>;
    return <Pill kind="ok">{m.status}</Pill>;
  }
  return <Pill kind="dim">{m.state}</Pill>;
}
// the headed sections: a paused session that will wake on its own is not "just paused"
const GROUPS = ["Running", "Scheduled", "Paused", "Failed"] as const;
const groupOf = (m: Session): typeof GROUPS[number] => m.state === "paused" ? (hasSchedule(m) ? "Scheduled" : "Paused") : m.state === "failed" ? "Failed" : "Running";

// ---- actions (never optimistic: the pending label stays until the router confirms) ----
const pause = (id: string) => pendUntil("s:" + id, "Pausing…", () => api("POST", `api/sessions/${id}/pause`), (s) => find(s, id)?.state === "paused" || find(s, id)?.state === "failed", 120000);
// the optional prompt of a Resume: delivered as a message once the session is up again
export const RESUME_PROMPT = { label: "Prompt (optional)", placeholder: "Sent once it is back", max: 4000 };
export const resumeSession = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const prompt = await askText({ title: "Resume session?", rows: [{ label: "Session", value: m ? sessionTitle(m) : id }], detail: "Same conversation and files, on a new machine.", action: "Resume", input: { heading: "Resume", ...RESUME_PROMPT } });
  if (prompt === null) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: false, ...(prompt ? { prompt } : {}) });
    // a resume in another permission mode than the line's cert is a change the iPhone approves (signed)
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.kind === "resume-upgrade" && x.session === id)) || ["started", "initialising", "failed"].includes(find(s, id)?.state || ""), 120000);
    if (a) review(a);
    settle(30000);
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});

/** Open an approval on the shell's secure page (the app); the web page only points to the app. */
export function review(a: Approval) {
  if (!hasShell) { toast("Approvals happen in the Jarvis 2 app on the iPhone."); return; }
  requestSecure("approval", { approvalId: a.id }, (r) => { if (r.result === "done") { refresh(false); settle(60000); } });
}
// resume on the newest image: the router asks for an approval first
const upgrade = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const ok = await ask({ title: "Resume with the latest image?", rows: [{ label: "Session", value: m ? sessionTitle(m) : id }, { label: "Old machine", value: "Burned" }, { label: "Approval", value: "On the iPhone" }], action: "Resume with latest image" });
  if (!ok) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: true });
    let a: Approval | undefined;
    await refreshUntil((s) => !!(a = s.approvals.find((x) => x.kind === "resume-upgrade" && x.session === id)) || find(s, id)?.state === "failed", 90000);
    if (a) review(a); else if (hasShell) toast("No approval appeared yet — it will show in the Inbox when it does.");
  } catch (e: any) { failed(e); }
  finally { pend("s:" + id, null); }
});

// Destroy: first what would be lost (GET …/changes: uncommitted / unpushed work), then the destroy itself —
// the router pauses a running session (its final snapshot), archives it to the Storage Box and burns the line.
// A failed archive leaves it paused with "archive: …"; then the question is whether to destroy anyway.
async function changesRows(id: string): Promise<AskRow[]> {
  try {
    const c = await api<any>("GET", `api/sessions/${id}/changes`);
    if (!c.checked) return [{ label: "Unsaved work", value: "Not checked", id: "changes-unchecked" }, ...(c.reason ? [{ label: "Reason", value: String(c.reason) }] : [])];
    const rows: AskRow[] = [];
    if (c.status === "busy") rows.push({ label: "Claude", value: "Working", id: "changes-busy" });
    const dirty = (c.repos || []).filter((r: any) => r.uncommitted > 0 || r.unpushed > 0 || r.unpushed === -1);
    for (const r of dirty) {
      if (r.uncommitted > 0) rows.push({ label: "Uncommitted", value: `${r.name}: ${r.uncommitted}` });
      if (r.unpushed > 0) rows.push({ label: "Unpushed", value: `${r.name}: ${r.unpushed}` });
      if (r.unpushed === -1) rows.push({ label: "No upstream", value: r.name });
    }
    if (!dirty.length) rows.push({ label: "Unsaved work", value: c.paused ? "None (at pause)" : "None", id: "changes-none" });
    return rows;
  } catch (e: any) { return [{ label: "Unsaved work", value: "Not checked", id: "changes-unchecked" }, { label: "Error", value: e.message }]; }
}
export const destroySession = (id: string) => exclusive("s:" + id, async () => {
  pend("s:" + id, "Checking…");
  const m = find(getStore().state, id);
  const rows = [{ label: "Session", value: m ? sessionTitle(m) : id }, ...(await changesRows(id)), { label: "Archived first", value: "Transcripts, ~/artifacts" }];
  const ok = await ask({ title: "Destroy session?", rows, detail: "It can't be resumed afterwards.", action: "Destroy session", danger: true });
  pend("s:" + id, null);
  if (!ok) return;
  pend("s:" + id, "Destroying…");
  try {
    await api("POST", `api/sessions/${id}/destroy`);
    await refreshUntil((s) => { const x = find(s, id); return !x || (x.state !== "destroying" && !!x.error?.startsWith("archive:")); }, 15 * 60 * 1000);
    const x = find(getStore().state, id);
    if (x && x.error?.startsWith("archive:")) {
      if (await ask({ title: "Archiving failed", rows: [{ label: "Error", value: x.error }, { label: "If destroyed", value: "Transcript and artifacts lost" }], action: "Destroy anyway", danger: true })) {
        await api("POST", `api/sessions/${id}/destroy?force=1`);
        await refreshUntil((s) => !find(s, id), 10 * 60 * 1000);
      }
    }
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
// Permission mode (signed in the line's cert). Running: switched in place; raising to bypass needs a fresh
// phone grant for the terminal feature, so a 403 {phoneGrant} opens the grant page and the switch runs again
// once it is signed. Paused: kept for the next resume, which the iPhone approves.
export const switchMode = (m: Session, mode: "auto" | "bypass") => exclusive("s:" + m.id, async () => {
  const title = sessionTitle(m);
  if (!(await ask({ title: "Switch permission mode?", rows: [
    { label: "Session", value: title },
    { label: "Mode", value: mode === "bypass" ? "Bypass (no prompts)" : "Auto (classifier)" },
    { label: "Applies", value: m.state === "paused" ? "At the next resume" : "Now (Claude relaunches)" },
    ...(mode === "bypass" ? [{ label: "Approval", value: "On the iPhone" }] : []),
  ], action: "Switch", danger: mode === "bypass" }))) return;
  const run = async (): Promise<void> => {
    pend("s:" + m.id, "Switching mode…");
    try {
      const j = await api<any>("POST", `api/sessions/${m.id}/permission-mode`, { mode });
      if (j.nextStart) { toast("Applies at the next resume.", "ok"); await refresh(false); return; }
      await refreshUntil((s) => { const x = find(s, m.id); return !!x && x.permissionMode === mode && !serverBusy(x); }, 120000);
    } catch (e: any) {
      if (e.status === 403 && e.body?.needsGrant && hasShell) {
        pend("s:" + m.id, null);
        requestGrant(m.id, title, { holder: e.body.needsGrant, kind: "grant", minutes: 10 }, (ok) => { if (ok) exclusive("s:" + m.id, run); });
        return;
      }
      failed(e); await refresh(false);
    } finally { pend("s:" + m.id, null); }
  };
  await run();
});
// the two switches: two-phase, the menu item shows the router's value
const toggle = (m: Session, what: "auto-pause" | "notify-idle", on: boolean) =>
  pendUntil("s:" + m.id, on ? "Turning on…" : "Turning off…", () => api("POST", `api/sessions/${m.id}/${what}`, { on }),
    (s) => (what === "auto-pause" ? find(s, m.id)?.autoPause : find(s, m.id)?.notifyIdle) === (on ? "on" : "off"), 20000);

function menuItems(m: Session): MenuItem[] {
  const items: MenuItem[] = [];
  const live = !["approval", "destroying"].includes(m.state);
  if (live) items.push({ label: "Grants…", sub: "Which features may run commands in it", onClick: () => openPage("grants", { id: m.id }) });
  if (live) items.push({ label: "Schedules…", sub: "Wakeups and crons", onClick: () => openPage("schedules", { id: m.id }) });
  if (!m.oneShot && live) items.push({ label: "Auto-pause when idle", sub: "Pause after 1 h with nothing running", checked: m.autoPause !== "off", onClick: () => toggle(m, "auto-pause", m.autoPause === "off") });
  if (live) items.push({ label: "Idle notifications", sub: "A Discord DM when it sits idle", checked: m.notifyIdle !== "off", onClick: () => toggle(m, "notify-idle", m.notifyIdle === "off") });
  if (m.state === "started" || m.state === "paused") items.push(m.permissionMode === "bypass"
    ? { label: "Switch to auto mode", sub: "Permission prompts gated by the classifier", onClick: () => switchMode(m, "auto") }
    : { label: "Switch to bypass mode", sub: "No permission prompts; the iPhone allows it", onClick: () => switchMode(m, "bypass") });
  if (m.state === "paused") items.push({ label: "Resume with latest image", sub: "Newest session image; the iPhone approves", onClick: () => upgrade(m.id) });
  if (canCopy) items.push({ label: "Copy session id", sub: m.id, onClick: () => copyText(m.id).then(() => toast("Session id copied", "ok"), (e) => failed(e, "Could not copy: ")) });
  items.push({ label: "Destroy", sub: "Archive transcripts + ~/artifacts, then burn the machine", danger: true, onClick: () => destroySession(m.id) });
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

// what will wake this session, one line each
function Schedules({ m }: { m: Session }) {
  if (!hasSchedule(m)) return null;
  return (
    <Callout color="blue" variant="surface" mt={2} data={{ schedules: "1" }}>
      {(m.wakeups || []).map((w) => <Box key={"w" + w.name}>
        <Rows><Row label="Wakeup">{w.name}</Row><Row label="At">{when(w.at)}</Row></Rows>
        <Quote by="Prompt" color="blue" lines={2}>{clip(w.prompt)}</Quote>
      </Box>)}
      {(m.crons || []).map((c) => <Box key={"c" + c.name}>
        <Rows><Row label="Cron">{c.name}</Row><Row label="Repeats">{cronEvery(c.everySeconds)}</Row><Row label="Next">{when(c.nextAt)}</Row></Rows>
        <Quote by="Prompt" color="blue" lines={2}>{clip(c.prompt)}</Quote>
      </Box>)}
    </Callout>
  );
}
// a feature the machine turned away: one tap to allow it for 10 minutes, or a standing rule
function NeedsGrant({ m }: { m: Session }) {
  if (!m.needsGrant) return null;
  const h = m.needsGrant, title = sessionTitle(m);
  return (
    <Callout color="amber" mt={2} data={{ needsGrant: h }}>
      <P size={2} weight="bold" color="amber">Feature turned away</P>
      <Rows id={"needs-grant-" + m.id}>
        <Row label="Feature" id={"needs-grant-feature-" + m.id}>{holderTitle(h)}</Row>
        {!!HOLDERS[h]?.sub && <Row label="Does">{HOLDERS[h].sub}</Row>}
      </Rows>
      <Flex gap={2} mt={2} wrap>
        <Button size={1} id={"grant-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "grant", minutes: 10 })}>Allow 10 min</Button>
        <Button size={1} variant="soft" id={"rule-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "rule" })}>Standing rule</Button>
      </Flex>
    </Callout>
  );
}
// the machine is waiting at boot on a store that is locked: the unlock review page (Allow / Deny) one tap away
export function LockedStore({ m, compact }: { m: Session; compact?: boolean }) {
  if (!m.lockedStore) return null;
  const title = sessionTitle(m);
  const open = () => requestSecure("unlock", { sessionId: m.id, label: title }, (r) => { if (r.result === "done") { refresh(false); settle(30000); } });
  return (
    <Callout color="amber" mt={compact ? 0 : 2} data={{ lockedStore: m.lockedStore }}>
      <P size={2} weight="bold" color="amber">Waiting for unlock</P>
      <Rows><Row label="Store" id={"locked-store-" + m.id}>{m.lockedStore}</Row></Rows>
      <Flex gap={2} mt={2} wrap><Button size={1} id={"unlock-" + m.id} onPress={open}>{hasShell ? "Unlock…" : "Ask the iPhone to unlock"}</Button></Flex>
    </Callout>
  );
}
const DISCORD_GUILD = "1482150592414486748"; // the router's DISCORD_GUILD_ID default (router/discord.go)
const openDiscord = (ch: string) => Linking.openURL(`https://discord.com/channels/${DISCORD_GUILD}/${ch}`).catch((e) => failed(e, "Could not open Discord: "));

export function Sessions() {
  const sessions = useStore((s) => s.state.sessions);
  const approvals = useStore((s) => s.state.approvals);
  const pending = useStore((s) => s.pending);
  const policy = useStore((s) => s.policy);
  const models = useStore((s) => s.models);
  // within each group newest-first, so cards never swap between polls
  // task lines show in the Tasks tab
  const list = [...sessions].filter((m) => !isTaskLine(m)).sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")) || a.id.localeCompare(b.id));
  const cool = useCoolAfterShift(list.map((m) => m.id).join("|"));
  if (!list.length && !approvals.length) return <><InboxNote onOpen={() => setTab("inbox")} /><P size={3} color="gray" align="center" mt={8} mb={8} id="sessions-empty">No sessions.</P><FlyAccountSection /></>;
  return (
    <>
      {/* what waits for the phone is in the Inbox tab (views/Inbox.tsx); one line here points there */}
      <InboxNote onOpen={() => setTab("inbox")} />
      {GROUPS.map((g) => {
        const inGroup = list.filter((m) => groupOf(m) === g);
        if (!inGroup.length) return null;
        return <Box key={g} data={{ group: g }}><Lbl>{g}</Lbl><Cards>
          {inGroup.map((m) => {
            const busy = pending.get("s:" + m.id) || serverBusy(m);
            const moving = !!MOVING[m.state] && m.state !== "initialising";
            const paused = m.state === "paused";
            const own = storesOf(m, policy);
            const modelName = models.find((x) => x.id === m.model)?.label || m.model;
            // auto-pause: off / counting down / the default (a running, non-one-shot session only)
            const autoPause = m.oneShot || m.state !== "started" ? "" : m.autoPause === "off" ? "Off"
              : m.pauseInMs != null ? `In ${Math.max(1, Math.round(m.pauseInMs / 60000))} min` : "After 1 h idle";
            return (
              <Card key={m.id} dim={!!busy} data={{ session: m.id }} style={{ flex: 1 }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                  <Heading size={3} style={{ flex: 1 }}>{sessionTitle(m)}</Heading>
                  <Flex gap={1} wrap justify="flex-end" style={{ flexShrink: 0, maxWidth: "55%" }}><SessionPill m={m} />{!paused && hasSchedule(m) && <Pill kind="info">scheduled</Pill>}</Flex>
                </Flex>
                {(m.permissionMode === "bypass" || m.oneShot || m.authFailed) && <Flex gap={1} wrap align="center" mb={1}>
                  {m.permissionMode === "bypass" ? <Pill kind="bad">skip perms</Pill> : null}
                  {m.oneShot && <Pill kind="dim">one-shot</Pill>}
                  {m.authFailed && <Pill kind="bad">login failed</Pill>}
                </Flex>}
                <Rows id={"session-rows-" + m.id}>
                  <Row label="Stores"><BadgeList items={own} /></Row>
                  {!!(HARNESS[m.harness || ""] || m.harness) && <Row label="Harness">{HARNESS[m.harness || ""] || m.harness}</Row>}
                  {!!modelName && <Row label="Model">{modelName}</Row>}
                  {!!(m.region || m.guest) && <Row label="Machine">{[REGION[m.region || ""] || m.region, m.guest].filter(Boolean).join(" · ")}</Row>}
                  {!!m.created && <Row label="Created">{ago(m.created)}</Row>}
                  {paused && !!m.pausedAt && <Row label="Paused">{ago(m.pausedAt)}</Row>}
                  {!!autoPause && <Row label="Auto-pause" id={"autopause-" + m.id}>{autoPause}</Row>}
                </Rows>
                {!!m.resumePrompt && <Quote by={paused ? "Queued for the next resume" : "Queued prompt"} lines={3}>{clip(m.resumePrompt)}</Quote>}
                <NeedsGrant m={m} />
                <LockedStore m={m} />
                <Schedules m={m} />
                {!!m.error && <P size={2} color="red" mt={1}>{m.error}</P>}
                {!!m.discordChannel && <Flex mt={1}><Button size={1} variant="ghost" color="gray" id={"discord-" + m.id} onPress={() => openDiscord(m.discordChannel!)}>Discord channel ↗</Button></Flex>}
                <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }} data={{ actions: "1" }}>
                  {busy ? <BusyButton variant="soft" color="gray" label={busy} />
                    : moving ? null
                    : <>
                      {m.state === "started" && hasRemote(m) ? <Button id={"remote-" + m.id} onPress={() => openPage("remote", { id: m.id, title: sessionTitle(m) })}>Remote</Button>
                        : (m.state === "started" || m.state === "initialising") && <Button id={"term-" + m.id} onPress={() => openPage("terminal", { id: m.id, title: sessionTitle(m) })}>Terminal</Button>}
                      {(m.state === "started" || m.state === "initialising") && <PButton pkey={"s:" + m.id} id={"pause-" + m.id} variant="soft" onPress={() => pause(m.id)} label="Pause" />}
                      {paused && <PButton pkey={"s:" + m.id} id={"resume-" + m.id} color="green" onPress={() => resumeSession(m.id)} label="Resume" />}
                      {paused && <Button variant="soft" color="gray" id={"tail-" + m.id} onPress={() => openPage("transcript", { title: sessionTitle(m), note: "Paused " + (m.pausedAt ? ago(m.pausedAt) : ""), path: `api/sessions/${m.id}/tail`, action: { label: "Resume", run: () => resumeSession(m.id) } })}>Transcript</Button>}
                      <MoreButton m={m} cool={cool} />
                    </>}
                </Flex>
              </Card>
            );
          })}
        </Cards></Box>;
      })}
      <FlyAccountSection />
    </>
  );
}

// Everything on the Fly app that is not one of the sessions above — view only. The summary line is always
// there, so "nothing else is running" is something the page SAYS, not an absence.
export function FlyAccountSection() {
  const fly = useStore((s) => s.state.fly);
  if (!fly) return null;
  const other = fly.other || [];
  return (
    <Box id="fly-account" style={{ marginTop: 24 }}>
      {other.length > 0 && (
        <>
          <Heading size={3} mb={1}>Also on Fly</Heading>
          <Muted>Not sessions; in the sessions' Fly app.</Muted>
          <Cards mt={12}>
            {other.map((o) => (
              <Card key={o.kind + ":" + o.app + ":" + o.id} data={{ flyOther: o.kind }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}><Heading size={3} style={{ flex: 1 }}>{o.name || o.id}</Heading><Pill kind={o.state === "started" || o.kind === "volume" ? "wait" : "dim"}>{o.state || o.kind}</Pill></Flex>
                <Rows>
                  <Row label="Kind">{o.kind}</Row>
                  <Row label="App">{o.app}</Row>
                  {!!o.name && <Row label="Id" mono>{o.id}</Row>}
                  {!!o.detail && <Row label="Detail">{o.detail}</Row>}
                  {!!o.region && <Row label="Region">{REGION[o.region] || o.region}</Row>}
                  {!!o.created && <Row label="Created">{ago(o.created)}</Row>}
                </Rows>
              </Card>
            ))}
          </Cards>
        </>
      )}
      <Lbl>Fly app</Lbl>
      <Rows id="fly-summary">
        {fly.error ? <Row label="Not checked" color="red">{fly.error}</Row> : <>
          <Row label="Machines" id="fly-summary-machines">{String(fly.machines)}</Row>
          <Row label="Volumes" id="fly-summary-volumes">{String(fly.volumes)}</Row>
          <Row label="Not sessions" id="fly-summary-other">{String(other.length)}</Row>
        </>}
      </Rows>
    </Box>
  );
}
