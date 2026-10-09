import { useRef } from "react";
import { Linking, View } from "react-native";
import { api, ago, challengeRequest, cronEvery, holderTitle, HOLDERS, HARNESS, REGION, sessionTitle, storesOf, when, type Approval, type Session, type State } from "../lib/api";
import { useStore, getStore, pend, refresh, refreshUntil, pendUntil, settle, ask, askText, toast, failed, exclusive } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { requestGrant } from "../lib/grants";
import { Box, Button, Callout, CalloutText, Card, Flex, Heading, Lbl, Muted, P, Pill, Text } from "../ui/kit";
import { BusyButton, PButton, useCoolAfterShift } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";
import { openMenu, mouse, type MenuItem } from "../ui/overlays";

const find = (s: State, id: string) => s.sessions.find((x) => x.id === id);
const MOVING: Record<string, string> = { starting: "starting…", approval: "waiting for approval", initialising: "initialising…", pausing: "pausing…", resuming: "resuming…", destroying: "destroying…" };
const hasSchedule = (m: Session) => !!(m.wakeups || []).length || !!(m.crons || []).length;
const clip = (t: string) => t.length > 90 ? t.slice(0, 90) + "…" : t;

function SessionPill({ m }: { m: Session }) {
  if (m.state === "failed") return <Pill kind="bad">failed</Pill>;
  if (m.state === "paused") return hasSchedule(m) ? <Pill kind="info">scheduled</Pill> : <Pill kind="dim">paused</Pill>;
  if (m.state === "approval") return <Pill kind="info">needs approval</Pill>;
  if (MOVING[m.state]) return <Pill kind={m.state === "destroying" ? "bad" : "wait"} spin>{MOVING[m.state]}</Pill>;
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
export const RESUME_PROMPT = { label: "Prompt (optional)", placeholder: "What Claude should do once it is back — delivered as a message. Leave blank to just bring it back.", max: 4000 };
export const resumeSession = (id: string) => exclusive("s:" + id, async () => {
  const m = find(getStore().state, id);
  const prompt = await askText({ title: `Resume “${m ? sessionTitle(m) : id}”?`, detail: "Continues the same conversation on a new machine with the same image, with the files as they were when it was paused.", action: "Resume", input: { heading: "Resume", ...RESUME_PROMPT } });
  if (prompt === null) return;
  pend("s:" + id, "Resuming…");
  try {
    await api("POST", `api/sessions/${id}/resume`, { upgrade: false, ...(prompt ? { prompt } : {}) });
    await refreshUntil((s) => ["started", "initialising", "failed"].includes(find(s, id)?.state || ""), 120000);
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

// Destroy: first what would be lost (GET …/changes: uncommitted / unpushed work), then the destroy itself —
// the router pauses a running session (its final snapshot), archives it to the Storage Box and burns the line.
// A failed archive leaves it paused with "archive: …"; then the question is whether to destroy anyway.
async function changesText(id: string): Promise<string> {
  let msg = "";
  try {
    const c = await api<any>("GET", `api/sessions/${id}/changes`);
    if (c.checked) {
      const dirty = (c.repos || []).filter((r: any) => r.uncommitted > 0 || r.unpushed > 0 || r.unpushed === -1);
      if (c.status === "busy") msg += "Claude is still working in this session.\n\n";
      if (dirty.length) {
        msg += "Unsaved work will be lost:\n" + dirty.map((r: any) => "• " + r.name + ": "
          + (r.uncommitted > 0 ? r.uncommitted + " uncommitted file(s)" : "")
          + (r.uncommitted > 0 && (r.unpushed > 0 || r.unpushed === -1) ? ", " : "")
          + (r.unpushed > 0 ? r.unpushed + " unpushed commit(s)" : r.unpushed === -1 ? "branch has no upstream (nothing pushed)" : "")).join("\n") + "\n";
      } else if (c.status !== "busy") msg += "No uncommitted or unpushed changes found" + (c.paused ? " (as of when it was paused)" : "") + ".\n";
    } else msg += "Could not check for unsaved changes (" + (c.reason || "unknown") + ").\n";
  } catch (e: any) { msg += "Could not check for unsaved changes (" + e.message + ").\n"; }
  return msg;
}
export const destroySession = (id: string) => exclusive("s:" + id, async () => {
  pend("s:" + id, "Checking…");
  const m = find(getStore().state, id);
  const msg = (await changesText(id)) + "\nThe transcripts and ~/artifacts are archived to the Storage Box first; then the machine is burned and the session can never be resumed. It moves to Previous. Your repos on GitHub are not affected.";
  const ok = await ask({ title: `Destroy “${m ? sessionTitle(m) : id}”?`, detail: msg, action: "Destroy session", danger: true });
  pend("s:" + id, null);
  if (!ok) return;
  pend("s:" + id, "Destroying…");
  try {
    await api("POST", `api/sessions/${id}/destroy`);
    await refreshUntil((s) => { const x = find(s, id); return !x || (x.state !== "destroying" && !!x.error?.startsWith("archive:")); }, 15 * 60 * 1000);
    const x = find(getStore().state, id);
    if (x && x.error?.startsWith("archive:")) {
      if (await ask({ title: "Archiving to the Storage Box failed", detail: x.error + "\n\nDestroy anyway? The transcript and artifacts will be lost.", action: "Destroy anyway", danger: true })) {
        await api("POST", `api/sessions/${id}/destroy?force=1`);
        await refreshUntil((s) => !find(s, id), 10 * 60 * 1000);
      }
    }
  } catch (e: any) { failed(e); await refresh(false); }
  finally { pend("s:" + id, null); }
});
const reject = (a: Approval) => pendUntil("a:" + a.id, "Rejecting…", () => api("POST", `api/approvals/${a.id}/reject`), (s) => !s.approvals.some((x) => x.id === a.id), 30000);
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
  if (m.state === "paused") items.push({ label: "Resume with latest image", sub: "Newest session image; the iPhone approves", onClick: () => upgrade(m.id) });
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

const KIND_TITLE: Record<string, string> = { "new-session": "New session", "resume-upgrade": "Resume on the latest image", "add-store": "Add a store" };
function ApprovalCard({ a }: { a: Approval }) {
  const r = challengeRequest(a, useStore((s) => s.policy));
  const restore = a.options && (a.options as any).restore;
  const what = a.kind === "add-store" ? `Add ${r.addedStore || "?"}` : `Stores: ${r.stores.join(", ") || "none"} · ${HARNESS[r.harness] || r.harness}`;
  return (
    <Card data={{ approval: a.id }}>
      <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
        <Heading size={3} style={{ flex: 1 }}>{a.label || KIND_TITLE[a.kind] || a.kind}</Heading>
        <Pill kind="info">{restore ? "Restore" : KIND_TITLE[a.kind] || a.kind}</Pill>
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

// what will wake this session, one line each
function Schedules({ m }: { m: Session }) {
  if (!hasSchedule(m)) return null;
  return (
    <Callout color="blue" variant="surface" mt={2} data={{ schedules: "1" }}>
      {(m.wakeups || []).map((w) => <CalloutText key={"w" + w.name} color="blue"><Text weight="medium">{`Wakes${w.name === "default" ? "" : " “" + w.name + "”"} ${when(w.at)}`}</Text> — “{clip(w.prompt)}”</CalloutText>)}
      {(m.crons || []).map((c) => <CalloutText key={"c" + c.name} color="blue"><Text weight="medium">{`Repeats ${cronEvery(c.everySeconds)}, next ${when(c.nextAt)}`}</Text> — “{clip(c.prompt)}”</CalloutText>)}
    </Callout>
  );
}
// a feature the machine turned away: one tap to allow it for 10 minutes, or a standing rule
function NeedsGrant({ m }: { m: Session }) {
  if (!m.needsGrant) return null;
  const h = m.needsGrant, title = sessionTitle(m);
  return (
    <Callout color="amber" mt={2} data={{ needsGrant: h }}>
      <CalloutText color="amber">{`The machine turned away ${holderTitle(h).toLowerCase()} (${HOLDERS[h]?.sub || "a router feature"}).`}</CalloutText>
      {hasShell ? <Flex gap={2} mt={2} wrap>
        <Button size={1} id={"grant-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "grant", minutes: 10 })}>{`Allow ${holderTitle(h).toLowerCase()} for 10 minutes`}</Button>
        <Button size={1} variant="soft" id={"rule-" + m.id} onPress={() => requestGrant(m.id, title, { holder: h, kind: "rule" })}>Make a standing rule</Button>
      </Flex> : <CalloutText color="amber">Allow it in the Jarvis 2 app on the iPhone.</CalloutText>}
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
  const list = [...sessions].sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")) || a.id.localeCompare(b.id));
  const cool = useCoolAfterShift(list.map((m) => m.id).join("|"));
  if (!list.length && !approvals.length) return <><P size={3} color="gray" align="center" mt={8} mb={8}>{"No sessions.\n" + (mouse() ? "Click" : "Tap") + " “New session”."}</P><FlyAccountSection /></>;
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
            const paused = m.state === "paused";
            const own = storesOf(m, policy);
            const modelName = models.find((x) => x.id === m.model)?.label || m.model;
            const line1 = [own.length ? "stores: " + own.join(", ") : "no stores", HARNESS[m.harness || ""] || m.harness, modelName].filter(Boolean).join(" · ");
            // auto-pause status line: off / counting down / generic; paused sessions explain Resume
            const apInfo = paused ? (hasSchedule(m) ? "Paused — the router resumes it on schedule; Resume brings it back now." : "Paused — Resume continues the same conversation.")
              : m.oneShot ? (m.state === "started" ? "One-shot — archived and destroyed by itself once its prompt is done." : "")
              : m.state === "started" ? (m.autoPause === "off" ? "Auto-pause off — stays running while idle."
                : m.pauseInMs != null ? `Pauses in ${Math.max(1, Math.round(m.pauseInMs / 60000))} min if still idle.` : "Auto-pauses after 1 h idle.") : "";
            return (
              <Card key={m.id} dim={!!busy} data={{ session: m.id }} style={{ flex: 1 }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}>
                  <Heading size={3} style={{ flex: 1 }}>{sessionTitle(m)}</Heading>
                  <Flex gap={1} wrap justify="flex-end" style={{ flexShrink: 0, maxWidth: "55%" }}><SessionPill m={m} />{!paused && hasSchedule(m) && <Pill kind="info">scheduled</Pill>}</Flex>
                </Flex>
                <Flex gap={1} wrap align="center">
                  <Muted>{line1}</Muted>
                  {m.permissionMode === "bypass" ? <Pill kind="bad">skip perms</Pill> : null}
                  {m.oneShot && <Pill kind="dim">one-shot</Pill>}
                </Flex>
                <Muted>{[REGION[m.region || ""] || m.region || "", m.guest || "", m.created ? "created " + ago(m.created) : "", m.pausedAt && paused ? "paused " + ago(m.pausedAt) : ""].filter(Boolean).join(" · ")}</Muted>
                {!!apInfo && <Muted mt={1}>{apInfo}</Muted>}
                {m.authFailed && <P size={2} color="red" mt={1}>Claude's login failed in this session — the router writes fresh credentials from Jarvis 1 when it can.</P>}
                {!!m.resumePrompt && <Muted mt={1}>{(paused ? "Prompt queued for the next resume" : "Prompt queued — delivered once it is up") + " — “" + clip(m.resumePrompt) + "”"}</Muted>}
                <NeedsGrant m={m} />
                <Schedules m={m} />
                {!!m.error && <P size={2} color="red" mt={1}>{m.error}</P>}
                {!!m.discordChannel && <Flex mt={1}><Button size={1} variant="ghost" color="gray" id={"discord-" + m.id} onPress={() => openDiscord(m.discordChannel!)}>Discord channel ↗</Button></Flex>}
                <Flex gap={2} pt={3} wrap style={{ marginTop: "auto" }} data={{ actions: "1" }}>
                  {busy ? <BusyButton variant="soft" color="gray" label={busy} />
                    : moving ? null
                    : <>
                      {(m.state === "started" || m.state === "initialising") && <Button id={"term-" + m.id} onPress={() => openPage("terminal", { id: m.id, title: sessionTitle(m) })}>Terminal</Button>}
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
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
export function FlyAccountSection() {
  const fly = useStore((s) => s.state.fly);
  if (!fly) return null;
  const other = fly.other || [];
  return (
    <Box id="fly-account" style={{ marginTop: 24 }}>
      {other.length > 0 && (
        <>
          <Heading size={3} mb={1}>Also on Fly</Heading>
          <Muted>Not sessions, but in the sessions' Fly app{other.some((o) => o.kind !== "app") ? " — and billed" : ""}.</Muted>
          <Cards mt={12}>
            {other.map((o) => (
              <Card key={o.kind + ":" + o.app + ":" + o.id} data={{ flyOther: o.kind }}>
                <Flex justify="space-between" align="flex-start" gap={2} mb={1}><Heading size={3} style={{ flex: 1 }}>{o.name || o.id}</Heading><Pill kind={o.state === "started" || o.kind === "volume" ? "wait" : "dim"}>{o.state || o.kind}</Pill></Flex>
                <Muted>{o.kind + " · app " + o.app + (o.name ? " · " + o.id : "")}</Muted>
                <Muted>{[o.detail, REGION[o.region || ""] || o.region, o.created ? "created " + ago(o.created) : ""].filter(Boolean).join(" · ")}</Muted>
              </Card>
            ))}
          </Cards>
        </>
      )}
      <P size={1} color="gray" align="center" mt={4} id="fly-summary">
        {fly.error ? `Could not check the Fly app: ${fly.error}`
          : `Fly: ${plural(fly.machines, "machine")} · ${plural(fly.volumes, "volume")} — ${other.length ? plural(other.length, "item") + " outside the sessions" : "nothing outside the sessions"}.`}
      </P>
    </Box>
  );
}
