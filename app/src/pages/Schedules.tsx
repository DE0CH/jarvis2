// A session's wakeups and crons (router/schedule.go, Jarvis 1's shapes): at the due time the router delivers
// the prompt into the session as a message, resuming it first when it is paused. Delivery runs as the
// `scheduler` feature, so the session must allow it (arming from inside the session does that by itself) or
// the phone must (a standing rule; a session with a sensitive store takes only a phone grant).
import { useEffect, useState } from "react";
import { api, cronEvery, sessionTitle, when, type Cron, type Wakeup } from "../lib/api";
import { useStore, ask, exclusive, failed, pend, refresh, toast } from "../lib/store";
import { hasShell } from "../lib/shell";
import { requestGrant } from "../lib/grants";
import { Button, Card, Flex, Heading, Lbl, Muted, P, RadioCards, Segmented, Spinner, TextArea, TextField } from "../ui/kit";
import { BtnLabel, PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { Page } from "../ui/page";

export type SchedulesSpec = { id: string };
const deviceZone = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch { return "UTC"; } })();
const EVERY: [string, string][] = [["daily", "Daily at"], ["hours", "Every N hours"]];

export function SchedulesPage({ spec }: { spec: SchedulesSpec }) {
  const sid = spec.id;
  const m = useStore((s) => s.state.sessions.find((x) => x.id === sid));
  const [ws, setWs] = useState<Wakeup[] | null>(null), [cs, setCs] = useState<Cron[] | null>(null), [err, setErr] = useState("");
  const load = async () => {
    try {
      const [w, c] = await Promise.all([api<{ wakeups: Wakeup[] }>("GET", `api/sessions/${sid}/wakeups`), api<{ crons: Cron[] }>("GET", `api/sessions/${sid}/crons`)]);
      setWs(w.wakeups || []); setCs(c.crons || []); setErr("");
    } catch (e: any) { setErr(e.message); }
  };
  useEffect(() => { load(); }, [sid]);
  const title = m ? sessionTitle(m) : sid;

  // the new-schedule form
  const [kind, setKind] = useState("wakeup");
  const [prompt, setPrompt] = useState(""), [name, setName] = useState("");
  const [inMin, setInMin] = useState("60"), [every, setEvery] = useState("daily"), [time, setTime] = useState("09:00"), [hours, setHours] = useState("6");
  const [busy, setBusy] = useState<string | null>(null), [formErr, setFormErr] = useState("");
  async function add() {
    setFormErr("");
    if (!prompt.trim()) { setFormErr("Write the prompt the session gets."); return; }
    const nm = name.trim() || undefined;
    let body: any;
    if (kind === "wakeup") {
      const mins = parseFloat(inMin);
      if (!(mins >= 1)) { setFormErr("Minutes from now: a number, at least 1."); return; }
      body = { prompt: prompt.trim(), delaySeconds: Math.round(mins * 60), name: nm };
    } else if (every === "daily") {
      if (!/^\d{1,2}:\d{2}$/.test(time.trim())) { setFormErr("Time must be HH:MM, 24-hour."); return; }
      body = { prompt: prompt.trim(), time: time.trim(), tz: deviceZone, name: nm || "daily" };
    } else {
      const h = parseFloat(hours);
      if (!(h >= 0.25)) { setFormErr("Every N hours: at least 0.25."); return; }
      body = { prompt: prompt.trim(), everySeconds: Math.round(h * 3600), name: nm || "every" };
    }
    setBusy("Saving…");
    try {
      await api("POST", `api/sessions/${sid}/${kind === "wakeup" ? "wakeups" : "crons"}`, body);
      setPrompt(""); setName("");
      await load(); await refresh(false);
      toast(kind === "wakeup" ? "Wakeup armed." : "Cron armed.", "ok");
    } catch (e: any) { setFormErr(e.message); }
    setBusy(null);
  }
  const cancel = (what: "wakeup" | "cron", n: string) => exclusive(`sch:${what}:${n}`, async () => {
    if (!(await ask({ title: `Cancel the ${what}${n === "default" ? "" : " “" + n + "”"}?`, action: "Cancel " + what, danger: true }))) return;
    pend(`sch:${what}:${n}`, "Cancelling…");
    try { await api("DELETE", what === "wakeup" ? `api/sessions/${sid}/wakeups/${encodeURIComponent(n)}` : `api/sessions/${sid}/crons/${encodeURIComponent(n)}`); await load(); await refresh(false); }
    catch (e: any) { failed(e); }
    finally { pend(`sch:${what}:${n}`, null); }
  });

  return (
    <Page title="Schedules" id="schedules-page" onSubmit={busy ? undefined : add}
      right={<Button id="sch-save" disabled={!!busy} onPress={add}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Arm"}</Button>}>
      <Muted mt={2}>{title}</Muted>
      <Muted mt={2}>At the time, the prompt arrives in the session as a message; a paused session is resumed first. The session has to allow the scheduler (it does when it arms one itself), or the phone does with a standing rule.</Muted>
      {hasShell && m && <Flex mt={2}><Button size={1} variant="soft" color="gray" id="sch-rule" onPress={() => requestGrant(sid, title, { holder: "scheduler", kind: "rule" })}>Standing rule for the scheduler…</Button></Flex>}
      <Lbl>Armed</Lbl>
      {err ? <P size={2} color="red">{err}</P>
        : !ws || !cs ? <Flex gap={2} align="center"><Spinner /><Muted>Loading…</Muted></Flex>
        : !ws.length && !cs.length ? <P size={3} color="gray" align="center" mt={4} mb={4} id="sch-none">Nothing armed.</P>
        : <Cards>
          {ws.map((w) => (
            <Card key={"w:" + w.name} data={{ wakeup: w.name }}>
              <Heading size={3} mb={1}>{"Wakes" + (w.name === "default" ? "" : " “" + w.name + "”") + " " + when(w.at)}</Heading>
              <Muted>“{w.prompt}”</Muted>
              <Flex mt={3}><PButton pkey={"sch:wakeup:" + w.name} variant="soft" color="red" onPress={() => cancel("wakeup", w.name)} label="Cancel" id={"sch-cancel-w-" + w.name} /></Flex>
            </Card>))}
          {cs.map((c) => (
            <Card key={"c:" + c.name} data={{ cron: c.name }}>
              <Heading size={3} mb={1}>{`“${c.name}” ${cronEvery(c.everySeconds)}`}</Heading>
              <Muted>{`next ${when(c.nextAt)}${c.tz && c.tz !== "UTC" ? " · " + c.tz : ""}${c.runs ? ` · ${c.runs} run${c.runs === 1 ? "" : "s"}` : ""}${c.untilIso ? " · until " + new Date(c.untilIso).toLocaleDateString() : ""}`}</Muted>
              <Muted>“{c.prompt}”</Muted>
              <Flex mt={3}><PButton pkey={"sch:cron:" + c.name} variant="soft" color="red" onPress={() => cancel("cron", c.name)} label="Cancel" id={"sch-cancel-c-" + c.name} /></Flex>
            </Card>))}
        </Cards>}
      <Lbl>New</Lbl>
      <Segmented id="sch-kind" value={kind} onChange={setKind} items={[["wakeup", "Once"], ["cron", "Repeating"]]} />
      <Lbl>Prompt</Lbl>
      <TextArea id="sch-prompt" rows={3} autoCapitalize="sentences" maxLength={3500} placeholder="What the session gets at that time, as a message." value={prompt} onChangeText={setPrompt} />
      {kind === "wakeup" ? <>
        <Lbl>In (minutes)</Lbl>
        <TextField id="sch-in" keyboardType="numeric" value={inMin} onChangeText={setInMin} style={{ maxWidth: 140 }} />
        <Flex gap={2} mt={2} wrap>{[["15", "15 min"], ["60", "1 h"], ["240", "4 h"], ["1440", "1 day"]].map(([v, l]) => <Button key={v} size={1} variant={inMin === v ? "solid" : "soft"} color={inMin === v ? "blue" : "gray"} onPress={() => setInMin(v)}>{l}</Button>)}</Flex>
      </> : <>
        <Lbl>Repeat</Lbl>
        <RadioCards id="sch-every" value={every} onChange={setEvery} options={EVERY.map(([v, l]) => ({ value: v, title: l }))} />
        {every === "daily" ? <><Lbl>At (24-hour, {deviceZone})</Lbl><TextField id="sch-time" keyboardType="numbers-and-punctuation" value={time} onChangeText={setTime} style={{ maxWidth: 140 }} /></>
          : <><Lbl>Every (hours)</Lbl><TextField id="sch-hours" keyboardType="numeric" value={hours} onChangeText={setHours} style={{ maxWidth: 140 }} /></>}
      </>}
      <Lbl>Name (optional)</Lbl>
      <TextField id="sch-name" autoCapitalize="none" autoCorrect={false} placeholder={kind === "wakeup" ? "default" : "daily"} value={name} onChangeText={setName} style={{ maxWidth: 240 }} />
      <Muted mt={1}>Arming the same name again replaces it.</Muted>
      {!!formErr && <P size={2} color="red" mt={3} id="sch-err">{formErr}</P>}
    </Page>
  );
}
