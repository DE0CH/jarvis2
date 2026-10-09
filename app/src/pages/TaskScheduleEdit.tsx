// New / edit a task's daily schedule: which task, daily at HH:MM in a time zone. Saving never fires a slot that
// has already passed today.
import { useState } from "react";
import { api } from "../lib/api";
import { useStore, loadTasks } from "../lib/store";
import { Button, Flex, Lbl, Muted, P, RadioCards, Spinner, Switch, TextField } from "../ui/kit";
import { BtnLabel, useBusy } from "../ui/bits";
import { Page, closePage } from "../ui/page";
import { deleteSchedule } from "../views/TaskSchedules";

export type ScheduleSpec = { id?: string; instance?: string };
const ZONES: [string, string][] = [["Europe/London", "London"], ["Asia/Shanghai", "Shanghai"], ["Asia/Hong_Kong", "Hong Kong"], ["UTC", "UTC"]];
const deviceZone = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "Europe/London"; } catch { return "Europe/London"; } })();

export function TaskScheduleEdit({ spec }: { spec: ScheduleSpec }) {
  const data = useStore((s) => s.tasks.data);
  const cur = spec.id ? data.schedules.find((s) => s.id === spec.id) : undefined;
  const [instance, setInstance] = useState(cur ? cur.instance : spec.instance || (data.instances.length === 1 ? data.instances[0].id : ""));
  const [time, setTime] = useState(cur ? cur.time : "09:00");
  const [tz, setTz] = useState(cur ? cur.tz : "Europe/London");
  const [enabled, setEnabled] = useState(cur ? cur.enabled : true);
  const [busy, run, guard] = useBusy();
  const [err, setErr] = useState("");
  if (spec.id && !cur) return <Page title="Schedule"><Muted mt={3}>This schedule no longer exists.</Muted></Page>;
  const inst = data.instances.find((i) => i.id === instance);
  const save = () => guard(async () => {
    setErr("");
    if (!instance) { setErr("Pick a task."); return; }
    if (!/^\d{1,2}:\d{2}$/.test(time.trim())) { setErr("Time must be HH:MM, 24-hour (e.g. 07:30)."); return; }
    await run("Saving…", async () => {
      try {
        await api(cur ? "PUT" : "POST", cur ? "api/tasks/schedules/" + cur.id : "api/tasks/schedules", cur ? { time: time.trim(), tz: tz.trim(), enabled } : { instance, time: time.trim(), tz: tz.trim(), enabled });
        await loadTasks();
        closePage();
      } catch (e: any) { setErr(e.message); }
    });
  });
  return (
    <Page title={cur ? "Edit schedule" : "New schedule"} onSubmit={busy ? undefined : save} id="task-schedule"
      right={<Button id="se-save" disabled={!!busy} onPress={save}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : "Save"}</Button>}>
      <Lbl>Task</Lbl>
      {cur || spec.instance ? <P size={3}>{inst ? inst.name : "(deleted task)"}</P>
        : data.instances.length ? <RadioCards id="se-task" value={instance} onChange={setInstance} options={data.instances.map((i) => ({ value: i.id, title: i.name, sub: data.templates.find((t) => t.name === i.template)?.title || i.template }))} />
        : <Muted>No tasks yet — make one in the Tasks tab first.</Muted>}
      <Lbl>Repeat</Lbl>
      <P size={2}>Daily</P>
      <Lbl>At (24-hour)</Lbl>
      <TextField id="se-time" autoComplete="off" autoCorrect={false} keyboardType="numbers-and-punctuation" placeholder="09:00" value={time} onChangeText={setTime} style={{ maxWidth: 140 }} />
      <Lbl>Time zone</Lbl>
      <TextField id="se-tz" autoComplete="off" autoCorrect={false} autoCapitalize="none" placeholder="Europe/London" value={tz} onChangeText={setTz} />
      <Flex gap={2} mt={2} wrap>
        {[...ZONES, ...(ZONES.some(([z]) => z === deviceZone) ? [] : [[deviceZone, "This device"] as [string, string]])].map(([z, l]) => (
          <Button key={z} size={1} variant={tz === z ? "solid" : "soft"} color={tz === z ? "blue" : "gray"} onPress={() => setTz(z)}>{l}</Button>))}
      </Flex>
      <Muted mt={1}>An IANA zone name; daylight saving is followed. A slot missed by more than 2 h (router down) is skipped.</Muted>
      <Lbl>On</Lbl>
      <Switch id="se-enabled" on={enabled} onChange={setEnabled} label={enabled ? "Runs every day" : "Paused"} />
      {!!err && <P size={2} color="red" mt={3} id="se-err">{err}</P>}
      {cur && <Flex mt={6}><Button variant="soft" color="red" onPress={async () => { if (await deleteSchedule(cur, inst?.name || "task")) closePage(); }} id="se-delete">Delete schedule</Button></Flex>}
    </Page>
  );
}
