// Schedules tab (Jarvis 1's): tasks that run by themselves, daily at a time in a time zone. On/off right on the
// card; tap to edit.
import { Pressable, View } from "react-native";
import { api, fromNow, type TaskSchedule, type TasksOverview } from "../lib/api";
import { useStore, ask, pendTasks } from "../lib/store";
import { Button, Callout, Card, Flex, Heading, Muted, P, Spinner, Switch } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";
import { RunPill } from "./Tasks";

export const scheduleText = (s: TaskSchedule) => `Daily at ${s.time} · ${s.tz.replace(/_/g, " ")}`;
const nextText = (s: TaskSchedule) => (s.enabled && s.nextAt ? `Next run ${fromNow(new Date(s.nextAt))} (${new Date(s.nextAt).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" })} your time)` : "Off");

export function setScheduleEnabled(s: TaskSchedule, on: boolean) {
  return pendTasks("sched:" + s.id, on ? "Turning on…" : "Turning off…", () => api("PUT", "api/tasks/schedules/" + s.id, { enabled: on }),
    (d: TasksOverview) => d.schedules.some((x) => x.id === s.id && x.enabled === on));
}
export async function deleteSchedule(s: TaskSchedule, name: string) {
  if (!(await ask({ title: `Delete the schedule of “${name}”?`, detail: "The task and its runs stay.", action: "Delete", danger: true }))) return false;
  await pendTasks("sched:" + s.id, "Deleting…", () => api("DELETE", "api/tasks/schedules/" + s.id), (d) => !d.schedules.some((x) => x.id === s.id));
  return true;
}

export function TaskSchedules() {
  const ts = useStore((s) => s.tasks), pending = useStore((s) => s.pending);
  const { schedules, instances } = ts.data;
  if (!ts.loaded) return ts.err ? <Callout color="red">{"Could not load schedules: " + ts.err}</Callout>
    : <Flex gap={2} align="center" justify="center" mt={6}><Spinner /><P size={3} color="gray">Loading schedules…</P></Flex>;
  return (
    <View>
      {!!ts.err && <Callout color="red" mb={3}>{"Could not refresh: " + ts.err}</Callout>}
      {schedules.length ? <Cards>{schedules.map((s) => {
        const inst = instances.find((i) => i.id === s.instance);
        const name = inst ? inst.name : "(deleted task)";
        const p = pending.get("sched:" + s.id);
        return (
          <Card key={s.id} data={{ schedule: s.id }} dim={!!p}>
            <Pressable accessibilityRole="button" onPress={() => openPage("task-schedule", { id: s.id })}>
              <Flex gap={2} align="center" wrap><Heading size={3} style={{ flexShrink: 1 }}>{name}</Heading>{inst?.lastRun && <RunPill run={inst.lastRun} />}</Flex>
              <P size={2} mt={1}>{scheduleText(s)}</P>
              <Muted>{nextText(s)}</Muted>
            </Pressable>
            <Flex gap={3} align="center" style={{ marginTop: "auto", paddingTop: 12 }}>
              {p ? <Flex gap={2} align="center"><Spinner /><Muted>{p}</Muted></Flex> : <Switch id={"sw-" + s.id} on={s.enabled} onChange={(v) => setScheduleEnabled(s, v)} label={s.enabled ? "On" : "Off"} />}
              <View style={{ flex: 1 }} />
              <Button variant="soft" color="gray" onPress={() => openPage("task-schedule", { id: s.id })}>Edit</Button>
              {inst && <Button variant="soft" color="gray" onPress={() => openPage("task", { id: inst.id })}>Task</Button>}
            </Flex>
          </Card>);
      })}</Cards>
        : <View style={{ alignItems: "center", marginTop: 32, gap: 12 }}>
          <P size={3} color="gray" align="center">No schedules yet.</P>
          {instances.length ? <PButton pkey="sched:new" label="+ New schedule" onPress={() => openPage("task-schedule", {})} id="sched-empty-new" />
            : <Muted>Make a task in the Tasks tab first.</Muted>}
        </View>}
    </View>
  );
}
