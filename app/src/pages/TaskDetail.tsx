// One task: its values and line, Run / Run on the latest image / Edit / Delete, its daily schedules and its runs
// (newest first, the last 20 kept) — tap a run for its output and log.
import { useEffect, useState } from "react";
import { Pressable, View } from "react-native";
import { api, ago, RUN_ACTIVE, type TaskRun } from "../lib/api";
import { useStore, ask, loadTasks, pendTasks } from "../lib/store";
import { runInstance } from "../lib/tasks";
import { useTheme } from "../theme";
import { Badge, BadgeList, Button, Callout, Card, Flex, Lbl, Muted, P, Row, Rows, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Page, closePage, openPage } from "../ui/page";
import { RunPill, StatePill, runWhen, paramRows, InstanceAction } from "../views/Tasks";
import { ScheduleRows } from "../views/TaskSchedules";

export type TaskSpec = { id: string };
export function TaskDetail({ spec }: { spec: TaskSpec }) {
  const id = spec.id, t = useTheme();
  const data = useStore((s) => s.tasks.data);
  const inst = data.instances.find((i) => i.id === id);
  const tmpl = inst && data.templates.find((x) => x.name === inst.template);
  const schedules = data.schedules.filter((s) => s.instance === id);
  const [runs, setRuns] = useState<TaskRun[] | null>(null), [err, setErr] = useState("");
  const key = (inst?.activeRun?.name || "") + "|" + (inst?.activeRun?.phase || "") + "|" + (inst?.lastRun?.name || "") + "|" + (inst?.queued || 0);
  // the run list follows api/tasks (a new run, a phase change) and polls itself while one is active
  useEffect(() => {
    let live = true, timer: any;
    const load = async () => {
      try { const j = await api<{ runs: TaskRun[] }>("GET", `api/tasks/instances/${id}/runs`); if (!live) return; setRuns(j.runs || []); setErr("");
        if ((j.runs || []).some((r) => RUN_ACTIVE(r.phase))) timer = setTimeout(load, 2000); }
      catch (e: any) { if (live) setErr(e.message); }
    };
    load();
    return () => { live = false; clearTimeout(timer); };
  }, [id, key]);
  useEffect(() => { loadTasks(); const tm = setInterval(() => loadTasks(), 5000); return () => clearInterval(tm); }, [id]);
  if (!inst) return <Page title="Task"><Muted mt={3}>This task no longer exists.</Muted></Page>;
  const del = async () => {
    if (!(await ask({ title: "Delete task?", rows: [
      { label: "Task", value: inst.name },
      ...(schedules.length ? [{ label: "Schedules", value: "Deleted (" + schedules.length + ")" }] : []),
      { label: "Run history", value: "Deleted" },
      { label: "Session line", value: "Archived, destroyed" },
      { label: "Template", value: "Kept" },
    ], action: "Delete", danger: true }))) return;
    await pendTasks("task-del:" + id, "Deleting…", () => api("DELETE", "api/tasks/instances/" + id), (d) => !d.instances.some((i) => i.id === id), 60000);
    closePage();
  };
  const upgrade = async () => {
    if (!(await ask({ title: "Run on the latest image?", rows: [{ label: "Task", value: inst.name }, { label: "Approval", value: "On the iPhone" }], action: "Run on latest image" }))) return;
    await runInstance(id, true);
  };
  const ready = inst.state === "ready" || inst.state === "running" || inst.state === "busy";
  return (
    <Page title={inst.name} id="task-page" right={<InstanceAction inst={inst} id="td-run" />}>
      <Flex gap={2} align="center" mt={2} wrap><StatePill inst={inst} /></Flex>
      {inst.state === "approval" && <Callout color="blue" mt={3}>Approve once in the iPhone app's Inbox.</Callout>}
      {!!inst.activeRun?.waiting && <Callout color="amber" mt={3}><Rows><Row label="Waiting" id="td-waiting">{inst.activeRun.waiting}</Row></Rows></Callout>}
      <Rows mt={3} id="td-rows">
        <Row label="Template">{tmpl ? tmpl.title : <><P size={2}>{inst.template}</P><Badge color="red">missing</Badge></>}</Row>
        <Row label="Created">{new Date(inst.createdAt).toLocaleDateString()}</Row>
        <Row label="Stores"><BadgeList items={inst.stores || []} /></Row>
        {!!inst.size && <Row label="Size">{inst.size}</Row>}
        {!!inst.queued && <Row label="Queued">{String(inst.queued)}</Row>}
        {!!inst.detail && inst.state !== "approval" && <Row label="Detail">{inst.detail}</Row>}
      </Rows>
      {paramRows(inst, tmpl).length > 0 && <Card mt={3} size={1} variant="surface"><Rows id="td-params">{paramRows(inst, tmpl).map(([l, v]) => <Row key={l} label={l} selectable>{v}</Row>)}</Rows></Card>}
      <Flex gap={2} mt={3} wrap>
        <Button variant="soft" disabled={!tmpl} onPress={() => openPage("task-edit", { id })} id="td-edit">Edit</Button>
        <Button variant="soft" onPress={() => openPage("task-schedule", { instance: id })} id="td-schedule">Schedule daily…</Button>
        {ready && <PButton pkey={"task:" + id} variant="soft" label="Run on latest image" onPress={upgrade} id="td-upgrade" />}
        <PButton pkey={"task-del:" + id} variant="soft" color="red" label="Delete" onPress={del} id="td-delete" />
      </Flex>
      {schedules.length > 0 && <>
        <Lbl>Schedules</Lbl>
        {schedules.map((s) => (
          <Pressable key={s.id} onPress={() => openPage("task-schedule", { id: s.id })} style={{ paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: t.gray.a[4] }}>
            <ScheduleRows s={s} />
          </Pressable>))}
      </>}
      <Lbl>Runs</Lbl>
      {err ? <P size={2} color="red">{err}</P>
        : !runs ? <Flex gap={2} align="center"><Spinner /><Muted>Loading runs…</Muted></Flex>
        : !runs.length ? <Muted>Not run yet.</Muted>
        : <View nativeID="td-runs">{runs.map((r) => (
          <Pressable key={r.name} {...({ dataSet: { run: r.name } } as any)} testID={"td-run-" + r.name} onPress={() => openPage("task-run", { name: r.name, title: inst.name })}
            style={({ hovered }: any) => ({ paddingVertical: 10, paddingHorizontal: 4, borderBottomWidth: 1, borderBottomColor: t.gray.a[4], backgroundColor: hovered ? t.gray.a[2] : "transparent" })}>
            <Flex gap={2} align="center" wrap>
              <RunPill run={r} />
              <Badge>{r.trigger === "schedule" ? "scheduled" : "manual"}</Badge>
              {r.upgrade && <Badge color="blue">latest image</Badge>}
              {r.exitCode != null && r.phase !== "succeeded" && <Badge color="red">{"exit " + r.exitCode}</Badge>}
              <Muted>{runWhen(r)?.[1] || (r.createdAt ? ago(r.createdAt) : "")}</Muted>
            </Flex>
            {!!r.waiting && <Rows mt={1}><Row label="Waiting">{r.waiting}</Row></Rows>}
          </Pressable>))}</View>}
    </Page>
  );
}
