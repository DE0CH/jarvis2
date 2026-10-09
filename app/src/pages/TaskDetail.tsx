// One task: its values and line, Run / Run on the latest image / Edit / Delete, its daily schedules and its runs
// (newest first, the last 20 kept) — tap a run for its output and log.
import { useEffect, useState } from "react";
import { Pressable, View } from "react-native";
import { api, ago, fromNow, RUN_ACTIVE, type TaskRun } from "../lib/api";
import { useStore, ask, loadTasks, pendTasks } from "../lib/store";
import { runInstance } from "../lib/tasks";
import { useTheme } from "../theme";
import { Button, Callout, Card, Flex, Lbl, Muted, P, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Page, closePage, openPage } from "../ui/page";
import { RunPill, StatePill, runWhen, paramSummary, InstanceAction } from "../views/Tasks";
import { scheduleText } from "../views/TaskSchedules";

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
    if (!(await ask({ title: `Delete “${inst.name}”?`, detail: `Its ${schedules.length ? schedules.length + " schedule(s) and " : ""}run history go with it, and its session line is destroyed (archived like any session). The template stays.`, action: "Delete", danger: true }))) return;
    await pendTasks("task-del:" + id, "Deleting…", () => api("DELETE", "api/tasks/instances/" + id), (d) => !d.instances.some((i) => i.id === id), 60000);
    closePage();
  };
  const upgrade = async () => {
    if (!(await ask({ title: `Run “${inst.name}” on the latest image?`, detail: "Resumes its line on the newest session image (how a changed template reaches a task). The iPhone approves the new image first.", action: "Run on latest image" }))) return;
    await runInstance(id, true);
  };
  const ready = inst.state === "ready" || inst.state === "running" || inst.state === "busy";
  return (
    <Page title={inst.name} id="task-page" right={<InstanceAction inst={inst} id="td-run" />}>
      <Flex gap={2} align="center" mt={2} wrap><StatePill inst={inst} /><Muted>{tmpl ? tmpl.title : `${inst.template} (template missing)`} · created {new Date(inst.createdAt).toLocaleDateString()}</Muted></Flex>
      {inst.state === "approval" && <Callout color="blue" mt={3}>The iPhone approves this task's line once (it opens at the top of the session list). Runs need no approval after that.</Callout>}
      {!!inst.detail && inst.state !== "approval" && <Muted mt={1}>{inst.detail}</Muted>}
      {!!inst.activeRun?.waiting && <Callout color="amber" mt={3}>{"Waiting: " + inst.activeRun.waiting}</Callout>}
      {!!paramSummary(inst, tmpl) && <Card mt={3} size={1} variant="surface"><P size={2} selectable>{paramSummary(inst, tmpl)}</P></Card>}
      <Muted mt={2}>{[inst.stores?.length ? "stores: " + inst.stores.join(", ") : "no stores", inst.size, inst.queued ? `${inst.queued} queued` : ""].filter(Boolean).join(" · ")}</Muted>
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
            <P size={2}>{scheduleText(s)}</P>
            <Muted>{s.enabled && s.nextAt ? "next " + fromNow(new Date(s.nextAt)) : "off"}</Muted>
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
              <P size={2}>{r.trigger === "schedule" ? "Scheduled" : "Manual"}{r.upgrade ? " · latest image" : ""}</P>
              <Muted>{runWhen(r) || (r.createdAt ? ago(r.createdAt) : "")}{r.exitCode != null && r.phase !== "succeeded" ? ` · exit ${r.exitCode}` : ""}</Muted>
            </Flex>
            {!!r.waiting && <Muted>{"waiting: " + r.waiting}</Muted>}
          </Pressable>))}</View>}
    </Page>
  );
}
