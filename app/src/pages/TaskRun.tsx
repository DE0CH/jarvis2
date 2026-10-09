// One run: its phase, why it failed or waits, its output and its log (store values masked by the machine),
// refreshed every 2 s while it is queued or running. Stop drops a queued run or pauses the line.
import { useEffect, useState } from "react";
import { View } from "react-native";
import { api, ago, RUN_ACTIVE, type TaskRun as Run } from "../lib/api";
import { ask, loadTasks } from "../lib/store";
import { useTheme, radius } from "../theme";
import { Button, Callout, Flex, Lbl, Muted, P, Spinner, Text, mono } from "../ui/kit";
import { Page } from "../ui/page";
import { RunPill } from "../views/Tasks";

export type TaskRunSpec = { name: string; title: string };
function Mono({ text, id }: { text: string; id: string }) {
  const t = useTheme();
  return <View nativeID={id} style={{ marginTop: 4, padding: 12, borderRadius: radius[3], backgroundColor: t.gray.a[2], borderWidth: 1, borderColor: t.gray.a[5] }}>
    <Text selectable style={{ fontFamily: mono, fontSize: 12.5, lineHeight: 18, color: t.gray[12] }}>{text}</Text>
  </View>;
}
export function TaskRunPage({ spec }: { spec: TaskRunSpec }) {
  const name = spec.name;
  const [run, setRun] = useState<Run | null>(null), [log, setLog] = useState(""), [out, setOut] = useState(""), [err, setErr] = useState(""), [stopping, setStopping] = useState(false);
  const get = async () => { const j = await api<{ run: Run; log: string; output: string }>("GET", "api/tasks/runs/" + encodeURIComponent(name)); setRun(j.run); setLog(j.log || ""); setOut(j.output || ""); return j.run; };
  useEffect(() => {
    let live = true, timer: any;
    const load = async () => {
      try { const r = await get(); if (!live) return; setErr(""); if (RUN_ACTIVE(r.phase)) timer = setTimeout(load, 2000); else loadTasks(); }
      catch (e: any) { if (live) { setErr(e.message); timer = setTimeout(load, 5000); } }
    };
    load();
    return () => { live = false; clearTimeout(timer); };
  }, [name]);
  const stop = async () => {
    if (!(await ask({ title: "Stop this run?", detail: "A queued run is dropped; a starting or running one is stopped and its line paused. It stays in the history as stopped.", action: "Stop", danger: true }))) return;
    setStopping(true);
    try { await api("POST", `api/tasks/runs/${encodeURIComponent(name)}/stop`); for (let i = 0; i < 15; i++) { const r = await get(); if (!RUN_ACTIVE(r.phase)) break; await new Promise((x) => setTimeout(x, 1000)); } }
    catch (e: any) { setErr(e.message); }
    setStopping(false);
  };
  return (
    <Page title={spec.title} id="task-run" right={run && RUN_ACTIVE(run.phase) ? <Button color="red" variant="soft" disabled={stopping} onPress={stop} id="tr-stop">{stopping ? "Stopping…" : "Stop"}</Button> : undefined}>
      {!run ? (err ? <P size={2} color="red" mt={3}>{err}</P> : <Flex gap={2} align="center" mt={4}><Spinner /><Muted>Loading the run…</Muted></Flex>) : <>
        <Flex gap={2} align="center" mt={2} wrap>
          <RunPill run={run} />
          <Muted>{(run.trigger === "schedule" ? "Scheduled" : "Manual") + (run.upgrade ? " · on the latest image" : "")}</Muted>
        </Flex>
        <Muted mt={1}>{[run.createdAt ? "queued " + ago(run.createdAt) : "", run.ranAt ? "script started " + ago(run.ranAt) : "", run.finishedAt ? "finished " + ago(run.finishedAt) : "", run.exitCode != null ? "exit code " + run.exitCode : ""].filter(Boolean).join(" · ")}</Muted>
        <Muted>{run.id}</Muted>
        {!!run.reason && <Callout color="red" mt={3}>{run.reason}</Callout>}
        {!!run.waiting && <Callout color="amber" mt={3}>{"Waiting: " + run.waiting}</Callout>}
        {!!err && <P size={2} color="red" mt={2}>{err}</P>}
        <Lbl>Output</Lbl>
        {out ? <Mono text={out} id="tr-output" /> : <Muted>{RUN_ACTIVE(run.phase) ? "No output yet…" : "No output."}</Muted>}
        <Lbl>Log</Lbl>
        {log ? <Mono text={log} id="tr-log" /> : <Muted>{RUN_ACTIVE(run.phase) ? "No log yet…" : "No log."}</Muted>}
      </>}
    </Page>
  );
}
