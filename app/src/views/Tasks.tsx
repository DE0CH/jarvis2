// Tasks tab (Jarvis 1's): the instances — a template filled in, each its own session line that the phone approved
// once; Run resumes the line, runs the template's script and pauses it again — and the templates (tasks/<name>/
// in the repo, written by Claude). Daily schedules have their own tab (views/TaskSchedules.tsx).
import { Pressable, View } from "react-native";
import { ago, RUN_ACTIVE, type TaskInstance, type TaskRun, type TaskTemplate } from "../lib/api";
import { useStore } from "../lib/store";
import { runInstance, reapprove } from "../lib/tasks";
import { Badge, BadgeList, Button, Callout, Card, Flex, Heading, Lbl, Muted, P, Pill, Row, Rows, Spinner } from "../ui/kit";
import { PButton } from "../ui/bits";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";

const PHASE: Record<string, ["ok" | "dim" | "wait" | "bad" | "info", string]> = {
  queued: ["wait", "queued"], starting: ["wait", "starting"], running: ["info", "running"], succeeded: ["ok", "succeeded"], failed: ["bad", "failed"],
  timedout: ["bad", "timed out"], stopped: ["dim", "stopped"], lost: ["bad", "lost"],
};
export function RunPill({ run }: { run: TaskRun }) {
  const [kind, label] = PHASE[run.phase] || ["dim", run.phase];
  return <Pill kind={kind} spin={RUN_ACTIVE(run.phase)}>{label}</Pill>;
}
const STATE: Record<string, ["ok" | "dim" | "wait" | "bad" | "info", string]> = {
  approval: ["info", "needs approval"], ready: ["ok", "ready"], running: ["info", "running"], busy: ["wait", "busy"], failed: ["bad", "failed"], gone: ["bad", "no line"],
};
export const StatePill = ({ inst }: { inst: TaskInstance }) => { const [k, l] = STATE[inst.state] || ["dim", inst.state]; return <Pill kind={k} spin={inst.state === "running" || inst.state === "busy"}>{l}</Pill>; };
/** when a run last moved, as a label and a value: Finished / Started / Queued */
export const runWhen = (r: TaskRun): [string, string] | null => (r.finishedAt ? ["Finished", ago(r.finishedAt)] : r.ranAt ? ["Started", ago(r.ranAt)] : r.createdAt ? ["Queued", ago(r.createdAt)] : null);
/** a task's filled-in values as rows (label, value), empty ones left out */
export function paramRows(inst: TaskInstance, t?: TaskTemplate): [string, string][] {
  return (t ? t.fields : Object.keys(inst.params).map((name) => ({ name, label: name, type: "text" })))
    .flatMap((f): [string, string][] => { const v = inst.params[f.name]; return v === "" || v == null || (Array.isArray(v) && !v.length) ? [] : [[f.label, f.type === "checkbox" ? (v ? "Yes" : "No") : Array.isArray(v) ? v.join(", ") : String(v)]]; });
}
/** the primary action for an instance, by its state */
export function InstanceAction({ inst, id }: { inst: TaskInstance; id?: string }) {
  if (inst.state === "approval") return <Button variant="soft" disabled>Waiting for the phone</Button>;
  if (inst.state === "gone" || inst.state === "failed") return <PButton pkey={"task:" + inst.id} label="New line…" onPress={() => reapprove(inst)} id={id ? id + "-approve" : undefined} />;
  if (inst.activeRun) return <Button variant="soft" disabled>Running…</Button>;
  return <PButton pkey={"task:" + inst.id} label="Run" onPress={() => runInstance(inst.id)} id={id} />;
}

function InstanceCard({ inst, t }: { inst: TaskInstance; t?: TaskTemplate }) {
  const r = inst.activeRun || inst.lastRun;
  return (
    <Card data={{ task: inst.id }}>
      <Pressable accessibilityRole="button" onPress={() => openPage("task", { id: inst.id })}>
        <Flex gap={2} align="center" wrap>
          <Heading size={3} style={{ flexShrink: 1 }}>{inst.name}</Heading>
          <StatePill inst={inst} />{r && <RunPill run={r} />}
        </Flex>
        <Rows mt={1} id={"task-rows-" + inst.id}>
          <Row label="Template">{t ? t.title : <><P size={2}>{inst.template}</P><Badge color="red">missing</Badge></>}</Row>
          {!!inst.schedules && <Row label="Schedules">{String(inst.schedules)}</Row>}
          {!!inst.stores?.length && <Row label="Stores"><BadgeList items={inst.stores} /></Row>}
          {paramRows(inst, t).map(([l, v]) => <Row key={"p:" + l} label={l} lines={2}>{v}</Row>)}
          <Row label="Last run">{r ? <><P size={2}>{runWhen(r)?.[1] || ""}</P>{r.trigger === "schedule" && <Badge>scheduled</Badge>}</> : "Never"}</Row>
          {!!inst.detail && inst.state !== "approval" && <Row label="Detail">{inst.detail}</Row>}
        </Rows>
      </Pressable>
      <Flex gap={2} style={{ marginTop: "auto", paddingTop: 12 }}>
        <InstanceAction inst={inst} id={"run-" + inst.id} />
        <Button variant="soft" color="gray" onPress={() => openPage("task", { id: inst.id })} id={"open-" + inst.id}>Open</Button>
      </Flex>
    </Card>
  );
}

function TemplateCard({ t }: { t: TaskTemplate }) {
  return (
    <Card variant="surface" data={{ template: t.name }}>
      <Heading size={3}>{t.title}</Heading>
      <Rows mt={1}>
        <Row label="Name" mono>{t.name}</Row>
        {!!t.stores?.length && <Row label="Stores"><BadgeList items={t.stores} /></Row>}
        {!!t.prompt && <Row label="Claude prompt"><Badge color="blue">yes</Badge></Row>}
      </Rows>
      {t.error ? <P size={2} color="red" mt={1}>Broken task.json: {t.error}</P>
        : <>
          {!!t.description && <P size={2} mt={1}>{t.description}</P>}
          {!!t.fields.length && <Rows mt={1}><Row label="Fields"><BadgeList items={t.fields.map((f) => f.label + (f.required ? " *" : ""))} /></Row></Rows>}
        </>}
      <Flex gap={2} style={{ marginTop: "auto", paddingTop: 12 }}>
        <Button variant="soft" disabled={!!t.error} onPress={() => openPage("task-edit", { template: t.name })} id={"new-" + t.name}>New task</Button>
      </Flex>
    </Card>
  );
}

export function Tasks() {
  const ts = useStore((s) => s.tasks);
  const { templates, instances } = ts.data;
  const tmpl = (n: string) => templates.find((x) => x.name === n);
  if (!ts.loaded) return ts.err ? <Callout color="red">{"Could not load tasks: " + ts.err}</Callout>
    : <Flex gap={2} align="center" justify="center" mt={6}><Spinner /><P size={3} color="gray">Loading tasks…</P></Flex>;
  return (
    <View>
      {!!ts.err && <Callout color="red" mb={3}>{"Could not refresh: " + ts.err}</Callout>}
      <Lbl mt={0}>Tasks</Lbl>
      {instances.length ? <Cards>{instances.map((i) => <InstanceCard key={i.id} inst={i} t={tmpl(i.template)} />)}</Cards>
        : <Muted>No tasks yet.</Muted>}
      <Lbl mt={6}>Templates</Lbl>
      {templates.length ? <Cards>{templates.map((t) => <TemplateCard key={t.name} t={t} />)}</Cards>
        : <Muted>No templates in tasks/.</Muted>}
    </View>
  );
}
