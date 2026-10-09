// New / edit a task: a name plus the template's fields (task.json: text, textarea, number, select, multiselect,
// checkbox). A (multi)select of stores is filled from the core's store list; the picked stores join the task's
// session line, which the iPhone approves when the task is made (they can't change afterwards: make a new task).
// Parameters are not secret (they travel unsigned in the machine's config): secrets belong in a store.
import { useEffect, useState } from "react";
import { View } from "react-native";
import { api, CORE_STORE, harnessStoreSet, type TaskField, type TaskOption } from "../lib/api";
import { useStore, loadTasks, loadStores, toast } from "../lib/store";
import { openApprovalFor } from "../lib/tasks";
import { Button, CheckboxCards, Lbl, Muted, P, RadioCards, Spinner, Switch, TextArea, TextField } from "../ui/kit";
import { BtnLabel, useBusy } from "../ui/bits";
import { Page, closePage, openPage } from "../ui/page";

export type TaskEditSpec = { template?: string; id?: string };
const initial = (f: TaskField, v: unknown): any => {
  const x = v === undefined ? f.default : v;
  if (f.type === "checkbox") return !!x;
  if (f.type === "multiselect") return Array.isArray(x) ? x.map(String) : [];
  return x == null ? "" : String(x);
};
const norm = (o: TaskOption | string): TaskOption => (typeof o === "string" ? { value: o, label: o } : { value: String(o.value), label: o.label || String(o.value), sub: o.sub });

export function FieldInput({ f, value, onChange, opts }: { f: TaskField; value: any; onChange: (v: any) => void; opts: TaskOption[] }) {
  const choices = opts.map((o) => ({ value: o.value, title: o.label, sub: o.sub }));
  switch (f.type) {
    case "textarea": return <TextArea id={"tf-" + f.name} rows={4} placeholder={f.placeholder} defaultValue={value} onChangeText={onChange} />;
    case "number": return <TextField id={"tf-" + f.name} keyboardType="numeric" placeholder={f.placeholder} defaultValue={value} onChangeText={onChange} />;
    case "select": return choices.length ? <RadioCards id={"tf-" + f.name} value={value} onChange={onChange} options={choices} /> : <Muted>No options available.</Muted>;
    case "multiselect": return choices.length ? <CheckboxCards id={"tf-" + f.name} value={value} onChange={onChange} options={choices} /> : <Muted>No options available.</Muted>;
    case "checkbox": return <Switch id={"tf-" + f.name} on={!!value} onChange={onChange} label={value ? "Yes" : "No"} />;
    default: return <TextField id={"tf-" + f.name} autoComplete="off" autoCorrect={false} placeholder={f.placeholder} defaultValue={value} onChangeText={onChange} />;
  }
}

export function TaskEdit({ spec }: { spec: TaskEditSpec }) {
  const data = useStore((s) => s.tasks.data), stores = useStore((s) => s.stores), sizes = useStore((s) => s.sizes), models = useStore((s) => s.models);
  const hidden = harnessStoreSet(useStore((s) => s.policy));
  useEffect(() => { loadStores(); }, []);
  const inst = spec.id ? data.instances.find((i) => i.id === spec.id) : undefined;
  const t = data.templates.find((x) => x.name === (inst ? inst.template : spec.template));
  const [name, setName] = useState(inst ? inst.name : t ? t.title : "");
  const [vals, setVals] = useState<Record<string, any>>(() => Object.fromEntries((t?.fields || []).map((f) => [f.name, initial(f, inst?.params[f.name])])));
  const [busy, run, guard] = useBusy();
  const [err, setErr] = useState("");
  if (!t) return <Page title="Task"><P size={2} color="red" mt={3}>{spec.id && !inst ? "This task no longer exists." : `Template “${inst?.template || spec.template}” is not in tasks/.`}</P></Page>;
  // options: the template's own, or the core's stores / the sizes / the models
  const optionsOf = (f: TaskField): TaskOption[] =>
    f.optionsFrom === "stores" ? stores.items.filter((s) => s.name !== CORE_STORE && !hidden.has(s.name)).map((s) => ({ value: s.name, label: s.name, sub: [s.sensitive ? "sensitive" : "", s.empty ? "empty" : "", s.unlocked ? "" : "locked"].filter(Boolean).join(" · ") || undefined }))
    : f.optionsFrom === "sizes" ? sizes.map((s) => ({ value: s.id, label: s.id, sub: s.label }))
    : f.optionsFrom === "models" ? models.map((m) => ({ value: m.id, label: m.label || m.id }))
    : (f.options || []).map(norm);
  const storeField = (f: TaskField) => f.optionsFrom === "stores";
  const save = () => guard(async () => {
    setErr("");
    if (!name.trim()) { setErr("A name is required."); return; }
    await run("Saving…", async () => {
      try {
        const params: Record<string, any> = {};
        for (const f of t.fields) params[f.name] = vals[f.name];
        const r = await api<{ id: string; session: string | null }>(inst ? "PUT" : "POST", inst ? "api/tasks/instances/" + inst.id : "api/tasks/instances", inst ? { name: name.trim(), params } : { template: t.name, name: name.trim(), params });
        await loadTasks();
        closePage();
        if (!inst) { toast(`Made “${name.trim()}” — the iPhone approves it once.`, "ok"); openPage("task", { id: r.id }); openApprovalFor(r.session, "new-session"); }
      } catch (e: any) { setErr(e.message); }
    });
  });
  return (
    <Page title={inst ? "Edit task" : "New task"} onSubmit={busy ? undefined : save} id="task-edit"
      right={<Button id="te-save" disabled={!!busy} onPress={save}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : inst ? "Save" : "Make task"}</Button>}>
      <Muted mt={2}>From the template “{t.title}”{t.description ? ` — ${t.description}` : ""}</Muted>
      <Lbl>Name</Lbl>
      <TextField id="te-name" autoComplete="off" defaultValue={name} onChangeText={setName} placeholder="What this task is for" />
      {t.fields.map((f) => (
        <View key={f.name}>
          <Lbl>{f.label + (f.required ? " *" : "")}</Lbl>
          <FieldInput f={f} value={vals[f.name]} opts={optionsOf(f)} onChange={(v) => setVals((x) => ({ ...x, [f.name]: v }))} />
          {storeField(f) && <Muted mt={1}>{inst ? "Stores are part of the task's approved line: changing them needs a new task." : "The picked stores join the task's line; the iPhone shows them when it approves."}</Muted>}
          {!!f.help && <Muted mt={1}>{f.help}</Muted>}
        </View>
      ))}
      <Muted mt={4}>{`Values are not secret (they reach the machine unsigned). Secrets come from stores: the template's (${(t.stores || []).join(", ") || "none"}) and any picked above.`}</Muted>
      {!!err && <P size={2} color="red" mt={3} id="te-err">{err}</P>}
    </Page>
  );
}
