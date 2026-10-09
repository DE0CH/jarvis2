// New session. In the app this form is normal mode: it carries the prompt, title, permission mode, model
// and size, and may PRE-select non-sensitive stores; Continue pushes the shell's secure page, where the
// stores and the harness are chosen for real and the iPhone signs. On the web the form only creates a
// pending request (POST api/sessions); the approval happens in the app.
import { useEffect, useRef, useState } from "react";
import { api, newId, CORE_STORE } from "../lib/api";
import { useStore, loadStores, refresh, settle, toast, failed } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, CheckboxCards, Flex, Lbl, Muted, RadioCards, Spinner, TextArea, TextField } from "../ui/kit";
import { BtnLabel } from "../ui/bits";
import { Page, useDone } from "../ui/page";

export function NewSession() {
  const SIZES = useStore((s) => s.sizes), MODELS = useStore((s) => s.models), stores = useStore((s) => s.stores);
  useEffect(() => { loadStores(); }, []);
  // the normal-mode form never lists sensitive stores (those are only picked on the secure page), nor the
  // core's own store (it never goes to a session)
  const plain = stores.items.filter((s) => !s.sensitive && s.name !== CORE_STORE);
  const [picked, setPicked] = useState<string[]>([]);
  const touched = useRef(false);
  useEffect(() => { if (!touched.current) setPicked(plain.some((s) => s.name === "default") ? ["default"] : []); }, [plain.map((s) => s.name).join(",")]);
  const [perm, setPerm] = useState("bypass"), [model, setModel] = useState(""), [size, setSize] = useState("medium"), [harness, setHarness] = useState("claude");
  useEffect(() => { setModel((m) => m || MODELS[0]?.id || ""); }, [MODELS[0]?.id]);
  const [label, setLabel] = useState(""), [prompt, setPrompt] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const done = useDone();
  // one create per form: the router answers a repeat of this id with the first create
  const requestId = useRef(newId());
  const canStart = !busy && (hasShell || picked.length > 0);
  function start() {
    if (!canStart) return;
    const body = { requestId: requestId.current, label: label.trim(), prompt: prompt.trim(), model, permissionMode: perm, size, harness, stores: picked };
    if (hasShell) {
      // the form stays underneath the shell's page: Back there returns to it as it was
      setBusy("Opening…");
      requestSecure("new-session", body, (r) => {
        setBusy(null);
        if (r.result === "done") { refresh(false); settle(120000); done(); }
      });
      return;
    }
    setBusy("Starting…");
    api("POST", "api/sessions", body)
      .then(() => { toast("Requested. Approve it in the Jarvis 2 app on the iPhone once the machine is up.", "ok"); refresh(false); settle(120000); done(); })
      .catch((e) => { failed(e); setBusy(null); });
  }
  return (
    <Page title="New session" onSubmit={canStart ? start : undefined}
      right={<Button id="ns-start" disabled={!canStart} onPress={start}>{busy ? <><Spinner /><BtnLabel>{busy}</BtnLabel></> : hasShell ? "Continue" : "Start"}</Button>}>
      <Lbl>First prompt (optional)</Lbl>
      <TextArea id="ns-prompt" rows={4} autoCapitalize="sentences" placeholder="Typed into the session as its first message once it is up." value={prompt} onChangeText={setPrompt} />
      <Lbl>Session title (optional)</Lbl>
      <TextField id="ns-title" autoComplete="off" autoCorrect={false} autoCapitalize="sentences" placeholder="e.g. refactor billing module" value={label} onChangeText={setLabel} />
      <Lbl>Secret stores</Lbl>
      {hasShell && <Muted style={{ marginBottom: 8 }}>Pre-selection only — you confirm the stores on the next, secure screen. Sensitive stores can only be picked there.</Muted>}
      {!hasShell && <Muted style={{ marginBottom: 8 }}>Sensitive stores can only be picked in the app.</Muted>}
      {plain.length ? <CheckboxCards id="ns-stores" value={picked} onChange={(v) => { touched.current = true; setPicked(v); }} options={plain.map((s) => ({ value: s.name, title: s.name, sub: `${s.keys.length} key${s.keys.length === 1 ? "" : "s"}${s.unlocked ? "" : " · locked"}` }))} />
        : stores.loaded ? <Muted>No (non-sensitive) stores.</Muted>
        : stores.err ? <Muted>{"Could not list the stores: " + stores.err}</Muted>
        : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>}
      {!hasShell && <>
        <Lbl>Harness</Lbl>
        <RadioCards id="ns-harness" value={harness} onChange={setHarness} options={[
          { value: "claude", title: "Claude Code", sub: "Claude subscription · Claude app" },
          { value: "opencode", title: "OpenCode · OpenRouter", sub: "Paseo app + web UI" },
        ]} />
      </>}
      <Lbl>Permission mode</Lbl>
      <RadioCards id="ns-perm" value={perm} onChange={setPerm} options={[
        { value: "auto", title: "Auto", sub: "Auto-approve safe actions; the permission classifier gates the rest." },
        { value: "bypass", title: "Dangerously skip permissions", sub: "No prompts at all (--dangerously-skip-permissions)." },
      ]} />
      {MODELS.length > 0 && <><Lbl>Model</Lbl>
        <RadioCards id="ns-model" value={model} onChange={setModel} options={MODELS.map((m) => ({ value: m.id, title: m.label || m.id, sub: m.id }))} /></>}
      {SIZES.length > 0 && <><Lbl>Machine size</Lbl>
        <RadioCards id="ns-size" value={size} onChange={setSize} options={SIZES.map((s) => ({ value: s.id, title: s.id[0].toUpperCase() + s.id.slice(1), sub: s.label }))} /></>}
    </Page>
  );
}
