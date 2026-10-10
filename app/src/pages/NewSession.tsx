// New session. In the app this form is normal mode: it carries the prompt, title, permission mode, model
// and size, and may PRE-select non-sensitive stores; Continue pushes the shell's secure page, where the
// stores and the harness are chosen for real and the iPhone signs. On the web the form only creates a
// pending request (POST api/sessions); the approval happens in the app.
import { useEffect, useRef, useState } from "react";
import { api, newId, CORE_STORE, harnessStoreSet } from "../lib/api";
import { useStore, loadStores, refresh, settle, toast, failed } from "../lib/store";
import { hasShell, requestSecure } from "../lib/shell";
import { Button, CheckboxCards, Flex, Lbl, Muted, RadioCards, Segmented, Spinner, TextArea, TextField } from "../ui/kit";
import { BtnLabel } from "../ui/bits";
import { Page, useDone } from "../ui/page";

export function NewSession() {
  const SIZES = useStore((s) => s.sizes), MODELS = useStore((s) => s.models), stores = useStore((s) => s.stores);
  useEffect(() => { loadStores(); }, []);
  // the normal-mode form never lists sensitive stores (those are only picked on the secure page), nor the
  // core's own store (it never goes to a session)
  const hidden = harnessStoreSet(useStore((s) => s.policy));
  const plain = stores.items.filter((s) => !s.sensitive && s.name !== CORE_STORE && !hidden.has(s.name));
  const [picked, setPicked] = useState<string[]>([]);
  const touched = useRef(false);
  useEffect(() => { if (!touched.current) setPicked(plain.some((s) => s.name === "default") ? ["default"] : []); }, [plain.map((s) => s.name).join(",")]);
  const [perm, setPerm] = useState("bypass"), [model, setModel] = useState(""), [size, setSize] = useState("medium"), [harness, setHarness] = useState("claude");
  // the models of the chosen harness (the router swaps a model of another harness for that harness's default)
  const models = MODELS.filter((m) => hasShell || (m.harness || "claude") === harness);
  useEffect(() => { setModel((m) => (models.some((x) => x.id === m) ? m : models[0]?.id || "")); }, [harness, models.map((m) => m.id).join(",")]);
  const [label, setLabel] = useState(""), [prompt, setPrompt] = useState("");
  // one-shot: the session runs its prompt, then is archived and destroyed by itself (never auto-paused)
  const [mode, setMode] = useState("session"), [autoPause, setAutoPause] = useState<string[]>(["on"]);
  const oneShot = mode === "oneshot";
  // repos from Settings → Repos, each with its deploy key in its own store (github-<repo>): picking a repo also
  // picks its store when that is not sensitive (a sensitive one, e.g. github-jarvis2, only on the secure page)
  const repoList = useStore((s) => s.state.repos) || [];
  const [repos, setRepos] = useState<string[]>([]), [apiProxy, setApiProxy] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const done = useDone();
  // one create per form: the router answers a repeat of this id with the first create
  const requestId = useRef(newId());
  const canStart = !busy && (hasShell || picked.length > 0) && !(oneShot && !prompt.trim());
  function start() {
    if (!canStart) return;
    const chosen = repoList.filter((r) => repos.includes(r.name));
    const withRepos = [...new Set([...picked, ...chosen.map((r) => r.store).filter((n) => plain.some((s) => s.name === n))])];
    const body = { requestId: requestId.current, label: label.trim(), prompt: prompt.trim(), model, permissionMode: perm, size, harness, stores: withRepos, oneShot, autoPause: !oneShot && autoPause.includes("on"),
      repos: chosen.map((r) => r.url).join(","), apiProxy: apiProxy.includes("on") };
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
      <Segmented id="ns-mode" value={mode} onChange={setMode} items={[["session", "Session"], ["oneshot", "One-shot"]]} />
      <Lbl>{oneShot ? "Prompt" : "First prompt (optional)"}</Lbl>
      <TextArea id="ns-prompt" rows={4} autoCapitalize="sentences" placeholder={oneShot ? "The one job for this session. Claude runs it, then the session is archived and destroyed." : "Typed into the session as its first message once it is up."} value={prompt} onChangeText={setPrompt} />
      {oneShot && <Muted mt={1}>Needs a prompt. If Claude asks you something, the session waits (“needs you”) until you answer, then finishes.</Muted>}
      <Lbl>Session title (optional)</Lbl>
      <TextField id="ns-title" autoComplete="off" autoCorrect={false} autoCapitalize="sentences" placeholder="e.g. refactor billing module" value={label} onChangeText={setLabel} />
      <Lbl>Secret stores</Lbl>
      {hasShell && <Muted style={{ marginBottom: 8 }}>Pre-selection only — you confirm the stores on the next, secure screen. Sensitive stores can only be picked there.</Muted>}
      {!hasShell && <Muted style={{ marginBottom: 8 }}>Sensitive stores can only be picked in the app.</Muted>}
      {plain.length ? <CheckboxCards id="ns-stores" value={picked} onChange={(v) => { touched.current = true; setPicked(v); }} options={plain.map((s) => ({ value: s.name, title: s.name, sub: [s.empty ? "empty" : "", s.unlocked ? "" : "locked"].filter(Boolean).join(" · ") || "unlocked" }))} />
        : stores.loaded ? <Muted>No (non-sensitive) stores.</Muted>
        : stores.err ? <Muted>{"Could not list the stores: " + stores.err}</Muted>
        : <Flex gap={2} align="center"><Spinner /><Muted>Loading stores…</Muted></Flex>}
      {!hasShell && <>
        <Lbl>Harness</Lbl>
        <RadioCards id="ns-harness" value={harness} onChange={setHarness} options={[
          { value: "claude", title: "Claude Code", sub: "Claude subscription · Claude app" },
          { value: "opencode", title: "OpenCode · OpenRouter", sub: "Paseo app + web UI" },
          { value: "openclaw", title: "claw-code · OpenClaw", sub: "Claude subscription · OpenClaw app + Control UI" },
        ]} />
      </>}
      <Lbl>Repos</Lbl>
      {repoList.length ? <CheckboxCards id="ns-repo" value={repos} onChange={setRepos} options={repoList.map((r) => ({ value: r.name, title: r.repo, sub: r.store }))} />
        : <Muted>No repos yet — add some in Settings → Repos.</Muted>}
      {!!repoList.length && !repos.length && <Muted mt={1}>No repo selected — the session starts with an empty workspace.</Muted>}
      {repoList.some((r) => repos.includes(r.name) && !plain.some((s) => s.name === r.store)) && <Muted mt={1} id="ns-repo-sensitive">
        {`Pick ${repoList.filter((r) => repos.includes(r.name) && !plain.some((s) => s.name === r.store)).map((r) => r.store).join(", ")} on the ${hasShell ? "next, secure screen" : "app's secure screen"} to push: a sensitive store (or one without a key) isn't pre-selected.`}</Muted>}
      <Lbl>Permission mode</Lbl>
      <RadioCards id="ns-perm" value={perm} onChange={setPerm} options={[
        { value: "auto", title: "Auto", sub: "Auto-approve safe actions; the permission classifier gates the rest." },
        { value: "bypass", title: "Dangerously skip permissions", sub: "No prompts at all (--dangerously-skip-permissions)." },
      ]} />
      {models.length > 0 && <><Lbl>Model</Lbl>
        <RadioCards id="ns-model" value={model} onChange={setModel} options={models.map((m) => ({ value: m.id, title: m.label || m.id, sub: m.id }))} /></>}
      {!oneShot && <><Lbl>Idle</Lbl>
        <CheckboxCards id="ns-autopause" value={autoPause} onChange={setAutoPause} options={[{ value: "on", title: "Auto-pause when idle", sub: "Pauses the machine after 1 h with nothing running. Resume brings it back — the conversation and your files are kept." }]} /></>}
      <Lbl>API proxy</Lbl>
      <CheckboxCards id="ns-apiproxy" value={apiProxy} onChange={setApiProxy} options={[{ value: "on", title: "API proxy", sub: "Logs every request to and response from the Anthropic API into ~/artifacts/api-log, archived with the session." }]} />
      {SIZES.length > 0 && <><Lbl>Machine size</Lbl>
        <RadioCards id="ns-size" value={size} onChange={setSize} options={SIZES.map((s) => ({ value: s.id, title: s.id[0].toUpperCase() + s.id.slice(1), sub: s.label }))} /></>}
    </Page>
  );
}
