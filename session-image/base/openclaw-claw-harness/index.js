// OpenClaw agent harness "claw-code": each turn runs the claw-code CLI (fork DE0CH/claw-code)
//   claw --model <id> --permission-mode <mode> --output-format json prompt "<text>"
// with CLAW_EVENT_STREAM=1, and maps its NDJSON events (session, text_delta, thinking_delta,
// tool_use, tool_result, permission_request, result, error) onto OpenClaw: live assistant text and
// tool activity, approvals, and the session transcript. claw keeps the conversation itself (its own
// session under <workspace>/.claw/sessions/); this plugin maps each OpenClaw session to the claw
// session id and resumes it with CLAW_RESUME_SESSION. Modelled on the bundled acpx harness.
// Selected per model in openclaw.json: agentRuntime {id: "claw-code"}.
// Config `statusFile` (claude-env sessions: ~/.claude/sessions/openclaw.json): the status shim Jarvis reads —
// busy while a turn runs, waiting while a permission request waits for an answer, idle otherwise. Written
// here because OpenClaw's own run hooks (before_agent_run / agent_end) do not fire for a harness turn.
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  clearActiveEmbeddedRun,
  emitAgentEvent,
  projectAgentToolActivity,
  resolveAgentHarnessBeforePromptBuildResult,
  setActiveEmbeddedRun,
} from "openclaw/plugin-sdk/agent-harness-runtime";
import { SessionManager } from "openclaw/plugin-sdk/agent-sessions";
import { DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS } from "openclaw/plugin-sdk/approval-runtime";
import { toErrorObject } from "openclaw/plugin-sdk/error-runtime";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { resolveStorePath } from "openclaw/plugin-sdk/session-store-runtime";
import { appendSessionTranscriptMessageByIdentityStrict } from "openclaw/plugin-sdk/session-transcript-runtime";

const HARNESS_ID = "claw-code";
const LABEL = "claw-code";
const PERMISSION_MODES = { bypass: "danger-full-access", ask: "workspace-write", "read-only": "read-only" };
// claw's tools in OpenClaw's tool-policy vocabulary (admission must cover what claw can reach)
const NATIVE_TOOLS = ["ls", "read", "write", "edit", "exec", "apply_patch", "web_fetch", "web_search"];

const zeroUsage = () => ({ input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } });

// OpenClaw session id -> claw session id, in the plugin's own state file
function sessionStore(stateDir) {
  const file = path.join(stateDir, "plugins", HARNESS_ID, "sessions.json");
  const read = () => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return {}; } };
  const write = (all) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file + ".tmp", JSON.stringify(all, null, 1)); fs.renameSync(file + ".tmp", file); };
  return {
    get: (id) => read()[id],
    set: (id, value) => { const all = read(); all[id] = value; write(all); },
    delete: (id) => { const all = read(); delete all[id]; write(all); },
  };
}

// Spawn claw and yield its events; `answer(obj)` writes a control line to its stdin.
function runClaw({ command, args, cwd, env, signal, onEvent }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let buffer = "", stderr = "", chain = Promise.resolve(), failed;
    const answer = (obj) => { if (!child.stdin.destroyed) child.stdin.write(JSON.stringify(obj) + "\n"); };
    const kill = () => { if (child.exitCode === null) child.kill("SIGTERM"); };
    signal.addEventListener("abort", kill, { once: true });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim(); buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let event; try { event = JSON.parse(line); } catch { continue; }
        if (!event || typeof event.type !== "string") continue; // claw's own non-stream JSON (e.g. its error envelope)
        chain = chain.then(() => onEvent(event, answer)).catch((error) => { failed ??= error; kill(); });
      }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-4000); });
    child.on("error", (error) => { signal.removeEventListener("abort", kill); reject(error); });
    child.on("close", (code, sig) => {
      signal.removeEventListener("abort", kill);
      chain.then(() => (failed ? reject(failed) : resolve({ code, signal: sig, stderr })), reject);
    });
  });
}

function createHarness(api) {
  const cfg = () => api.pluginConfig || {};
  const store = () => sessionStore(api.runtime.state.resolveStateDir());
  return {
    id: HARNESS_ID,
    label: LABEL,
    autoSelection: { providerIds: [] },
    authBootstrap: "harness", // claw brings its own credentials (env / the session's API proxy)
    executionEnvironment: "host-only",
    conversationToolPolicyNativeTools: NATIVE_TOOLS,
    supports: ({ requestedRuntime }) =>
      requestedRuntime === HARNESS_ID
        ? { supported: true, priority: 100 }
        : { supported: false, reason: `Choose ${LABEL} explicitly (agentRuntime.id "${HARNESS_ID}")` },
    async runAttempt(input) {
      const c = cfg();
      shim.runs++; writeStatus(c, { turnStarted: true });
      try { return await runClawAttempt({ api, input, cfg: c, sessions: store() }); }
      finally { shim.runs = Math.max(0, shim.runs - 1); writeStatus(c); }
    },
    async reset(input) { if (input.sessionId) store().delete(input.sessionId); },
    async withSessionDeletion(input, run) {
      let committed = false;
      try { return await run({ commit: () => { committed = true; }, rollback: () => { committed = false; } }); }
      finally { if (committed && input.sessionId) store().delete(input.sessionId); }
    },
    async dispose() {},
  };
}

// The status shim, same shape harness-opencode.sh writes: {pid, sessionId, name, nameSource, harness, status,
// statusUpdatedAt (moves on every status change AND every new turn), lastActivityMs, startedAt, bridgeSessionId}.
const shim = { runs: 0, approvals: 0, status: "", statusUpdatedAt: Date.now(), lastActivityMs: 0, startedAt: Date.now() };
function writeStatus(cfg, { turnStarted = false } = {}) {
  if (!cfg.statusFile) return;
  const status = shim.approvals ? "waiting" : shim.runs ? "busy" : "idle";
  if (status !== shim.status || turnStarted) { shim.status = status; shim.statusUpdatedAt = Date.now(); }
  if (turnStarted) shim.lastActivityMs = Date.now();
  const machine = process.env.SESSION_ID || process.env.FLY_MACHINE_ID || "";
  const entry = { pid: process.pid, sessionId: "openclaw", name: process.env.SESSION_LABEL || "",
    nameSource: process.env.SESSION_LABEL ? "harness" : "derived", harness: "openclaw", status,
    statusUpdatedAt: shim.statusUpdatedAt, lastActivityMs: shim.lastActivityMs, startedAt: shim.startedAt,
    bridgeSessionId: "openclaw:" + machine, activeRuns: shim.runs };
  try {
    fs.mkdirSync(path.dirname(cfg.statusFile), { recursive: true });
    fs.writeFileSync(cfg.statusFile + ".tmp", JSON.stringify(entry));
    fs.renameSync(cfg.statusFile + ".tmp", cfg.statusFile);
  } catch (e) { console.error(`[${HARNESS_ID}] status file: ${e.message}`); }
}

async function runClawAttempt({ api, input, cfg, sessions }) {
  if (!input.agentId || !input.sessionKey) throw new Error("claw-code needs an owned OpenClaw session");
  const { agentId, sessionKey } = input;
  const controller = new AbortController();
  const signal = AbortSignal.any([controller.signal, ...(input.abortSignal ? [input.abortSignal] : [])]);
  const assertActive = () => { signal.throwIfAborted(); input.hostCapabilities.assertActive(); };
  const transcript = { agentId, sessionKey, sessionId: input.sessionId, storePath: resolveStorePath(input.config?.session?.store, { agentId }) };
  const recorder = input.userTurnTranscriptRecorder;
  if (!recorder) throw new Error("claw-code needs its admitted transcript recorder");

  let started = false, settled = false, timedOut = false, failure, terminalAnchor, assistantKey, lastAssistant;
  let messages = [];
  const toolMetas = [];
  const assistantTexts = [];
  // the transcript rows this turn produces, in order: one assistant row per model response,
  // a toolResult row per tool call
  const rows = [];
  let current; // the assistant row being streamed
  let text = "", reasoning = "";
  const toolArgs = new Map();
  const activeRun = {
    kind: "embedded",
    runId: input.runId,
    toolAuthorityFingerprint: input.toolAuthorityFingerprint,
    queueMessage: async () => { throw new Error(`${LABEL} does not support live message injection`); },
    isStreaming: () => started && !settled,
    isAborted: () => signal.aborted,
    isCompacting: () => false,
    cancel: () => controller.abort(),
    abort: () => controller.abort(),
    sourceReplyDeliveryMode: input.sourceReplyDeliveryMode,
  };
  const emitTool = async (data) => {
    const item = projectAgentToolActivity(data);
    const base = { runId: input.runId, sessionKey, sessionId: input.sessionId };
    if (data.phase === "start") emitAgentEvent({ ...base, stream: "item", data: item });
    emitAgentEvent({ ...base, stream: "tool", data });
    if (data.phase !== "start") emitAgentEvent({ ...base, stream: "item", data: item });
    await input.onAgentEvent?.({ stream: "tool", data });
  };
  const newAssistant = () => ({
    role: "assistant", provider: input.provider, model: input.modelId, api: input.model?.api,
    content: [], stopReason: "stop", timestamp: Date.now(), usage: zeroUsage(),
  });
  const flushText = () => {
    if (!current) return;
    if (reasoning) current.content.push({ type: "thinking", thinking: reasoning });
    if (text) { current.content.push({ type: "text", text }); assistantTexts.push(text); }
    reasoning = ""; text = "";
  };

  let registered = false, timer;
  assertActive();
  try {
    setActiveEmbeddedRun(input.sessionId, activeRun, sessionKey, input.sessionFile, agentId);
    registered = true;
    input.replyOperation?.attachBackend(activeRun);
    timer = setTimeout(() => { timedOut = true; input.onAttemptTimeout?.(new Error("claw-code turn timed out")); controller.abort(); }, input.timeoutMs);
    timer.unref?.();

    const context = await SessionManager.openModelContextAsync(transcript, { cwd: input.workspaceDir, signal });
    messages = context.buildSessionContext().messages;
    assertActive();
    await recorder.persistApproved({ expectedSessionId: input.sessionId });
    assertActive();
    const admission = recorder.getAdmissionReceipt();
    if (recorder.isBlocked() || !recorder.hasPersisted() || !admission) throw new Error("claw-code input was not admitted to its transcript");

    const built = await resolveAgentHarnessBeforePromptBuildResult({
      prompt: input.prompt,
      currentInboundContext: input.currentInboundContext,
      messages,
      developerInstructions: [input.extraSystemPrompt].filter(Boolean).join("\n\n"),
      ctx: {
        runId: input.runId, agentId, sessionId: input.sessionId, sessionKey, workspaceDir: input.workspaceDir,
        config: input.config, trigger: input.trigger, modelProviderId: input.provider, modelId: input.modelId,
      },
      bootstrapContextRunKind: input.bootstrapContextRunKind,
    });
    if (built.toolsAllow) throw new Error("claw-code cannot enforce this prompt-hook tool restriction");

    const mapping = sessions.get(input.sessionId);
    const resume = mapping && mapping.cwd === input.workspaceDir ? mapping.clawSessionId : undefined;
    const prompt = [
      !resume && built.developerInstructions ? `Conversation instructions:\n${built.developerInstructions}` : undefined,
      built.prompt,
    ].filter(Boolean).join("\n\n");
    const mode = PERMISSION_MODES[cfg.permissionMode || "bypass"] || "danger-full-access";
    const env = {
      ...process.env,
      ...(cfg.env || {}),
      CLAW_EVENT_STREAM: "1",
      CLAW_CLAUDE_CODE_VERSION: cfg.claudeCodeVersion || process.env.CLAW_CLAUDE_CODE_VERSION || "2.1.287",
      ...(resume ? { CLAW_RESUME_SESSION: resume } : {}),
    };
    if (!resume) delete env.CLAW_RESUME_SESSION;
    const requestId = `${admission.entryId}:claw:${randomUUID()}`;
    let result, streamError;

    const onEvent = async (event, answer) => {
      assertActive();
      switch (event.type) {
        case "session":
          sessions.set(input.sessionId, { clawSessionId: event.session_id, cwd: input.workspaceDir });
          if (!started) { started = true; recorder.markSentToProvider?.(); input.onExecutionStarted?.(); }
          break;
        case "message_start":
          flushText();
          current = newAssistant(); rows.push(current);
          break;
        case "thinking_delta":
          if (event.text) { reasoning += event.text; await input.onReasoningStream?.({ text: reasoning }); }
          break;
        case "text_delta": {
          if (!current) { current = newAssistant(); rows.push(current); }
          if (!text && !assistantTexts.length) await input.onAssistantMessageStart?.();
          text += event.text;
          const update = { stream: "assistant", data: { text, delta: event.text } };
          emitAgentEvent({ runId: input.runId, sessionKey, sessionId: input.sessionId, ...update });
          await input.onAgentEvent?.(update);
          await input.onPartialReply?.({ text });
          break;
        }
        case "tool_use": {
          if (!current) { current = newAssistant(); rows.push(current); }
          flushText();
          const args = event.input && typeof event.input === "object" ? event.input : { input: event.input };
          current.content.push({ type: "toolCall", id: event.id, name: event.name, arguments: args });
          current.stopReason = "toolUse";
          toolArgs.set(event.id, args);
          toolMetas.push({ toolName: event.name, toolCallId: event.id, meta: undefined, isError: false });
          await emitTool({ phase: "start", name: event.name, toolCallId: event.id, args });
          break;
        }
        case "tool_result": {
          const meta = toolMetas.find((t) => t.toolCallId === event.id);
          if (meta) meta.isError = !!event.is_error;
          const output = String(event.output ?? "");
          rows.push({
            role: "toolResult", toolCallId: event.id, toolName: event.name,
            content: [{ type: "text", text: output }], isError: !!event.is_error, timestamp: Date.now(),
          });
          await emitTool({ phase: "result", name: event.name, toolCallId: event.id, isError: !!event.is_error,
            args: toolArgs.get(event.id), result: { content: [{ type: "text", text: output.slice(0, 20000) }] } });
          await input.onToolResult?.({ text: output });
          break;
        }
        case "message_stop":
          flushText();
          break;
        case "permission_request": {
          let allow = false, reason;
          shim.approvals++; writeStatus(cfg);
          try {
            const approvalSignal = signal;
            const requested = await input.hostCapabilities.requestApproval({
              title: `${LABEL} permission request`,
              description: event.reason || `${event.tool_name} needs ${event.required_mode}`,
              detail: JSON.stringify(event.input),
              signal: approvalSignal, severity: "warning", toolName: event.tool_name,
              allowedDecisions: ["allow-once", "deny"],
              timeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS, transportTimeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS + 10_000,
            });
            const decided = requested?.id
              ? await input.hostCapabilities.waitForApproval({
                  approvalId: requested.id, timeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS,
                  transportTimeoutMs: DEFAULT_PLUGIN_APPROVAL_TIMEOUT_MS + 10_000, signal: approvalSignal,
                })
              : undefined;
            allow = decided?.decision === "allow-once";
          } catch (error) {
            reason = `approval failed: ${toErrorObject(error, "approval failed").message}`;
          } finally { shim.approvals = Math.max(0, shim.approvals - 1); writeStatus(cfg); }
          answer({ type: "permission_response", request_id: event.request_id, allow, ...(reason ? { reason } : {}) });
          break;
        }
        case "result":
          result = event;
          break;
        case "error":
          streamError = event.message;
          break;
        default:
          break;
      }
    };

    const command = cfg.command || "claw";
    const exit = await runClaw({
      command,
      args: ["--model", input.modelId, "--permission-mode", mode, "--output-format", "json", "prompt", prompt],
      cwd: input.workspaceDir, env, signal, onEvent,
    });
    flushText();
    if (!signal.aborted && (streamError || exit.code !== 0) && !result) {
      throw new Error(`claw-code failed: ${streamError || exit.stderr.trim().split("\n").pop() || `exit ${exit.code}`}`);
    }
    // usage of the whole turn goes on the final assistant row
    let last = [...rows].reverse().find((row) => row.role === "assistant");
    if (!last) { last = newAssistant(); rows.push(last); }
    if (signal.aborted) last.stopReason = "aborted";
    if (result?.usage) {
      const u = result.usage;
      last.usage = { ...zeroUsage(), input: u.input_tokens || 0, output: u.output_tokens || 0,
        cacheRead: u.cache_read_input_tokens || 0, cacheWrite: u.cache_creation_input_tokens || 0,
        totalTokens: (u.input_tokens || 0) + (u.output_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0) };
    }
    if (!last.content.length) last.content.push({ type: "text", text: signal.aborted ? "(stopped)" : "" });
    for (const [i, row] of rows.entries()) {
      const key = `${requestId}:${i}`;
      const written = await appendSessionTranscriptMessageByIdentityStrict({
        ...transcript, config: input.config, runId: input.runId, updateMode: "inline",
        message: { ...row, idempotencyKey: key },
        prepareMessageAfterIdempotencyCheck: (message) => { input.hostCapabilities.assertActive(); return message; },
      });
      if (written.kind !== "result") throw new Error("claw-code transcript row was not committed");
      if (row === last) { assistantKey = key; terminalAnchor = written.result.anchor; rows[i] = written.result.message; last = written.result.message; }
    }
    messages = (await SessionManager.openModelContextAsync(transcript, { cwd: input.workspaceDir, through: terminalAnchor })).buildSessionContext().messages;
    lastAssistant = last;
  } catch (error) {
    failure = error;
  } finally {
    settled = true;
    clearTimeout(timer);
    if (registered) clearActiveEmbeddedRun(input.sessionId, activeRun, sessionKey, input.sessionFile);
  }
  return {
    terminal: timedOut
      ? { kind: "timeout", phase: "prompt", source: "runtime", aborted: true }
      : signal.aborted
        ? { kind: "aborted", source: "external" }
        : failure
          ? { kind: "failed", source: "prompt", error: failure }
          : { kind: "ok" },
    sessionIdUsed: input.sessionId,
    sessionFileUsed: input.sessionFile,
    agentHarnessId: HARNESS_ID,
    runtimeModelSelection: { provider: input.provider, model: input.modelId },
    messagesSnapshot: messages,
    assistantTexts,
    lastAssistant,
    currentAttemptAssistant: lastAssistant,
    ...(assistantKey ? { assistantTranscriptOwned: true, assistantTranscriptIdempotencyKey: assistantKey, contextEngineTerminalAnchor: terminalAnchor } : {}),
    toolMetas,
    didSendViaMessagingTool: false,
    messagingToolSentTexts: [],
    messagingToolSentMediaUrls: [],
    messagingToolSentTargets: [],
    cloudCodeAssistFormatError: false,
    replayMetadata: { hadPotentialSideEffects: toolMetas.length > 0, replaySafe: !started },
    itemLifecycle: { startedCount: toolMetas.length, completedCount: failure ? 0 : toolMetas.length, activeCount: 0 },
  };
}

export default definePluginEntry({
  id: HARNESS_ID,
  name: "claw-code harness",
  description: "Runs agent turns with the claw-code CLI; text and tool calls stream into OpenClaw.",
  register(api) {
    api.registerAgentHarness(createHarness(api));
  },
});
