// Thin JSON client for the Jarvis 2 router (docs/API.md), shared by the web page and the app. Paths are
// written "api/state"; auth.ts / auth.native.ts say where they go and how the request is authorised.
import { base, fetchInit, authHeaders, checkRefused } from "./auth";

export const url = (path: string) => base() + path.replace(/^\//, "");

// What a failed request means, in words. The router answers errors as JSON {error}; errors that come
// from the core arrive as the core's signed error document {payload, sig} (payload {kind:"error", error});
// the layers in front of it (Cloudflare) answer plain text or HTML, and a dropped connection is only the
// platform's bare "Load failed" / "Network request failed".
const STATUS_HINT: Record<number, string> = {
  400: "bad request", 401: "not authorised", 403: "forbidden", 404: "not found", 409: "conflict",
  413: "request too large", 423: "locked", 429: "rate-limited — try again shortly", 500: "router error",
  502: "bad gateway — the router or the core dropped the request",
  503: "unavailable — the router is restarting",
  504: "timed out — no response from the router in time",
};
export function reasonOf(text: string): string {
  let j: any = null; try { j = JSON.parse(text); } catch {}
  if (j && typeof j === "object") {
    if (typeof j.payload === "string") { try { const p = JSON.parse(j.payload); if (p && p.error) return "core: " + p.error; } catch {} }
    return String(j.error || j.message || "");
  }
  return text.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}
export function httpError(method: string, path: string, status: number, text: string): Error {
  const reason = reasonOf(text), hint = STATUS_HINT[status] || (status >= 500 ? "server error" : "request failed");
  const e: any = new Error(`${reason || hint} (HTTP ${status}${reason ? " " + hint : ""} · ${method} ${path})`);
  e.status = status;
  try { e.body = JSON.parse(text); } catch {} // e.g. 403 {needsGrant, phoneGrant}
  return e;
}
export function networkError(method: string, path: string, e: any): Error {
  const offline = typeof navigator !== "undefined" && (navigator as any).onLine === false;
  const why = offline ? "this device is offline" : "the connection to the router dropped or never opened";
  return new Error(`network error: ${why} — ${method} ${path}${e?.message ? " · " + e.message : ""}`);
}
export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  let r: Response;
  for (;;) {
    try {
      r = await fetch(url(path), {
        ...fetchInit, method,
        headers: { ...(await authHeaders()), ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (e) { throw networkError(method, path, e); }
    if ((await checkRefused(r)) === "ok") break;
  }
  const text = await r.text().catch(() => "");
  if (!r.ok) throw httpError(method, path, r.status, text);
  try { return JSON.parse(text) as T; }
  catch { throw new Error(`the router answered ${method} ${path} with something that isn't JSON: ${reasonOf(text) || "(empty body)"}`); }
}

// ---- the router's shapes (docs/API.md) ----
export type SessionState = "starting" | "approval" | "initialising" | "started" | "pausing" | "paused" | "resuming" | "destroying" | "failed";
export type Wakeup = { name: string; at: number; atIso?: string; prompt: string };
export type Cron = { name: string; prompt: string; everySeconds: number; tz?: string; nextAt: number; nextAtIso?: string; until?: number | null; untilIso?: string | null; runs?: number; lastFiredIso?: string | null };
export type Refusal = { kind: "fallback" | "refusal"; at?: string; from?: string; to?: string; model?: string; category?: string };
export type Session = {
  id: string; machineId?: string | null; released?: boolean; name?: string; state: SessionState | string; status?: string | null;
  created?: string; region?: string; environment?: string; harness?: string; label?: string; model?: string;
  permissionMode?: string; guest?: string; stores?: string[] | null; size?: string; image?: string; pausedAt?: string | null; error?: string | null; title?: string; destroyedAt?: string;
  // live fields (docs/API.md "Sessions"): the machine's report, the autopilot's settings, the schedule
  aiTitle?: string; liveName?: string; userTitle?: string; bgTasks?: number; needsGrant?: string; pauseInMs?: number;
  autoPause?: "on" | "off"; notifyIdle?: "on" | "off"; oneShot?: boolean; oneShotDone?: boolean; authFailed?: boolean;
  credsExpiresAt?: string | number; discordChannel?: string; statusUpdatedAt?: string; lastReport?: string; refusals?: Refusal[];
  wakeups?: Wakeup[]; crons?: Cron[]; resumePrompt?: string; createRequestId?: string; repos?: string;
  // a lifecycle action holding the session (others are refused 409) and a permission-mode / restart job
  busy?: { kind: string; since?: string } | null; wake?: { kind: string; phase: string; error?: string } | null; apiProxy?: "on" | "off";
};
export type RepoEntry = { name: string; url: string };
export type GhRepo = { fullName: string; url: string; htmlUrl: string; description?: string; language?: string; private?: boolean; fork?: boolean; archived?: boolean; pushedAt?: string };
export type UsageLimit = { kind: string; group: string; percent: number; severity?: string; resetsAt: string | null; model: string | null; surface: string | null; active: boolean };
export type Usage = {
  fetchedAt: string; cached?: boolean; stale?: boolean; error?: string;
  limits: UsageLimit[];
  extraUsage: { enabled: boolean; monthlyLimit: number; usedCredits: number; utilization: number; currency: string; decimalPlaces: number; disabledReason?: string | null; spendLimitReached: boolean } | null;
};
export function fromNow(iso: string | Date) { const d = new Date(iso).getTime() - Date.now(); return d < 0 ? ago(iso) : "in " + ago(new Date(Date.now() - d)).replace(" ago", "").replace("just now", "a moment"); }
export type TailMessage = { role: "user" | "assistant"; text: string; at?: string };
export type ArchiveInfo = { dir: string; title: string; transcripts: string[]; artifacts: number; signer?: string; snapshotAt?: string; last?: TailMessage | null };
/** a destroyed session (GET api/records): the session's fields plus where its archive is */
export type Rec = Session & { destroyedAt: string; archive?: ArchiveInfo | null; archiveError?: string; restored?: { sessionId: string; at: string }[]; live?: { oneShot?: boolean } };
export type Grant = { id: string; session: string; holder: string; kind: "grant" | "rule"; ends: string };
export type Budget = { month: string; spentUsd: number; capUsd: number; warnUsd: number; warned: boolean; capped: boolean; cappedAt?: string | null; ratePerHour: number; perMonth: number; running: number; volumes: number; sampledAt?: string | null };
export type FlyOther = { kind: string; app: string; id: string; name?: string; state?: string; region?: string; created?: string; detail?: string };
export type FlyView = { apps: number; machines: number; volumes: number; other: FlyOther[]; error?: string | null; checkedAt?: string | null };
export type SignedDoc = { payload: string; sig: string };
export type ApprovalKind = "new-session" | "resume-upgrade" | "add-store";
export type Approval = {
  id: string; kind: ApprovalKind; created?: string; session?: string | null; label?: string;
  challenge: SignedDoc; machine?: string; options?: Record<string, unknown>;
};
export type CoreStatus = { up: boolean; signingKey?: string; agreementKey?: string };
export type State = {
  sessions: Session[]; approvals: Approval[]; core: CoreStatus;
  budget?: Budget | null; fly?: FlyView | null; flyApp?: string; repos?: RepoEntry[];
  loadError?: string | null; // client-side: the last api/state fetch failed
  loaded?: boolean; // client-side: api/state has answered at least once
};
export type Choice = { id: string; label: string; harness?: string };
// a store as the core lists it (payload of POST api/core/stores). Read here only for display and
// pre-selection; the shell verifies the core's signature before anything is signed.
export type CoreStore = { name: string; sensitive: boolean; empty: boolean; unlocked: boolean };
// which stores each harness brings (GET api/policy): the router adds them to a session, so the app
// doesn't offer them in pickers or list them in summaries
export type Policy = Record<string, string[]>;
export async function loadPolicy(): Promise<Policy> {
  const j = await api<{ harnesses?: Record<string, { stores?: string[] }> }>("GET", "api/policy");
  const out: Policy = {};
  for (const [h, v] of Object.entries(j.harnesses || {})) out[h] = v.stores || [];
  return out;
}
export const harnessStoreSet = (p: Policy) => new Set(Object.values(p).flat());

/** the core's store list, unverified (the web page and the normal-mode UI only show it) */
export async function coreStores(): Promise<CoreStore[]> {
  const d = await api<SignedDoc>("POST", "api/core/stores", { nonce: newId() });
  const p = JSON.parse(d.payload);
  if (p.kind !== "stores") throw new Error("the core's store list has the wrong kind");
  return p.stores || [];
}

/** what a challenge asks for, read for display only (the shell checks it before signing) */
export function challengeRequest(a: Approval, p: Policy = {}): { stores: string[]; sensitive: string[]; harness: string; addedStore?: string; permissionMode?: string } {
  try {
    const r = JSON.parse(a.challenge.payload).request || {};
    const harness = r.options?.harness || "claude", h = new Set(p[harness] || []);
    return { stores: (r.stores || []).filter((n: string) => !h.has(n)), sensitive: r.sensitive || [], harness, addedStore: r.addedStore || undefined, permissionMode: r.options?.permissionMode === "bypass" ? "bypass" : "auto" };
  } catch { return { stores: [], sensitive: [], harness: "?" }; }
}

export const newId = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));

export const REGION: Record<string, string> = { arn: "Stockholm", fra: "Frankfurt", ams: "Amsterdam", lhr: "London", cdg: "Paris", waw: "Warsaw", mad: "Madrid", iad: "Virginia", ord: "Chicago", sjc: "San Jose", lax: "Los Angeles", sin: "Singapore", nrt: "Tokyo", hkg: "Hong Kong", syd: "Sydney" };
export const HARNESS: Record<string, string> = { claude: "Claude Code", opencode: "OpenCode", openclaw: "OpenClaw" };
export function ago(iso: string | Date) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago"; if (s < 86400) return Math.floor(s / 3600) + " h ago"; return Math.floor(s / 86400) + " d ago";
}
export const sessionTitle = (m: Session) => m.userTitle || m.label || m.aiTitle || m.title || m.name || m.id;
export const usd = (n: number) => "USD " + (Math.round(n * 100) / 100).toFixed(2);
/** "at 07:52" / "Oct 12 07:52", with how far away it is */
export function when(at: number | string) {
  const t = typeof at === "number" ? at : Date.parse(at);
  const d = new Date(t), now = new Date();
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const mins = Math.round((t - Date.now()) / 60000);
  const rel = mins < 1 ? "now" : mins < 120 ? `in ${mins} min` : mins < 48 * 60 ? `in ${Math.round(mins / 60)} h` : `in ${Math.round(mins / 1440)} d`;
  return `${d.toDateString() === now.toDateString() ? "at " + hm : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm} (${rel})`;
}
/** "daily" / "every 6 h" / "every 3 d" */
export function cronEvery(sec: number) {
  return sec === 86400 ? "daily" : sec === 604800 ? "weekly" : sec % 86400 === 0 ? `every ${sec / 86400} d` : sec % 3600 === 0 ? `every ${sec / 3600} h` : `every ${Math.round(sec / 60)} min`;
}
// the features that may hold a grant (router/grants.go), in words — the shell's grant page says the same
export const HOLDERS: Record<string, { title: string; sub: string }> = {
  terminal: { title: "Terminal", sub: "read the screen and type into the session" },
  scheduler: { title: "Scheduler", sub: "deliver wakeups and crons as messages" },
  status: { title: "Status", sub: "read the screen, press Escape on a prompt left waiting" },
  login: { title: "Login repair", sub: "write fresh Claude credentials and send “continue”" },
  archive: { title: "Archive check", sub: "list uncommitted work before a destroy" },
  remote: { title: "Remote page", sub: "read the web UI's link and the pairing offer or gateway token" },
};
export const holderTitle = (h: string) => HOLDERS[h]?.title || h;
// the store named `core` holds the core's own Fly token: it never shows for sessions (the core keeps it out of
// its store list; the filter is only a second guard)
export const CORE_STORE = "core";
/** the stores a session (or a record) was given, without the ones its harness brought */
export const storesOf = (m: Session, p: Policy = {}) => {
  const all = m.stores && m.stores.length ? m.stores : (m.environment || "").split(",").filter(Boolean);
  const h = new Set(p[m.harness || "claude"] || []);
  return all.filter((n) => !h.has(n) && n !== CORE_STORE);
};

// ---- tasks (docs/API.md "Tasks"): templates, instances (each a session line on harness task:<template>), runs,
// daily schedules — Jarvis 1's shapes where the meaning is the same
export type TaskOption = { value: string; label: string; sub?: string };
export type TaskField = { name: string; label: string; type: "text" | "textarea" | "number" | "select" | "multiselect" | "checkbox"; required: boolean; default?: unknown; options?: TaskOption[]; optionsFrom?: string; help?: string; placeholder?: string };
export type TaskTemplate = { name: string; title: string; description?: string; run?: string; prompt?: string; stores?: string[]; timeoutSeconds?: number; size?: string; fields: TaskField[]; files?: string[]; source?: string; error?: string };
export type TaskRunPhase = "queued" | "starting" | "running" | "succeeded" | "failed" | "timedout" | "stopped" | "lost";
export type TaskRun = { id: string; name: string; instance: string; instanceName?: string; template: string; trigger: "manual" | "schedule"; schedule?: string | null; slot?: string | number | null; upgrade?: boolean;
  phase: TaskRunPhase; createdAt?: string | null; resumedAt?: string | null; startedAt?: string | null; ranAt?: string | null; finishedAt?: string | null; exitCode?: number | null; reason?: string | null; waiting?: string | null; tail?: string[] | null; logBytes?: number; outputBytes?: number };
export type TaskInstance = { id: string; template: string; name: string; params: Record<string, unknown>; size?: string; stores?: string[]; session: string | null; createdAt: string; updatedAt?: string | null;
  state: "approval" | "ready" | "running" | "busy" | "failed" | "gone"; detail?: string; sessionState?: string; image?: string | null; lastRun: TaskRun | null; activeRun: TaskRun | null; queued: number; schedules: number };
export type TaskSchedule = { id: string; instance: string; time: string; tz: string; enabled: boolean; since: number; createdAt: string; nextAt: number | null };
export type TasksOverview = { sessionImage?: string | null; templates: TaskTemplate[]; instances: TaskInstance[]; schedules: TaskSchedule[] };
export const RUN_ACTIVE = (p: TaskRunPhase) => p === "queued" || p === "starting" || p === "running";
export const isTaskLine = (m: Session) => (m.harness || "").startsWith("task:");
