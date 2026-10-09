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
export type Session = {
  id: string; machineId?: string | null; released?: boolean; name?: string; state: SessionState | string; status?: string | null;
  created?: string; region?: string; environment?: string; harness?: string; label?: string; model?: string;
  permissionMode?: string; guest?: string; stores?: string[] | null; size?: string; image?: string; pausedAt?: string | null; error?: string | null; title?: string; destroyedAt?: string;
};
export type SignedDoc = { payload: string; sig: string };
export type ApprovalKind = "new-session" | "resume-upgrade" | "add-store";
export type Approval = {
  id: string; kind: ApprovalKind; created?: string; session?: string | null; label?: string;
  challenge: SignedDoc; machine?: string; options?: Record<string, unknown>;
};
export type CoreStatus = { up: boolean; signingKey?: string; agreementKey?: string };
export type State = {
  sessions: Session[]; approvals: Approval[]; core: CoreStatus;
  loadError?: string | null; // client-side: the last api/state fetch failed
  loaded?: boolean; // client-side: api/state has answered at least once
};
export type Choice = { id: string; label: string };
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
export function challengeRequest(a: Approval, p: Policy = {}): { stores: string[]; sensitive: string[]; harness: string; addedStore?: string } {
  try {
    const r = JSON.parse(a.challenge.payload).request || {};
    const harness = r.options?.harness || "claude", h = new Set(p[harness] || []);
    return { stores: (r.stores || []).filter((n: string) => !h.has(n)), sensitive: r.sensitive || [], harness, addedStore: r.addedStore || undefined };
  } catch { return { stores: [], sensitive: [], harness: "?" }; }
}

export const newId = () => (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));

export const REGION: Record<string, string> = { arn: "Stockholm", fra: "Frankfurt", ams: "Amsterdam", lhr: "London", cdg: "Paris", waw: "Warsaw", mad: "Madrid", iad: "Virginia", ord: "Chicago", sjc: "San Jose", lax: "Los Angeles", sin: "Singapore", nrt: "Tokyo", hkg: "Hong Kong", syd: "Sydney" };
export const HARNESS: Record<string, string> = { claude: "Claude Code", opencode: "OpenCode" };
export function ago(iso: string | Date) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + " min ago"; if (s < 86400) return Math.floor(s / 3600) + " h ago"; return Math.floor(s / 86400) + " d ago";
}
export const sessionTitle = (m: Session) => m.title || m.label || m.name || m.id;
// the store named `core` holds the core's own Fly token: it never shows for sessions (the core keeps it out of
// its store list; the filter is only a second guard)
export const CORE_STORE = "core";
/** the stores a session (or a record) was given, without the ones its harness brought */
export const storesOf = (m: Session, p: Policy = {}) => {
  const all = m.stores && m.stores.length ? m.stores : (m.environment || "").split(",").filter(Boolean);
  const h = new Set(p[m.harness || "claude"] || []);
  return all.filter((n) => !h.has(n) && n !== CORE_STORE);
};
