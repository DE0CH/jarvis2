// One external store for everything the UI polls, read from components with useSyncExternalStore.
// Nothing in here is optimistic: cards only change when the router reports the new state; in-flight
// actions show as PENDING labels on their buttons.
import { useSyncExternalStore } from "react";
import { AppState, Platform } from "react-native";
import { api, coreStores, loadPolicy, type Choice, type CoreStore, type Policy, type Session, type State } from "./api";

export type Tab = "sessions" | "stores" | "records" | "settings";
export const TABS: [Tab, string][] = [["sessions", "Sessions"], ["stores", "Stores"], ["records", "Records"], ["settings", "Settings"]];
// a list loaded on demand (records, the core's store list), not part of the 15 s poll
export type Loaded<T> = { loading: boolean; loaded: boolean; items: T[]; err: string | null };
export type Toast = { id: number; text: string; kind: "info" | "ok" | "error" };
// a pending yes/no question, shown as a centered dialog (App renders it); resolve gets the answer.
// `input`: a text box inside the same dialog; `match`: it must hold exactly this text before the
// action is enabled (a type-the-name guard for an irreversible action)
export type AskInput = { heading: string; label: string; placeholder?: string; note?: string; max?: number; match?: string };
export type Confirm = { title: string; detail?: string; action: string; danger?: boolean; input?: AskInput; resolve: (ok: boolean, text: string) => void };
type Store = {
  state: State; tab: Tab; pending: Map<string, string>; records: Loaded<Session>; stores: Loaded<CoreStore>;
  toasts: Toast[]; confirm: (Confirm & { id: number }) | null; sizes: Choice[]; models: Choice[]; refreshing: boolean; policy: Policy;
};
const empty = <T,>(): Loaded<T> => ({ loading: false, loaded: false, items: [], err: null });
const S: Store = {
  state: { sessions: [], approvals: [], core: { up: false } },
  tab: "sessions", pending: new Map(), records: empty(), stores: empty(),
  sizes: [], models: [], refreshing: false, toasts: [], confirm: null, policy: {},
};
const listeners = new Set<() => void>();
let snap = { ...S };
function emit() { snap = { ...S }; listeners.forEach((l) => l()); }
export function useStore<T>(sel: (s: Store) => T): T {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => sel(snap), () => sel(snap));
}
export const getStore = () => snap;

export function setTab(t: Tab) { S.tab = t; emit(); if (t === "records") loadRecords(); if (t === "stores") loadStores(); }
export function pend(key: string, label: string | null) { label ? S.pending.set(key, label) : S.pending.delete(key); S.pending = new Map(S.pending); emit(); }

// ---- notices: no alert()/confirm() — toasts at the bottom of the screen, questions as dialogs ----
let toastSeq = 0;
export function toast(text: string, kind: Toast["kind"] = "info", ms = kind === "error" ? 8000 : 5000) {
  const id = ++toastSeq; S.toasts = [...S.toasts, { id, text, kind }]; emit();
  setTimeout(() => dismissToast(id), ms);
}
export function dismissToast(id: number) { if (S.toasts.some((t) => t.id === id)) { S.toasts = S.toasts.filter((t) => t.id !== id); emit(); } }
// questions queue: a new ask() while one is up waits for it to be answered
let askSeq = 0;
const asks: (Confirm & { id: number })[] = [];
function enqueue(c: Confirm) { asks.push({ ...c, id: ++askSeq }); if (!S.confirm) { S.confirm = asks[0]; emit(); } }
/** Ask a yes/no question; resolves true when the action button is tapped, false on Cancel/dismiss. */
export function ask(q: Omit<Confirm, "resolve" | "input">): Promise<boolean> {
  return new Promise((resolve) => enqueue({ ...q, resolve: (ok) => resolve(ok) }));
}
export function answer(ok: boolean, text = "") {
  const c = S.confirm; if (!c) return;
  asks.shift(); S.confirm = asks[0] || null; emit(); c.resolve(ok, text);
}

// ---- concurrency primitives ---------------------------------------------------------------
// Every read of server state goes through coalesce(): one request at a time, and a call while one is
// running gets ONE follow-up request that starts after it (never the running one, which was sent before
// the caller's change and would hand back the old state).
function coalesce(fn: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null, next: Promise<void> | null = null;
  const start = (): Promise<void> => (running = fn().finally(() => { running = null; }));
  return () => {
    if (!running) return start();
    const after = () => { next = null; return start(); };
    return (next ??= running.then(after, after));
  };
}
// Every user action runs under a key (a session's is "s:<id>"): one run per key at a time, whichever
// button or menu started it.
const actions = new Map<string, Promise<unknown>>();
export function exclusive<T>(key: string, fn: () => Promise<T>): Promise<T | undefined> {
  const cur = actions.get(key);
  if (cur) { toast("Still busy with the last action — this can run once that finishes."); return cur as Promise<T | undefined>; }
  const p = fn().finally(() => actions.delete(key));
  actions.set(key, p);
  return p;
}
export function failed(e: any, prefix = "") { toast(prefix + (e?.message || String(e)), "error"); }
/** Poll api/state until pred holds (or maxMs passes). */
export async function refreshUntil(pred: (s: State) => boolean, maxMs: number) {
  const until = Date.now() + maxMs;
  while (Date.now() < until) { await refresh(false); if (pred(S.state)) return true; await new Promise((r) => setTimeout(r, 1000)); }
  return false;
}
// Run an action and keep its button pending until the router CONFIRMS the outcome (pred).
export function pendUntil(key: string, label: string, action: () => Promise<unknown>, pred: (s: State) => boolean, maxMs = 60000) {
  return exclusive(key, async () => {
    pend(key, label);
    try { await action(); await refreshUntil(pred, maxMs); }
    catch (e: any) { failed(e); await refresh(false); }
    finally { pend(key, null); }
  });
}

// ---- polling: 15 s idle, 2 s while something is settling ----------------------------------
let fastUntil = 0;
const pollState = coalesce(async () => {
  try {
    const st = await api<State>("GET", "api/state");
    S.state = { sessions: st.sessions || [], approvals: st.approvals || [], core: st.core || { up: false }, loaded: true, loadError: null };
  } catch (e: any) { S.state = { ...S.state, loadError: e.message }; }
  S.refreshing = false; emit();
  // a session is on its way somewhere: follow it closely
  if (S.state.sessions.some((m) => ["starting", "approval", "initialising", "pausing", "resuming", "destroying"].includes(m.state))) fastUntil = Math.max(fastUntil, Date.now() + 4000);
});
export function refresh(manual = false): Promise<void> {
  if (manual) { S.refreshing = true; emit(); if (S.tab === "records") loadRecords(); if (S.tab === "stores") loadStores(); }
  return pollState();
}
export function settle(maxMs = 90000) { fastUntil = Math.max(fastUntil, Date.now() + maxMs); }
// Nothing polls until the app is signed in (start(), from the root layout).
let lastPoll = 0, started = false;
export function start() {
  if (started) return; started = true;
  setInterval(async () => {
    if (Date.now() < fastUntil || Date.now() - lastPoll >= 15000) { lastPoll = Date.now(); await refresh(false); }
  }, 2000);
  // back in the foreground: refresh at once (this is also where an expired login gets noticed)
  AppState.addEventListener("change", (st) => { if (st === "active") refresh(false); });
  api<{ sizes: Choice[] }>("GET", "api/sizes").then((j) => { S.sizes = j.sizes || []; emit(); }).catch(() => {});
  api<{ models: Choice[] }>("GET", "api/models").then((j) => { S.models = j.models || []; emit(); }).catch(() => {});
  loadPolicy().then((p) => { S.policy = p; emit(); }).catch(() => {});
  refresh(true);
}

export const loadRecords = coalesce(async () => {
  S.records = { ...S.records, loading: true }; emit();
  try { const j = await api<{ records: Session[] }>("GET", "api/records"); S.records = { ...S.records, items: j.records || [], err: null, loaded: true }; }
  catch (e: any) { S.records = { ...S.records, err: e.message }; }
  S.records = { ...S.records, loading: false }; emit();
});
export const loadStores = coalesce(async () => {
  S.stores = { ...S.stores, loading: true }; emit();
  try { S.stores = { ...S.stores, items: await coreStores(), err: null, loaded: true }; }
  catch (e: any) { S.stores = { ...S.stores, err: e.message }; }
  S.stores = { ...S.stores, loading: false }; emit();
});

// read hooks for a browser test
if (Platform.OS === "web" && typeof window !== "undefined") {
  (window as any).getState = () => S.state;
  (window as any).__refresh = () => refresh(false);
}
