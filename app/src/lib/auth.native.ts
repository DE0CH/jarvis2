// The app: sign-in belongs to the trusted shell. It opens /api/auth/start in the system sign-in sheet
// (ASWebAuthenticationSession), keeps the Access token from the jarvis2://auth redirect in its own
// Keychain and hands it to this UI over XPC; every request carries it as `cf-access-token`, never cookies.
// The router's address also comes from the shell (its Info.plist), so the shell and this UI always talk
// to the same router.
//
// A refusal = the request ended on Cloudflare Access's login (*.cloudflareaccess.com, redirects followed)
// or a 401/403 that isn't JSON, or the router's own 403 "Access login required": the token expired, so sign-in runs again
// and the request is retried once with the new token.
import { useSyncExternalStore } from "react";
import { shellSession, shellSignIn } from "./shell";

let baseUrl = "https://jarvis2.deyaochen.com/";
let token = "";
export const base = () => baseUrl;
export const fetchInit: RequestInit = { credentials: "omit" };

export type AuthState = { phase: "loading" | "signedOut" | "signingIn" | "ready"; note: string | null };
let state: AuthState = { phase: "loading", note: null };
const listeners = new Set<() => void>();
function set(s: AuthState) { state = s; listeners.forEach((l) => l()); }
export const useAuthState = () => useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => state);

export async function loadAuth() {
  try { const s = await shellSession(); baseUrl = s.base.endsWith("/") ? s.base : s.base + "/"; token = s.token; }
  catch (e: any) { set({ phase: "signedOut", note: "The shell did not answer: " + (e?.message || e) }); return; }
  set({ phase: "ready", note: null });
}
export async function authHeaders(): Promise<Record<string, string>> { return token ? { "cf-access-token": token } : {}; }

// one sign-in at a time, shared by every request refused meanwhile
let running: Promise<boolean> | null = null;
export function signIn(): Promise<boolean> {
  return (running ??= (async () => {
    set({ phase: "signingIn", note: null });
    try {
      const t = await shellSignIn();
      if (!t) { set({ phase: "signedOut", note: "Sign-in was cancelled." }); return false; }
      token = t; set({ phase: "ready", note: null }); return true;
    } catch (e: any) { set({ phase: "signedOut", note: "Sign-in failed: " + (e?.message || e) }); return false; }
    finally { running = null; }
  })());
}

let lastSignIn = 0;
export async function checkRefused(r: Response): Promise<"ok" | "retry"> {
  const ct = r.headers.get("content-type") || "";
  // the router checks the Access JWT too and answers 403 {"error":"Access login required"} without one
  const routerRefused = r.status === 403 && ct.includes("json") && (await r.clone().text().catch(() => "")).includes("Access login required");
  const refused = routerRefused || /(^|\.)cloudflareaccess\.com$/.test(hostOf(r.url)) || ((r.status === 401 || r.status === 403) && !ct.includes("json"));
  if (!refused) return "ok";
  // a token that is refused straight after a sign-in is not going to work on a second try either
  if (Date.now() - lastSignIn < 10_000) { set({ phase: "signedOut", note: "Cloudflare Access refused the new sign-in." }); throw new Error("signed out of Cloudflare Access"); }
  lastSignIn = Date.now();
  if (await signIn()) return "retry";
  throw new Error("signed out of Cloudflare Access");
}
function hostOf(u: string) { const m = /^https?:\/\/([^/:?#]+)/i.exec(u || ""); return m ? m[1].toLowerCase() : ""; }
