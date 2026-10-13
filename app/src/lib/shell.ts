// The trusted iOS shell. On the web there is no shell: secure mode doesn't exist there. What would open a secure
// page files a request in the phone's Inbox instead (lib/inbox.ts): a repo key, a grant, an unlock — Deyao then
// approves it with Face ID in the app. `done` gets "back" (nothing was signed here).
import { fileFromWeb } from "./inbox";
export const hasShell = false;
export type SecureKind = "new-session" | "approval" | "stores" | "setup" | "grant" | "unlock" | "repo-key" | "restore";
export type SecureResult = { requestId?: string; kind?: SecureKind; result: "done" | "back"; id?: string };
export function requestSecure(kind: SecureKind, options: Record<string, unknown>, done?: (r: SecureResult) => void) {
  fileFromWeb(kind, options).finally(() => done?.({ kind, result: "back" }));
}
/** the web page can ask the phone for these (an Inbox request); the rest happen only in the app */
export const webAsks = (kind: SecureKind) => kind === "repo-key" || kind === "grant" || kind === "unlock" || kind === "restore";
export function markAppReady() {}
export async function shellSession(): Promise<{ base: string; token: string }> { return { base: "/", token: "" }; }
export async function shellSignIn(): Promise<string> { return ""; }
