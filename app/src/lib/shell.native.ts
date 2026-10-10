// The trusted iOS shell (Jarvis 2). This UI runs inside the shell's ExtensionKit extension. It can ask the
// shell to enter secure mode (with options that only pre-fill the shell's page), ask for the router's
// address + the Access token, and ask it to sign in. Only the shell leaves secure mode; it then tells this
// UI how the page ended.
import { NativeEventEmitter, NativeModules } from "react-native";

type Bridge = { requestSecureMode(options: string): void; secureSettled(requestId: string): void; session(): Promise<string>; signIn(): Promise<string> };
const bridge = NativeModules.ShellBridge as undefined | Bridge;
const events = bridge ? new NativeEventEmitter(NativeModules.ShellBridge) : null;
export const hasShell = !!bridge;
export type SecureKind = "new-session" | "approval" | "stores" | "setup" | "grant" | "unlock" | "repo-key";
export type SecureResult = { requestId?: string; kind?: SecureKind; result: "done" | "back"; id?: string };

const newId = () => String(Date.now()) + Math.random().toString(16).slice(2);
const waiting = new Map<string, (r: SecureResult) => void>();
// The app has drawn real content (the list, the sign-in screen or the error saying why not), not a blank first
// frame: the root layout says so (markAppReady). Until then the shell keeps its page up, e.g. Done on Reset or
// recover at first launch, while the bundle is still starting.
let ready = false;
const readyWaiters: (() => void)[] = [];
export function markAppReady() { if (ready) return; ready = true; readyWaiters.splice(0).forEach((f) => f()); }
const whenReady = (f: () => void) => { if (ready) f(); else readyWaiters.push(f); };
// One listener for the app's whole life (also for a page the shell opened by itself, e.g. Reset or recover at
// launch). The shell holds its page over the app until this UI has handled the result and drawn it (a form
// closed after Create), then reveals the app: so the answer goes back once the callback's work is on screen.
events?.addListener("secureFinished", (body: string) => {
  let r: SecureResult = { result: "back" };
  try { r = JSON.parse(body); } catch {}
  const done = r.requestId ? waiting.get(r.requestId) : undefined;
  if (r.requestId) waiting.delete(r.requestId);
  try { done?.(r); } catch {}
  // useDone closes a page 50 ms after setting its animation; then two frames for the change to reach the screen
  whenReady(() => setTimeout(() => requestAnimationFrame(() => requestAnimationFrame(() => bridge?.secureSettled(r.requestId || ""))), 120));
});
/** Push the shell's secure page of this kind; `done` runs when the shell comes back from it, before the app is
 *  revealed again (so a page it closes is already gone when the shell's page slides away). */
export function requestSecure(kind: SecureKind, options: Record<string, unknown>, done?: (r: SecureResult) => void) {
  const requestId = String(options.requestId || newId());
  if (done) waiting.set(requestId, done);
  bridge?.requestSecureMode(JSON.stringify({ ...options, kind, requestId }));
}
export async function shellSession(): Promise<{ base: string; token: string }> {
  if (!bridge) throw new Error("no shell");
  return JSON.parse(await bridge.session());
}
export async function shellSignIn(): Promise<string> { return bridge ? bridge.signIn() : ""; }
