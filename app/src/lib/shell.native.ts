// The trusted iOS shell (Jarvis 2). This UI runs inside the shell's ExtensionKit extension. It can ask the
// shell to enter secure mode (with options that only pre-fill the shell's page), ask for the router's
// address + the Access token, and ask it to sign in. Only the shell leaves secure mode; it then tells this
// UI how the page ended.
import { NativeEventEmitter, NativeModules } from "react-native";

type Bridge = { requestSecureMode(options: string): void; session(): Promise<string>; signIn(): Promise<string> };
const bridge = NativeModules.ShellBridge as undefined | Bridge;
const events = bridge ? new NativeEventEmitter(NativeModules.ShellBridge) : null;
export const hasShell = !!bridge;
export type SecureKind = "new-session" | "approval" | "stores" | "pairing";
export type SecureResult = { requestId?: string; kind?: SecureKind; result: "done" | "back"; id?: string };

const newId = () => String(Date.now()) + Math.random().toString(16).slice(2);
/** Push the shell's secure page of this kind; `done` runs when the shell comes back from it. */
export function requestSecure(kind: SecureKind, options: Record<string, unknown>, done?: (r: SecureResult) => void) {
  const requestId = String(options.requestId || newId());
  const sub = events?.addListener("secureFinished", (body: string) => {
    let r: SecureResult = { result: "back" };
    try { r = JSON.parse(body); } catch {}
    if (r.requestId && r.requestId !== requestId) return;
    sub?.remove();
    done?.(r);
  });
  bridge?.requestSecureMode(JSON.stringify({ ...options, kind, requestId }));
}
export async function shellSession(): Promise<{ base: string; token: string }> {
  if (!bridge) throw new Error("no shell");
  return JSON.parse(await bridge.session());
}
export async function shellSignIn(): Promise<string> { return bridge ? bridge.signIn() : ""; }
