// The trusted iOS shell. On the web there is no shell: secure mode doesn't exist there, approvals happen
// only in the app.
export const hasShell = false;
export type SecureKind = "new-session" | "approval" | "stores" | "setup" | "grant";
export type SecureResult = { requestId?: string; kind?: SecureKind; result: "done" | "back"; id?: string };
export function requestSecure(_kind: SecureKind, _options: Record<string, unknown>, _done?: (r: SecureResult) => void) {}
export async function shellSession(): Promise<{ base: string; token: string }> { return { base: "/", token: "" }; }
export async function shellSignIn(): Promise<string> { return ""; }
