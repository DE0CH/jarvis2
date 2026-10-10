// New session: in the app it is ONE page in the shell (secure: the stores, harness, every option, and Start under
// Face ID, which also unlocks the session's locked stores); on the web it is the form in pages/NewSession.tsx,
// which only files a request the app approves.
import { newId } from "./api";
import { refresh, settle } from "./store";
import { hasShell, requestSecure } from "./shell";
import { openPage } from "../ui/page";

export function openNewSession() {
  if (!hasShell) { openPage("new"); return; }
  requestSecure("new-session", { requestId: newId() }, (r) => { if (r.result === "done") { refresh(false); settle(120000); } });
}
