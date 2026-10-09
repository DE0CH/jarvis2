// Grants (docs/DESIGN.md "Grants"): a router feature (holder) may run commands in a session only while the
// phone allows it. This UI lists and forgets them; making one happens on the shell's secure grant page, which
// shows what it means and signs it with the phone's key — this UI only opens that page with a pre-selection.
import { api, type Grant } from "./api";
import { refresh, settle, toast } from "./store";
import { hasShell, requestSecure } from "./shell";

export const loadGrants = (sid: string) => api<{ grants: Grant[] }>("GET", `api/sessions/${sid}/grants`).then((j) => j.grants || []);
export const liveGrant = (gs: Grant[], holder: string) => gs.find((g) => g.holder === holder && Date.parse(g.ends) > Date.now());

/** Open the shell's grant page for this session (the app only); `done` runs once it comes back. */
export function requestGrant(sid: string, label: string, pre: { holder?: string; kind?: "grant" | "rule"; minutes?: number }, done?: (ok: boolean) => void) {
  if (!hasShell) { toast("Grants are signed in the Jarvis 2 app on the iPhone."); return; }
  requestSecure("grant", { sessionId: sid, label, ...pre }, (r) => {
    if (r.result === "done") { toast("Signed — the grant is saved.", "ok"); refresh(false); settle(20000); }
    done?.(r.result === "done");
  });
}
export const forgetGrant = (g: Grant) => api("DELETE", `api/grants/${g.id}`);
