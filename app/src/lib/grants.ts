// Grants (docs/DESIGN.md "Grants"): a router feature (holder) may run commands in a session only while the
// phone allows it. This UI lists and forgets them; making one happens on the shell's secure grant page, which
// shows what it means and signs it with the phone's key — this UI only opens that page with a pre-selection.
import { api, type Grant } from "./api";
import { refresh, settle, toast } from "./store";
import { hasShell, requestSecure } from "./shell";

export const loadGrants = (sid: string) => api<{ grants: Grant[] }>("GET", `api/sessions/${sid}/grants`).then((j) => j.grants || []);
export const liveGrant = (gs: Grant[], holder: string) => gs.find((g) => g.holder === holder && Date.parse(g.ends) > Date.now());

/** Open the shell's grant page for this session (the app only); `done` runs once it comes back. */
export const RULE_DAYS = 30;
/** Ask the phone for exactly this: the shell's grant page shows it in words, with Allow (Face ID) and Deny — nothing
 *  on that page can be changed, so the request is complete here (a standing rule without an end gets 30 days). */
export function requestGrant(sid: string, label: string, req: { holder: string; kind: "grant" | "rule"; minutes?: number; until?: string }, done?: (ok: boolean) => void) {
  if (!hasShell) { toast("Grants are signed in the Jarvis 2 app on the iPhone."); return; }
  const full = req.kind === "rule" ? { holder: req.holder, kind: "rule", until: req.until || new Date(Date.now() + RULE_DAYS * 86400000).toISOString() }
    : { holder: req.holder, kind: "grant", minutes: Math.min(10, Math.max(1, req.minutes || 10)) };
  requestSecure("grant", { sessionId: sid, label, ...full }, (r) => {
    if (r.result === "done") { toast("Signed — the grant is saved.", "ok"); refresh(false); settle(20000); }
    done?.(r.result === "done");
  });
}
export const forgetGrant = (g: Grant) => api("DELETE", `api/grants/${g.id}`);
