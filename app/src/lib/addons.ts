// Add-ons on a running session (docs/API.md "Approvals", router/addons.go): a terminal for 10 minutes, a command, a
// store. The web page only files them; each becomes an approval that Deyao signs in the iPhone app (Inbox).
import { api } from "./api";
import { refresh, settle, toast } from "./store";

/** file a terminal for this session (10 minutes, the most there is): an approval in the phone's Inbox */
export async function requestTerminal(sid: string): Promise<boolean> {
  try {
    await api("POST", "api/requests/terminal", { session: sid, minutes: 10 });
    toast("Sent to the Inbox: approve it in the Jarvis 2 app.", "ok");
    refresh(false); settle(5000);
    return true;
  } catch (e: any) { toast(e.message, "error"); return false; }
}

/** a 403 that says the call needs an open terminal (`needsTerminal`) */
export const needsTerminal = (e: any) => e?.status === 403 && !!e?.body?.needsTerminal;

/** drop stores in place: the main grant narrowed to the stores kept (POST api/sessions/:id/narrow) */
export const narrowStores = (sid: string, keep: string[]) => api<{ ok: boolean; stores: string[] }>("POST", `api/sessions/${sid}/narrow`, { stores: keep });
