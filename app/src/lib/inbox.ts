// The Inbox (docs/API.md "Requests", router/inbox.go): everything waiting for the phone's Face ID that was asked
// for somewhere else — a session, the web page, the setup session (Claude). Each entry opens the shell's secure page
// for it, which shows (1) what will be signed, rendered from the signed content, (2) the API call the router
// recorded and who made it, (3) the caller's own reason. This file renders the LIST's title from the entry's kind +
// params (display only: the review page renders its own from what it signs) and files requests from the web page.
import { api, challengeRequest, holderTitle, type Approval, type InboxItem, type Policy } from "./api";
import { refresh, settle, toast } from "./store";

/** the store a repo's deploy key lives in (core/deploykeys.go RepoStore) */
export function repoStore(repo: string): string {
  const [owner, name] = repo.toLowerCase().split("/");
  const slug = owner === "de0ch" ? name : owner + "-" + name;
  return "github-" + slug.replace(/[^a-z0-9]/g, "-").replace(/^-+|-+$/g, "");
}

/** the list's title: the core action (or the phone grant) the entry leads to */
export function inboxAction(it: InboxItem, approvals: Approval[] = [], policy: Policy = {}): string {
  const p = it.params, who = it.sessionName ? `“${it.sessionName}”` : it.session || "?";
  switch (it.kind) {
    case "repo-key":
      return p.action === "remove" ? `Delete the deploy key and store ${repoStore(p.repo || "")} of ${p.repo}`
        : `Make a deploy key for ${p.repo} (read + push), kept in store ${repoStore(p.repo || "")}${p.sensitive ? " (sensitive)" : ""}`;
    case "grant":
      return p.days ? `Standing rule: ${holderTitle(p.holder || "")} in ${who} for ${p.days} days`
        : `Allow ${holderTitle(p.holder || "")} in ${who} for ${p.minutes || 10} minutes`;
    case "unlock":
      return `Unlock the stores ${who} is waiting on`;
  }
  const a = approvals.find((x) => x.id === it.id);
  const r = a ? challengeRequest(a, policy) : null;
  if (it.kind === "add-store") return `Add store ${r?.addedStore || it.options?.store || "?"} to ${who}`;
  const what = r ? ` · stores ${r.stores.join(", ") || "none"} · ${r.permissionMode} mode` : "";
  if (it.kind === "resume-upgrade") return `Resume ${who} on the latest image${what}`;
  return (it.options?.restore ? `Restore ${it.options.restore}` : `New session ${who}`) + what;
}

/** the call as one line: POST /api/requests/repo/add {"repo":"DE0CH/claude-env"} */
export function inboxCall(it: InboxItem): string {
  if (!it.call?.path) return "(no API call recorded)";
  const args = it.call.args && Object.keys(it.call.args).length ? " " + JSON.stringify(Object.fromEntries(Object.entries(it.call.args).sort(([a], [b]) => a.localeCompare(b)))) : "";
  return `${it.call.method} ${it.call.path}${args}`;
}

export const denyRequest = (it: InboxItem) => api("DELETE", `api/requests/${it.id}`);

/** the web page has no shell: what would open a secure page files an Inbox request instead (Face ID on the phone) */
export async function fileFromWeb(kind: string, o: Record<string, unknown>): Promise<boolean> {
  let path = "", body: Record<string, unknown> = {};
  if (kind === "repo-key") { path = `api/requests/repo/${o.action === "remove" ? "remove" : "add"}`; body = { repo: o.repo, sensitive: !!o.sensitive }; }
  else if (kind === "grant") {
    path = "api/requests/grant"; body = { session: o.sessionId, holder: o.holder };
    if (o.grantKind === "rule") body.days = Math.max(1, Math.min(365, Math.round((Date.parse(String(o.until || "")) - Date.now()) / 86400000) || 30));
    else body.minutes = o.minutes || 10;
  } else if (kind === "unlock") { path = "api/requests/unlock"; body = { session: o.sessionId }; }
  else { toast("This needs the Jarvis 2 app on the iPhone.", "info"); return false; }
  try {
    const r = await api<{ id: string; duplicate: boolean }>("POST", path, body);
    toast(r.duplicate ? "Already in the Inbox on the iPhone." : "Sent to the Inbox: approve it in the Jarvis 2 app.", "ok");
    refresh(false); settle(5000);
    return true;
  } catch (e: any) { toast(e.message, "error"); return false; }
}
