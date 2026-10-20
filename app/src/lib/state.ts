// What the UI keeps of a GET api/state answer: every field the router sends, the lists and the core's status filled in
// when it leaves them out. Never a list of fields to copy: the Devices tab and the sessions' lease pills read
// `leases`, which such a list left out, so the tab said "No devices." from the day it shipped (2026-10-13 to 10-19).
import type { State } from "./api";

export function stateFrom(st: Partial<State>): State {
  return {
    ...st,
    sessions: st.sessions || [], approvals: st.approvals || [], core: st.core || { up: false }, budget: st.budget ?? null, fly: st.fly ?? null,
    repos: st.repos || [], inbox: st.inbox || [], inboxBatches: st.inboxBatches || [], leases: st.leases || [],
    messages: st.messages || [], messageRules: st.messageRules || [],
    loaded: true, loadError: null,
  };
}
