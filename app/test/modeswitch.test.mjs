// npm test: the web page's permission-mode switch reports the Inbox wait, never an error (Deyao, 2026-10-20)
import { test } from "node:test";
import assert from "node:assert/strict";
import { inboxToast, modeOutcome, modeWaitingText } from "../src/lib/modeswitch.ts";

test("the router's answers map to what the page does", () => {
  assert.equal(modeOutcome({ ok: true, permissionMode: "bypass", nextStart: true }), "next");
  assert.equal(modeOutcome({ waiting: "inbox", inboxId: "q1", needsGrant: "terminal", permissionMode: "bypass" }), "inbox");
  assert.equal(modeOutcome({ started: true, kind: "permission-mode", inPlace: true }), "run");
  assert.equal(modeOutcome({ ok: true, unchanged: true }), "run");
});

test("a switch waiting in the Inbox says so", () => {
  assert.match(inboxToast({ waiting: "inbox" }, "bypass"), /^Waiting on you in the Inbox: .*bypass/);
  assert.match(inboxToast({ waiting: "inbox", duplicate: true }, "bypass"), /^Already waiting in the Inbox/);
});

test("the card shows the waiting switch until the request lapses", () => {
  const now = Date.parse("2026-10-20T05:00:00Z");
  assert.match(modeWaitingText({ mode: "bypass", inbox: "q1", until: "2026-10-20T05:09:00Z" }, now), /bypass waits for the terminal grant in the Inbox/);
  assert.equal(modeWaitingText({ mode: "bypass", inbox: "q1", until: "2026-10-20T04:59:00Z" }, now), null);
  assert.equal(modeWaitingText(null, now), null);
});
