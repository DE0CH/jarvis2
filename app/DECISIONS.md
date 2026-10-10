# Design decisions in the Jarvis 2 app (for Deyao to review)

Carried over from the mock (DE0CH/jarvis2-mock DECISIONS.md) unless marked new.

1. **New session is split.** The React Native form (normal mode) keeps prompt, title, permission mode, model
   and size; its button says **Continue** and pushes the shell's secure page, where the **secret stores** and
   the **harness** are chosen for real, then **Create**. Create asks the router for the session, waits for
   the core's challenge (it comes before any machine exists, so in about a second), checks it carries
   exactly the stores picked on that page plus the harness's own (policy) and the harness picked there, and
   signs it (one Face ID). The router then starts the machine. The form's other fields travel along unsigned.
2. **Sensitive stores:** the React Native form (and the web form) never lists them; normal mode may
   pre-select non-sensitive stores only. A sensitive store is added only by a tap on the secure page, which
   then shows an amber warning. Any approval whose challenge includes a sensitive store shows the warning
   too (the core marks them in the signed challenge, so the router can't hide it).
3. **One secure page per approval kind, opened from a "Waiting for you" section** at the top of the
   Sessions tab (Review). The page reads the kind from the core-signed challenge's own fields, never from the
   router's label: new session (no predecessor, an image), resume on the latest image (a predecessor, an
   image), add a store (a machine and `addedStore`); anything else shows as a plain "Approve" with what is
   signed. It shows stores (harness stores badged), harness, the image, and Approve / Reject. **The phone
   refuses nothing it can show** (2026-10-09 redesign: the phone is the highest privilege); the only check
   afterwards is that the core's answer (an `approval`, or a `succession-cert` for an added store) carries
   this challenge's nonce.
4. **Resume with latest image** is in the session's More menu (paused sessions); the router asks for the
   approval first (nothing happens to the session until then; Reject leaves it paused) and the app opens the
   approval page by itself.
5. **Stores page in the shell** (Stores tab → "Unlock / lock…"): each store from the core's signed list
   (sensitive, empty, unlocked) with Unlock (Face ID → the Enclave's share → sealed to the core's one-off
   key; off for an empty store), the core's signed list of open unlocks (with my nonce) each with Lock,
   "Mark sensitive…" with an inline confirm (one way), and **New store** (a name → `stores/create`: empty,
   not sensitive; the setup session writes its values). Lock needs no Face ID. The React Native Stores tab and
   the web page list the stores unverified, view only.
6. **Reset or recover: one page in the shell** (Deyao, 2026-10-10: two paths, no one else involved). It opens by
   itself at launch when this iPhone hasn't set a core up, or when the router reports a core other than the pinned
   one (Back leaves it; the app can still view, nothing can be signed); also from Settings → "Reset or recover…".
   It first checks the core: the box key's signature on its keys (`keys/box.pub` from GitHub), then the core's
   signature on its state. **Reset** shows a new kit with Copy and "I've saved it", then claims the empty core with
   no stores; **Recover** takes the kit, reads the backups through the router (`api/backups`), checks and opens them,
   and claims the empty core with every store. A core that is set up asks first for the kit it was set up with and
   wipes it (the page waits for the new, empty core). On the core's signed `claimed` the page pins the core's keys
   and its own master public key and forgets the master key. Errors are one plain sentence, the technical part
   behind "Details". Copy (`CoreSetup.swift`, `SetupPage.swift`): "Jarvis 2 is empty. Choose one:" / "Jarvis 2 is
   set up on this iPhone." / "…set up with your recovery kit, for another iPhone." / "…set up with a different
   recovery kit."; Reset "Start fresh with a new recovery kit. Everything starts empty."; Recover "Bring everything
   back with the recovery kit in your password manager."
7. **Phone keys:** two Secure Enclave P-256 keys (signing + key agreement), `.biometryAny`, Face ID on every
   use; public keys made at first launch without Face ID. The **simulator** uses software keys (its Face ID
   can't be driven from CI); the secure banner says which.
8. **New: sign-in belongs to the shell.** ASWebAuthenticationSession on `/api/auth/start?redirect=jarvis2://auth`,
   the token in the shell's Keychain, handed to the React Native UI over XPC with the router's address (one
   source: the shell's Info.plist). A refusal (ended on cloudflareaccess.com, a non-JSON 401/403, or the
   router's "Access login required") opens the sheet again and retries once. No sign-in screen on launch:
   the first refused request opens the sheet.
9. **Not in the React Native app yet** (the router doesn't have them, or they need a native module the extension
   doesn't carry): content stores, devices and lease pills (forwarded to Jarvis 1, which doesn't take Jarvis 2
   sessions yet — PLAN.md "Later"), first-prompt attachments (a file picker; the router has `POST /api/uploads`).
   Everything else Jarvis 1's dashboard has is back (items 23–38).
10. **The image** shows as the ref the core read from Fly (on approval pages); the GitHub build attestation
    ("CI build from <date>") isn't checked yet.
11. **iPhone only** (`TARGETED_DEVICE_FAMILY = 1`), portrait + landscape.
12. **The web page** can view everything, request a new session (non-sensitive stores; harness on the form),
    reject approvals, pause/resume/destroy; approvals happen only in the app.
13. **TestFlight from GitHub Actions** (not Xcode Cloud): the archive is built unsigned and the export signs
    it with Apple's cloud-managed distribution certificate (App Store Connect API key in repo secrets) —
    signing at archive time would mint a development certificate per runner, and the team is at its limit.
    Build number = the workflow's run number; internal group "Owner" (all builds). App record "Jarvis 2"
    (6820459076); icon = the Jarvis ring with a "2" at its centre (`app/scripts/make-icon.py`). `workflow_dispatch` with `only=testflight` ships without
    rerunning the walkthrough.
15. **React Native's frameworks sit in the app's `Frameworks/`**, not inside the extension (App Store
    validation refuses an extension that carries its own); the extension loads them via its rpath. The shell
    binary links none of them.
14. **CI walkthrough** runs twice (light, dark), each against a fresh, empty core + router and a reset simulator
    keychain: Reset or recover (an old kit refused, then Recover with the public TEST kit, the backups through the
    router from the S3 stand-in) → stores (create, unlock; the core's own and the harness's stores hidden, a
    marker-sensitive store sensitive) → new session → grants (a 10-minute grant and a standing rule signed on the
    grant page, one forgotten) → schedules (a wakeup, a cron) → terminal → pause → transcript → resume with a prompt
    → resume with the latest image → destroy → previous (remove) → search → settings → Reset (the TEST kit wipes the
    core, which CI runs in a restart loop as Kubernetes would; a new kit shown, saved, claimed; the stores empty).

16. **The recovery kit format** (what Deyao keeps in the password manager, ONE entry): `jarvis2-kit:2:<master
    key>`, the base64 PKCS#8 DER of the P-256 private key (the body of a PEM "PRIVATE KEY" block, so `openssl pkey`
    reads it). Whitespace and line breaks in a paste are ignored; a `jarvis2-kit:1:` kit is refused with a plain
    sentence. The master key is made in software (it must go into the kit, so not the Enclave) and exists only in the
    setup page's memory and in the kit. A pasted kit is wiped on success, on leaving the page, and 10 minutes after
    it was pasted.
17. **The earlier master key page, held key and kit page are gone**; the app deletes the held key an earlier build
    kept in the Keychain at launch.
18. **New: what the shell trusts comes from GitHub, not the router**: `keys/box.pub` (the core's identity) and
    `keys/setup.pub` (the backups' signatures) are fetched from
    `https://raw.githubusercontent.com/DE0CH/jarvis2/main/keys/` when needed (no cache). The backups come through
    the router, which can't read or change them (sealed to the master key, signed by the setup key). Only a CI build
    can point the key source elsewhere: the code that reads the overrides is compiled only with `JARVIS_CI` (`JARVIS_CI_FLAG`, set on
    the simulator job's xcodebuild line), and the TestFlight job fails if the archive's Info.plist carries
    any override.
19. **New: the S3 stand-in in CI is `rclone serve s3`** (MinIO's downloads are gone, HTTP 410; moto doesn't
    check signatures) — it checks SigV4, so a wrong secret fails as on Hetzner. `ios/ci/standin.py` seeds it
    by calling infra/setup.py's own `backup` / `mark_sensitive_backup` with a per-run setup key and the public
    TEST master key, and the router on the runner reads it; extra buckets hold a backup signed by another key (must
    be refused) and one without the core store (accepted: the token comes later). The keys are served by a local
    `http.server`.
20. **New: harness stores are hidden** (GET `api/policy`): not offered in any picker, left out of the
    session/record/approval summaries; the secure approval page still lists them (badged "Harness") since
    they are part of what is signed. The `core` store never shows (the core keeps it out of its list).
21. **The `core` store may be missing from the backups**: a Recover goes on, and the setup session sends the core
    its Fly token (`infra/setup.py backup-core`).
22. **Backups are refused whole** when any object under `stores/` or `sensitive/` isn't signed by the setup
    key, names another store, comes twice, or doesn't open with the master key: a tampered bucket stops the Recover rather
    than quietly dropping a store.

23. **New: grants are signed on a shell page, never from text the React Native UI hands over.** There is no
    generic "sign this text" call: the UI only opens the secure **grant page** (kind `grant`, with a
    pre-selection: session, feature, minutes or standing rule). The page reads the session's **core-signed
    cert** (`GET api/sessions/:id/cert`, checked against the pinned core key) for the line, the stores, whether
    the session is sensitive and which phone it trusts; Deyao picks the feature (terminal, scheduler, status,
    login repair, archive check — each described in words), 1/2/5/10 minutes or a standing rule with an end date
    (offered only when the cert says the session isn't sensitive, since the machine would refuse it), and reads
    one sentence of what it means ("Terminal may run commands as the session's user in “X” for 10 minutes (until
    14:32)"). Allow asks the router for the draft, checks it field for field against those choices
    (`Checks.reviewGrant`: kind, the holder's key, the cert's line, scope `shell`, issued now, exactly the minutes
    or the end date, no extra fields, and that the cert names this phone), signs it with the same Secure Enclave
    key as approvals (one Face ID, whose prompt says the same sentence) and stores it (`POST …/grants`); the
    stored grant must come back for that feature and kind. Interop covers the cert and the checks against the
    real core.
24. **New: the feature→key list (`GET api/holders`) is the router's word.** Every holder key belongs to the
    router, so a router that lied about which key is "terminal" could only hand a grant to another of its own
    features; the line (from the core's cert) and the duration are what bind the grant, and those are checked.
25. **New: the session's card** carries what `/api/state` reports: Jarvis 1's status pill (working / needs you /
    idle · N background / booting / done · archiving), the auto-pause line (countdown, off, one-shot), Claude's
    failed login, the queued resume prompt, wakeups and crons (a blue box; a paused session with any is in
    the "Scheduled" group), a `needsGrant` box with **Allow <feature> for 10 minutes** and **Make a standing rule**
    (both open the grant page), and a link to its Discord channel. More: Grants…, Schedules…, Auto-pause when
    idle and Idle notifications (two-phase switches with a check mark), Resume with latest image, Destroy.
26. **New: Resume asks for an optional prompt** in the same dialog (delivered as a message once the session is
    up); **Destroy** first lists uncommitted / unpushed work (`/changes`), and when the archive fails offers
    "Destroy anyway" (`?force=1`). A paused session has **Transcript** (its snapshot's tail).
27. **New: the terminal draws the tmux capture as React Native text** (ui/ansi.ts parses the colour escapes; the
    cursor cell is inverted) instead of Jarvis 1's xterm.js in a WebView: the extension carries no WebView, and
    the router only sends snapshots anyway. Same page otherwise (always dark, key row, input bar on the keyboard,
    one snapshot a second, resize to fit). When the phone hasn't granted the terminal it says so and offers
    "Allow terminal for 10 minutes". It is offered while initialising too.
28. **New: Schedules page per session** (More → Schedules…): the armed wakeups and crons with Cancel, and a form
    to arm one (once in N minutes, or daily at HH:MM in the device's zone / every N hours), plus a shortcut to a
    standing rule for the scheduler. Jarvis 1 only listed them; the router has the app routes, so the page can.
29. **New: "Records" is called Previous again** (Jarvis 1's name). Each card: Restore (a new line; the phone
    approves it like a new session, and the approval opens by itself), Transcript (the archive's tail), Remove
    (off the list, the archive stays) and Delete (the archive too; type the title).
30. **New: Fly spend** in Settings (spent / cap, rate, running machines, the DM and pause thresholds) and as a
    banner when warned or capped; "Also on Fly" under the sessions as in Jarvis 1. Banners also for a Claude
    login that failed in a session and a Fly read error.
31. **New: Settings → Claude account** is a link to Jarvis 1 (re-login, usage and the token live there).
    New session has One-shot (needs a prompt) and the auto-pause switch, carried through the secure page; the
    approval page shows one-shot and a restore's source (the router's word, not signed).

32. **New: Repos** (in Settings since item 41; the list, the GitHub picker over the router's read-only token) and
    **Repos** + **API proxy** in New session (carried through the secure page; repos go as the comma-joined URLs
    the machine clones over SSH with each repo's deploy key from its store). Nothing is pre-picked.
33. **New: Remote page** for OpenCode / OpenClaw sessions (their primary action instead of Terminal): the web UI
    link, the Paseo pairing link + QR. The router reads them in the machine as the `remote` feature, so a 403
    offers "Allow the remote page for 10 minutes". **Usage** (the Claude quota, read through Jarvis 1) is a
    Settings card. Cards show the router's own lock (`busy`, `wake`) as the action label on every device.

34. **New: the permission mode is signed** (core Options carry `permissionMode`; Deyao: only raising to bypass
    needs the phone). The secure New session page picks it for real (pre-filled from the form) and checks the
    challenge carries it; every approval page reads it from the signed challenge, never the router's fields, and
    shows "Permission mode: bypass" highlighted (amber) or "auto". A resume in another mode than the line's cert
    comes as a `resume-upgrade` approval (titled "Approve resume"), and the app's Resume opens it by itself.
    More → Switch to bypass / auto mode: a paused session switches at its next resume; raising a running one to
    bypass needs a fresh phone grant for the terminal, so the router's 403 `{needsGrant, phoneGrant}` opens the
    grant page and the switch runs again once it is signed.

35. **New: Tasks and Schedules tabs** (Jarvis 1's, on the router's `/api/tasks`). A task is its own session line on
    harness `task:<template>`: **Make task** (name + the template's fields) creates it and the line's
    `new-session` approval ("Task: <name>") opens by itself in the app — the secure page names the harness "Task
    script “<template>”". Runs then need no phone: Run, the run list (queued → starting → running → result),
    a run's output and log, Stop. **Run on latest image** is the task's resume-upgrade (the phone approves the
    newer image, opened by itself); **New line…** asks the phone again when a task's line is gone or failed.
    A store field (`optionsFrom: "stores"`) is filled from the core's store list (sensitive ones marked); sizes and
    models from the router's lists; store fields can't change after creation (the router refuses, the form says
    so). Daily schedules (HH:MM + time zone, on/off on the card). Task lines are left out of the Sessions list.

36. **New: Search tab** (Jarvis 1's, second in the tab list): **Conversations** — every conversation of both Jarvises
    (Jarvis 1's search, forwarded by the router), the same filters (Chat / Actions / Records, time range, By session) and
    a hit opens the conversation around it, with **Resume** when the hit is a paused Jarvis 2 session (its live copy is
    filed under the session's id) or **Restore** when its archive is on the Previous list; **iCloud files** — Jarvis 1's
    iCloud index: name, folder, kind, size, the matching passage; a file opens what the index read from it, with the
    path's Copy button. Jarvis 1 had no iCloud screen (only its API); this one is new. Jarvis 1's search box on the
    Sessions and Previous tabs (filtering cards by transcript) isn't ported.
37. **New: copy buttons through the shell.** The extension carries no clipboard module (a pod wouldn't embed into
    the ExtensionKit target, lessons/73), so React Native asks the shell over XPC (`ShellBridge.copyText` →
    `HostService.copyText`), which writes `UIPasteboard` in the foreground app (plain text, ≤ 64 KB; the recovery kit
    keeps its own local-only, expiring copy). The web page uses the browser's clipboard. Copy appears on the Remote page
    (web UI link, pairing link — now in the app too), a session's More menu (its id) and an iCloud file's path; a toast
    says what was copied.
38. **New: the Claude app's title names the session** (`serverTitle`, read by the machine): cards, Discord channels and
    archive folders follow a rename in the Claude app, as in Jarvis 1. **Previous** hides Restore for an archive indexed
    by hand (`POST api/records`: no signed snapshot) and says why.

39. **Settings has one entry for this**: "Jarvis 2" (running or not) with "Reset or recover…"; the core's keys
    are no longer shown.

40. **Jarvis 1's look, exactly (Deyao, 2026-10-10: "Keep them the same as jarvis 1, like font size etc").** Two
    causes. (a) In the extension React Native has no `UIApplication`, so its font-size multiplier came out 0 and
    every text run fell back to iOS's 12 pt default: the whole app was one small size. `src/ui/rntext.native.tsx`
    gives every kit text run `dynamicTypeRamp="body"` (its multiplier from `UIFontMetrics`, which works in an
    extension: exactly 1.0 at the default text size, and it still follows the iPhone's text size like Jarvis 1)
    and text fields `allowFontScaling={false}` (the kit's fields are a fixed 16 pt anyway); the web keeps React
    Native's own components. (b) The shell's SwiftUI pages approximated the kit. `Shell/Kit.swift` now ports
    `src/ui/kit.tsx` + `theme/tokens.ts` value for value: the type ramp (size, line height with the glyphs centred
    in the line box, letter spacing, weight), Heading, P, Muted, Lbl (alpha gray, upper-case tracking), Button
    sizes 1–3 in every variant with the pressed fill, Card, TextField/TextArea (surface, gray border → focus
    colour), Callout, Badge, ChoiceCard/ChoiceText, Segmented and a CodeBox; `SecureFrame` follows `page.tsx`'s top
    bar and column. Store rows on the shell's pages are kit Cards. The page is drawn as one layer
    (`compositingGroup`), so the push motion's shadow no longer lands on every text run as a halo.

41. **New: Settings → Repos, each repo with its own deploy key** (Deyao, 2026-10-10; docs/DESIGN.md "Deploy keys").
    The Repos tab is gone; its card sits in Settings after Usage. **Add repo** (the GitHub picker, or "owner/name" /
    a GitHub URL typed; Return submits) opens the shell's secure page **Add repo** (kind `repo-key`): it asks the core
    for the request at once and shows what the core signed — the repo, "what happens" in one paragraph, the store as a
    store line (Sensitive badge), "replaces" in amber when the store exists, a **Sensitive store** check (on and
    fixed when the core says so: Jarvis 2's own repo, or a store sensitive already; ticking it asks the core again),
    and that Face ID opens `github-deploy-keys` for this one request. **Add** checks the request (this action, this
    repo, its store and title, the one token store), then ONE Face ID signs the request and computes the share
    (`PhoneKeys.signAndShare`, one LAContext), and the core's answer must be for this request (`Checks.deployKeyAnswer`).
    Each listed repo shows its store and key fingerprint, **No key** (amber) when the core's store list lacks its store
    (after a Recover) with **Make key**, and **Remove** (the same page, "Remove repo"). The web page lists the repos
    only. New session pre-selects a picked repo's store when it isn't sensitive and says which to tick on the secure
    page otherwise. The walkthrough adds `DE0CH/china-train` against the CI core's fake GitHub, sees `DE0CH/jarvis2`
    come up sensitive, and removes the first; interop covers the checks and the refusals against the real core and
    router.

## Unfinished / known gaps

- **Keyboard avoidance for React Native forms** still comes only from React Native (lessons/73: the
  extension sees keyboard height 0; the shell should resize the extension's area).
- **Free text** (prompt, title) goes to the machine unsigned (SECRETS-CONTROLLER.md "Open").
- **Fake machines never become `started`** in CI (nothing pulls secrets), so the walkthrough pauses and
  resumes sessions in `initialising`; the Pause button is offered there too.
- Approval pages show the router's session label (unsigned) next to the signed content.
- No GitHub build-attestation check of the session image (item 10).
- After a reinstall the phone's keys are new, but an already-recovered core refuses a second recovery (409):
  the core has to be restarted (= a new core) and recovered again.
