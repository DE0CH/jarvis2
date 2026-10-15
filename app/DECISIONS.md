# Design decisions in the Jarvis 2 apps (for Deyao to review)

Two codebases (Deyao, 2026-10-11): the **iPhone and iPad app** is one native SwiftUI app in `ios/` (Apple frameworks and
our Swift only); the **web page** is the Expo app in `app/`, web only. Items 1–22 are about the iOS app, 23–29 the
security fixes from the 2026-10-11 audit (`~/artifacts/away/audit/app.json`), 30–33 what was agreed with the R1 server
fixes, 34–40 carried over from the old app and still true, 41–43 the web page.

## The native app

1. **One SwiftUI app, no React Native, ExtensionKit, XPC or snapshot covers** (Deyao, 2026-10-11). The old app split a
   trusted Swift shell from an untrusted React Native extension in its own process; now the whole app is trusted code, so
   the "secure pages" are ordinary sheets of the app. What made them secure stays: what the phone signs is rendered from
   the signed content, every signature takes Face ID, the keys stay in the Secure Enclave and the Keychain (same Keychain
   service `dev.de0ch.jarvis2.shell`, so an installed app keeps its keys and pinned core across the update).
2. **No third-party Swift packages.** None was needed: QR codes come from CoreImage, the terminal from WebKit, crypto from
   CryptoKit. Two community agent skills guide the code (`.claude/skills/swiftui-pro`, `swift-concurrency-pro`, Paul
   Hudson, MIT).
3. **iOS 26.0 minimum**, built with the newest Xcode on GitHub's runners; the CI simulator is Xcode 27.0 / iOS 27.0 on an
   iPhone 17 (iPhone18,3), the shared `.github/actions/ios-simulator`. iOS 27-only APIs are not used.
4. **Swift 5 language mode with targeted concurrency checking** (models `@MainActor`, Secure Enclave work off the main
   actor). Swift 6 strict mode would surface data-race errors that only CI can show (no Mac here); the code is written to
   pass it later.
5. **Navigation**: a `TabView` with `.sidebarAdaptable` (tab bar on iPhone, sidebar on iPad): Sessions, Inbox (badge),
   Tasks, Settings, and the system Search tab. Four tabs plus Search keeps the iPhone free of a "More" tab: Previous sits
   in Sessions' toolbar; Stores, Repos and Machines under Settings; task schedules inside Tasks.
6. **Sessions is a `NavigationSplitView`**: grouped list (Running / Scheduled / Paused / Failed) beside the selected
   session's page on iPad, a stack on iPhone. Rows have swipe actions (Pause / Resume, Destroy) and a context menu with the
   old More menu; the page has every action as a list row, plus Terminal (or Remote) in the toolbar.
7. **Questions are alerts** (Destroy? Resume with a prompt? Delete permanently with the title typed), errors from a user's
   action are one alert, and a short note ("Session id copied") appears at the bottom for three seconds. Pull to refresh
   on every list (Apple's pattern; Jarvis 1's dashboard rules don't apply to this app).
8. **The Face ID reviews are sheets** (`Review/`): New session, an approval, a grant, an unlock, a repo key. Cancel (or
   Deny) in the top-left, the action (Start, Approve, Allow, Add) in the top-right, a swipe down is a Cancel; a sheet that is
   working can't be swiped away. Each page ends with which key signs (Secure Enclave with Face ID, or the simulator's
   software key).
9. **Reset or recover is a full-screen cover** at first launch and after the router reports another core, and from
   Settings. Close leaves it (the app can still view, nothing can be signed).
10. **The terminal is the router's page** (`GET /term/{id}`, `router/web/terminal.html`) in a `WKWebView` (Deyao: "just
    open a web page"): WebKit's content runs in its own process, so the app carries no terminal code. The page is loaded
    with the app's Access login: the `cf-access-token` header on the first load, the `CF_Authorization` cookie for the
    router's host and a fetch wrapper that adds the header, all in a non-persistent data store. `WKWebView` rather than
    SwiftUI's own `WebView`, which has no script message handler: the page asks the app for a grant (`jarvis2` handler,
    `grant`) and for a fresh login (`signin`); the app opens its Face ID review and calls `window.jarvis2Refresh()`.
11. **Sign-in**: `ASWebAuthenticationSession` on `/api/auth/start`, the token in the Keychain, sent as `cf-access-token`.
    A refused request opens the sheet again and retries once; a cancelled sign-in shows one "Signed out" screen.
12. **The router's shapes are read through a lenient JSON value** (`Model/JSON.swift`), so a new or differently typed
    field never empties a list. Nothing signed is read that way: signed documents are decoded and checked by
    `Security/CoreCrypto.swift`.
13. **Nothing is optimistic**: an action keeps its pending label until the router reports the outcome; one action per
    session (or record, task) at a time; reads of the router's state are coalesced (a call while one runs gets one
    follow-up). 15 s polling, 2 s while a session is moving, and at once when the app comes to the foreground.
    A pending label ends with the outcome itself; slower follow-up reads (a store's key rows after an unlock) run after
    it, and an action on one record (Lock of one open unlock) is keyed by that record, so a neighbour's action never
    leaves its button disabled with the tap dropped.
14. **New session is one page** (Deyao, 2026-10-10): kind (session / one-shot), prompt, title, stores, harness, repos,
    permission mode, model, size, auto-pause, API proxy. `default` is pre-picked when it isn't sensitive; DE0CH/claude-env
    and its store are pre-picked when the repo is on the list (Deyao, 2026-10-11), never a sensitive store. Start makes the
    session, waits for the core's challenge, checks it (items 24, 31) and signs it under one Face ID that also unlocks the
    session's locked stores for that session only.
15. **Stores are managed in the Stores page itself** (Settings → Stores): unlock (Face ID), lock, mark sensitive (a
    confirmation, one way), new empty store, the core's signed list of open unlocks, and each store's key names (from the
    router; never values).
16. **Repos**: Settings → Repos lists each repo with its store and key fingerprint, "No key" with Make key after a Recover,
    and Remove; Add repo is a searchable list of the repos the router's GitHub token sees plus a field for owner/name or a
    URL. A core refusal (e.g. the coming 409 "store github-x belongs to owner/repo" when another repo owns the store name)
    shows on the review page in the core's own words.
17. **Search** is the system search tab with two scopes (Conversations, iCloud files) and a filter menu (kind, time, by
    session); a hit opens the conversation around it or the file's indexed text.
18. **Tasks** keeps Jarvis 1's model (instances, templates, daily schedules) in one tab; a new task's approval opens by
    itself.
19. **iPhone and iPad** (`TARGETED_DEVICE_FAMILY 1,2`), every orientation on iPad.
20. **Version 2.0**, build number = the `ios` workflow's run number + 1000 (above the old app's builds).
21. **TestFlight from GitHub Actions** (`ios.yml`), archived unsigned and cloud-signed at export with the App Store Connect
    API key (lessons/75), bundle id `dev.de0ch.jarvis2`, the job in the `release` environment (main only). It ships only
    when a phone replica passed on the same `ios/` and `policy/`, and checks the archive carries no CI key source, no
    other keys ref, and the pinned policy is git's.
22. **Tests**: the walkthrough (`UITests/Jarvis2UITests.swift`, light and dark against the real core and router on the
    runner), the transitions run (`TransitionsUITests`: every tab, push, pop, edge swipe, sheet, background and relaunch,
    recorded; a blank screen over 1.5 s or a near-uniform screenshot fails it), the phone replica (`ReplicaUITests`, the
    Release build against a real box with Face ID driven by the runner) and the crypto interop test against the real core.
    The old Back-stress test (an extension killed or slow) has nothing left to test and is gone.

## The audit's app findings (2026-10-11) and their fixes

23. **Resume-with-a-change wasn't bound to a session (finding 1)**, **approval and unlock pages named the session from the
    router (finding 5)**: every approval page now reads the session from the challenge's predecessor, a core-signed cert
    checked against the pinned core key (`Checks.continues`): its signed title and first prompt (from a core that vouches),
    its line and machine, when it was issued, whether it holds a sensitive store. The challenge's line and predecessor id
    must be that cert's; an add-store's machine must be the predecessor's. "What you sign" names that session
    (`SignedAction.approval(of:)`). A resume or add-store with no predecessor is refused. The router's label shows only as
    "Listed by the router as … (unverified)".
24. **New session signed any extra store the router called a harness store (finding 2)**: the stores each harness brings
    are pinned in the app from git (`policy/stores.json` bundled; `PinnedPolicy`), and Start refuses a challenge with a
    store that wasn't picked and isn't the harness's by that list (`Checks.onlyHarnessExtras`). The harness's stores are
    listed on the page with their sensitivity, and a sensitive one joins the red "will hold sensitive secrets" warning: a
    harness store Deyao marked sensitive is still started (refusing it would stop every session of that harness), but
    never unseen. A CI build also takes the router's test policy.
25. **Grant and unlock pages took the session→cert mapping from the router (findings 3, 4)**: they show the session from
    its core-signed cert (title, first prompt, line, machine, sensitive warning in red), the signed text names it, and the
    page refuses when the cert's signed title differs from the session's title in the app's list.
26. **Line pins (findings 3–5)**: the app remembers which line each session id is the first time it verifies a cert for it
    (opening a session's page, a grant, an unlock, an approval) and refuses any later cert or predecessor that names another
    line for that id (`LinePins`). A session's line never changes (a resume keeps it; a restore is a new session); a Reset or
    Recover clears the pins. The first sighting is still the router's word.
27. **Untitled sessions and the held core**: a cert from the production core held today carries no signed settings, so the
    pages can't show a signed title; they say so in orange and show the line, machine, issue time and stores instead, and
    don't refuse (refusing would stop every grant and approval until the core is released). Full binding comes with the
    core release.
28. **Face ID binding (finding 6)**: the phone's Secure Enclave keys are made with `.biometryCurrentSet`, so enrolling
    another face or an alternate appearance (which needs only the passcode) makes them unusable. Trade-off: after any change
    to Face ID's enrolled faces Deyao pairs the phone again with Recover (his kit; running sessions end, paused ones are
    archived). To make that clean, every Reset and Recover now makes fresh phone keys before the claim; an installed phone
    keeps its older `.biometryAny` keys until its next Reset or Recover. A key the Enclave refuses shows one message saying
    so.
29. **Silent re-pin and the box key (finding 7)**: the app never pins a core except at the end of a Reset or Recover; a core
    that claims "set up on this iPhone" but isn't the pinned one asks for a Recover. Not fixed in the app: binding the core
    to something the box can't forge (an image attestation of the core, or a box key the cluster can't mount) needs a core
    change, which is held; see STATUS.

## Agreed with the R1 server fixes (2026-10-11)

30. **Device key countersignature**: the app has a long-lived Secure Enclave "device" key (made once per install, kept
    across Reset/Recover, `.userPresence`). Claim and wipe statements carry it as `device` inside the master-signed text,
    and the request bodies carry `deviceKey` and `deviceSig` (its signature over the statement). `infra/setup.py` trusts a
    new master only from the device it pinned.
31. **Store writers**: an unlock's (and a deploy key's token store's) blob must be written by the core or by the setup
    session (the setup key's signature over `jarvis2-store-blob\n<store>\n<E>\n<sha256>`), else the phone computes no
    share. Enforced when the core's signed store list says `writers: true`; an earlier core is let through.
32. **Image attestation**: CI signs each session image with a key whose public half is `keys/ci.pub`; the router passes
    `imageSig` with every approval. Until `keys/ci.pub` exists in git the approval page says "not attested yet"; after, an
    unattested image is refused (New session and approvals). This replaces the unbuilt GitHub-attestation check.
33. **TestFlight secrets** live in the GitHub environment `release`, which only main can use.

## Carried over (still true)

34. **Sensitive stores** are never pre-selected; picking one shows an amber warning (the web page: a red "sensitive"
    badge on the store and an amber "Sensitive" row); any approval whose signed challenge marks one says so.
35. **The recovery kit** is one string, `jarvis2-kit:2:<master key>` (base64 PKCS#8 DER of the P-256 private key);
    whitespace ignored; a version-1 kit is refused in plain words. The master key exists only in the setup page's memory
    and in the kit; a pasted kit is forgotten on leaving the page and 10 minutes after pasting; Copy is local-only and
    expires after two minutes.
36. **What the app trusts besides the router comes from git**: `keys/box.pub`, `keys/setup.pub` (and `keys/ci.pub`),
    fetched from GitHub with no cache; only a CI build can point elsewhere (`JARVIS_CI`), and the phone replica's Release
    build may name another git ref of the same repo (`JarvisKeysRef`).
37. **Backups are refused whole** when any object isn't signed by the setup key, names another store, comes twice or
    doesn't open with the master key. The `core` store may be missing (the setup session sends the core its Fly token).
38. **Grants are chosen in the app, reviewed on the Face ID page**: feature, 1–10 minutes or a standing rule until a date;
    the router's draft is checked field for field (`Checks.reviewGrant`) before signing; a standing rule is refused for a
    sensitive session. The feature→key list (`api/holders`) is the router's word (every holder key is the router's).
39. **The Inbox** lists every request filed by a session, the web page or the setup session and every approval; its
    review page shows the three fields (what you sign, rendered from the signed content; the call the router recorded;
    the caller's reason, unverified) above the page's own content, and Deny.
40. **The permission mode is signed**; a resume in another mode, with a prompt or a rollback is an approval the app
    opens by itself.

## The web page (app/)

41. **Web only**: no iOS build, no shell bridge; the `.native.*` files, the React Native extension and the Radix-to-Swift
    generator are gone.
42. It can view everything, request a new session (any stores, sensitive ones badged; docs/DECISIONS.md 164), reject approvals, pause, resume and destroy;
    where the app would open a review, it files an Inbox request ("approve it in the Jarvis 2 app").
43. `web.yml` typechecks and exports it; the router serves the export at `/`.

## Finishing the native app (2026-10-11, late; decided while Deyao was away)

44. **Reset sends the blobs form** (R2) to a core with a store key (an empty bundle), like Recover; an earlier core gets
    the older empty bundle. Once this build has shipped, the core takes only the blobs form.
45. **The terminal never shows a blank page**: a native progress view covers the web view until the page has loaded; a
    load failure says why, with Try again.
46. **A Face ID sheet that never came up is asked for again** (simulator only, LocalAuthentication -1000 "UI activation
    timed out", 3 tries): a busy iOS 27 simulator failed the replica's Reset that way. A real phone's Secure Enclave
    prompt is untouched.

## Images on New session (2026-10-12; decided while Deyao was away)

47. **Four ways to add an image on the app's New session**: Photos (PhotosPicker, no library permission asked), the
    camera (UIImagePickerController wrapped for SwiftUI; shown only where a camera exists), Files (images only) and the
    clipboard (PasteButton, so iOS asks no paste permission). Each row shows the thumbnail, name and size, with Remove.
    Photos and camera shots go as JPEG (0.85, longest side 4096 px); PNG, JPEG, GIF and WebP from Files or the clipboard
    go as they are (docs/DECISIONS.md 97).
48. **Start uploads, then checks the signature covers these bytes**: each image goes to `api/uploads` under that Start's
    request id (a retry is a new request and uploads again), then the request names them; the signed config must list
    exactly these files, by the name the router answered and the sha256 and size of the bytes the phone holds, or Start
    refuses before Face ID.
49. **The approval page checks the router's copy**: for a session made elsewhere (the web page), each signed attachment
    shows name, size and hash from the signed config, and a thumbnail only when the bytes read back from the router hash
    to the signed value; otherwise it says the copy doesn't match (the machine would refuse it). New session itself has
    no separate "What you sign" for images: its own thumbnails are the bytes it hashed, and the check in 48 binds them.
50. **The web page**: images only, from a file picker or pasted into the page, as they are (docs/DECISIONS.md 95).

## No prose assembled by code on the web page (2026-10-12; decided while Deyao was away)

51. **Three kit pieces carry the rule** (`app/src/ui/kit.tsx`): `Rows`/`Row` (a label on the left, the value on the
    right, wrapping; each row has `data-row=<label>`), `BadgeList` (a short list such as stores as badges, "None" when
    empty) and `Quote` (text a person or an LLM wrote, a prompt or a caller's reason, under a small label naming whose
    it is). Dialogs (`ask`) take `rows` the same way; their titles are fixed ("Destroy session?") and the session or
    item they are about is a row.
52. **Session cards** show Stores, Harness, Model, Machine, Created, Paused and Auto-pause as rows; the state, skip
    perms, one-shot and a failed Claude login are pills. The turned-away feature is "Feature turned away" with Feature /
    Does rows and two buttons (Allow 10 min, Standing rule); a locked store is "Waiting for unlock" with a Store row.
    The explanatory sentences under each card (what Resume does, auto-pause in words) are gone.

53. **Inbox cards** have a fixed title per kind (Grant, Standing rule, Make deploy key, Unlock stores, New session…)
    and rows for what the entry is about (Session, Feature, For, Repo, Store, Stores, Mode) and where it came from
    (From, Asked, Expires, Call). The caller's reason is a Quote labelled "Reason (from <caller>, unverified)".
54. **Grants page**: the session is a row; a turned-away feature and each grant in force are rows (Feature, Does,
    Ends); the long explanation at the top is gone.

55. **New session, Schedules, Settings, Repos**: the session a page is about is a Session row; wakeups and crons are
    cards titled by name with At / Repeats / Next / Time zone / Runs / Until rows and the prompt as a Quote; usage, Fly
    spend and a repo's key are rows (Left, Resets, Cap, Rate, Running, Store, Key…); stores that must be picked in the
    app are amber badges; image counts are a badge. Toasts that dropped a name or value into a sentence are fixed
    strings now. Long explanations became one fixed line or went.

56. **Machines, Previous, Stores**: machine, volume, app and org facts are rows (Session, Name, Region, Size, Created,
    Router, Image, Attached to, Used by, Machines…); the page head is Orgs (badges), Machines and "Stand out" (a count
    pill); a previous session's archive is Transcripts / Artifact files rows, "not restorable" a pill; a store's state
    is all pills. A previous session's last message is a Quote labelled whose it was.

57. **Tasks**: a task's template, schedules, stores, filled-in values (one row per field), last run and detail are
    rows; a template's name, stores and fields are rows and badges; a daily schedule is Daily at / Time zone / Next
    rows (or an "off" pill); a run's trigger, latest image and exit code are badges, its times rows (Queued, Script
    started, Finished, Exit code, Run). A template's own description (written in task.json) shows as written.

58. **Banners, Search, Transcript, Remote, iCloud file**: a failed Claude login is "Claude login failed" with the
    sessions as badges; the Fly spend banner is a title with Spent / Cap / Month rows; search stats are Candidates /
    Took / Notes rows and an empty search says "Nothing found."; a transcript page heads with Paused or Destroyed and
    Shows rows; a search hit's and an iCloud file's facts are rows. Error text from the router keeps its short
    "Could not …:" prefix.

## No prose assembled by code in the iPhone app (2026-10-12; decided while Deyao was away)

59. **"What you sign (exact)" is a list of facts** (`SignedAction` returns `[SignedFact]`: id, label, value, style),
    rendered as `LabeledContent` rows by `SignedFactsSection`, each with the accessibility id `signed-<id>`
    (`signed-kind` "Core request" / "Phone grant", `signed-action`, `signed-repo`, `signed-store`, `signed-sensitive`,
    `signed-feature`, `signed-session`, `signed-line`, `signed-duration`, `signed-until`, `signed-stores`,
    `signed-unlocks`, `signed-unlock-scope`, `signed-prompt`, …). Every value still comes from the core-signed content
    (begin document, challenge, cert) or the checked grant, never router text. The interop test checks the facts by id.
60. **Review pages opened in the app (not from the Inbox) show the same section** in place of the old "What you allow"
    / "What happens" paragraphs (grant, unlock, repo key); the approval page keeps its own rows (session, stores,
    settings) with the prose turned into rows and badges ("Router's label" + Unverified, Action, Also unlocks + Open to,
    Image build badge, Roll back from).
61. **The Inbox request block**: Caller as a row (`request-caller`), the call line, a mismatch as a red row naming the
    differing option, and the caller's reason under "Reason (unverified)" as its own text with "Written by the caller."
    Inbox rows: a fixed title per kind, then the repo / feature / session / length as values and who / when / expires
    as icon labels.
62. **Session page**: a turned-away feature is a "Turned away" section with Feature and Allows rows and the two buttons
    ("Allow for 10 minutes", "Make a standing rule"); a locked store is a Store row with Unlock; auto-pause is one row;
    wakeups and crons are `WakeRow`s (when, name, next, prompt as written). Banners, Fly counts, usage and spend are rows.
63. **Dialogs** keep the HIG title ("Destroy “X”?") with a short fixed message; a destroy lists what it would lose one
    line per repo ("repo · 2 uncommitted · 1 unpushed"). Toasts are short fixed words ("Grant saved", "Copied").

## The offline copy (2026-10-13)

64. **Settings → Encrypted backup** is its own page under "Jarvis 2" (beside Reset or recover…): one button, Download
    encrypted backup, which shows "Reading the backups…" until the file exists (nothing optimistic), then the facts as
    rows (Bucket, Fetched, Stores, Sensitive markers, Checked against keys/setup.pub, Valid n of n or Not valid with
    each failing object and its problem in red) and the File section (Name, Size, Save file…, a `ShareLink`, so Save to
    Files, AirDrop and the rest come from the system share sheet). A failure is an inline error row, never an alert. No
    kit, no Face ID: the page reads and checks only public, sealed data.

## Devices (2026-10-13)

65. **The web page's Devices tab** (`views/Devices.tsx`, Jarvis 1's): one card per shared device: holder (a session's
    title, or Deyao), purpose, what it is doing, Deyao's note, when it lapses, the queue (position, title, purpose,
    what it waits to do) and the last five events; Take over / Hand back (a note in the dialog) and Force return, each
    two-phase (the card changes when /api/state shows it). Session cards carry lease pills ("holds iphone", "#2 for
    mac"). No Face ID: moving a lease reaches no secret. The iOS app has neither yet.
66. **Content stores** (docs/DECISIONS.md 132-133): the web page's Content tab (`views/Content.tsx`, a store's files on its
    own page `pages/ContentStore.tsx`: upload from a file picker into an optional folder, download, delete, delete the
    store with its name typed) and a Content stores picker on New session in both apps (checkbox cards; the iPhone's
    Start refuses a challenge whose signed `content` isn't exactly the picked set, and the review rows list them).
    Task forms list content stores for `optionsFrom: "content"` fields. Settings → Paired apps (web,
    `views/PairedApps.tsx`; iPhone `Settings/ContentView.swift`) lists Deyao's paired OpenClaw/Paseo apps with Remove. In
    the iPhone app Content and Paired apps are Settings rows, not tabs (the tab bar is full).
67. **What each store and key is for** (web page, `ui/storedocs.tsx`; Deyao, 2026-10-13): the store list comes from
    `GET api/stores` (the core's signed list plus each key, its writer and its explanation). The Stores tab shows each
    store's about text and every key (name in mono, explanation, "Written by session" + the session's title for a key a
    session wrote); each text has an inline Edit (a text box with Save / Cancel, Saving… and the router's error under
    it, "Saved" for a moment; saving an empty text removes it) that `PUT`s `api/stores/{store}/docs`. Keys with none
    show "no explanation yet"; a store whose key names aren't known says so. New session's store picker on the web page
    shows only each store's name and status pills, no about text or keys (Deyao, 2026-10-15: they took too much
    space). The iOS app: 68.
68. **Stores of keys in the iOS app** (core/keys.go; Deyao, 2026-10-13). Settings → Stores keeps one row per store (pills, the
    number of keys, Unlock); tapping the row opens the store's page: its about text and its keys (name in mono, how long
    ago it was written, "Written by session <title>" in orange for a key a session wrote, its explanation), each text
    with the inline Edit of 67 (`PUT api/stores/{store}/docs`). A key a session wrote is also always in view on the
    store's row (orange, with the session's title). Every page that unlocks (the Stores row, New session's Start, an approval,
    the unlock review, a batch item) shows the session-written keys of the stores it opens ("Written by a session",
    from `GET api/stores` keyInfo) and the Face ID prompt names them; the unlock then refuses any key the core's signed
    unlock_begin names as machine-written that the page didn't show (StoreUnlock), so a value a session chose is never
    released unseen. Setup-written keys are checked against keys/setup.pub per key; anything but setup, machine or core
    is refused. A resume on a new image or mode (resume-upgrade) also unlocks the line's locked stores for that
    challenge under its one Face ID, as New session does. Recover lays each store's key backups (keys/<store>/<key>.json)
    over its whole-store backup by time (a deleted key leaves; a store only key backups name comes back sensitive) and
    claims with the `keys` bundle when the core's identity says so; Settings → Encrypted backup counts and checks key
    backups too. Until the held core is live the app also speaks the earlier whole-store formats (each branch marked).

69. **Restoring a store** (docs/DECISIONS.md 165; Deyao, 2026-10-13). iPhone: a store's page (Settings → Stores → the
    store) ends with **Versions** (not for a repo's deploy-key store): the core's signed list, newest first, each row
    "Version N", a Current pill, what made it as a pill (Recover, Key written, Key deleted, Restore + From N, Session
    when a session wrote it), when, and its key names; every other row has **Restore…**, which opens the restore review
    sheet (also what an Inbox `restore` request opens): "What you sign (exact)" rendered from the core's signed begin
    (store, sensitive, version put back, version replaced, keys put back, written by a session, keys removed, keys
    unchanged, backups), then each key put back with its writer and each removed key; **Restore** signs and shares the
    keys put back under one Face ID; Cancel (Deny from the Inbox). Web: each store card has **Versions** (the same list,
    unverified) with **Propose restore**, which files the Inbox request; the Inbox lists it as "Restore store" with Store
    and Version rows. Walkthrough: a key of default deleted as the setup session, then put back through Versions.
70. **Upgrade has no last size** (docs/DECISIONS.md 167; Deyao, 2026-10-15). A memory alert always offers Upgrade: the
    router's `memAlert` names the next size, its memory and its guest (`nextSize`, `nextGb`, `nextGuest`), and the apps
    print those rather than a table of their own. Button: "Upgrade to Large (8 GB)" for the named sizes, "Upgrade to
    16 GB" past them (iPhone `Fmt.upgradeTitle`, web `sizeName`); the notice names the guest ("…back on a bigger machine (8×performance · 32 GB)…"
    on the web and in the iPhone footer). The "Already the biggest size" row and
    callout are gone. A refused step (Fly can't make the guest) shows as the job's failure with Fly's error, as before.

## API calls (2026-10-15)

70. **An API call opens its own review sheet** (docs/DECISIONS.md 169; Deyao, 2026-10-15). iPhone: tapping an "API call"
    row (or its context menu's Review) opens `APICallReviewView`: "Runs as you" (Method, Path, Body as indented JSON with
    its content type), "Who asked" (Caller, Asked, Expires), "Reason (unverified)"; Approve in the toolbar (no Face ID),
    Deny below, Cancel. After Approve the sheet shows the Result (HTTP status) and "What it brings about": each open
    follow-up as a row that pushes its approval page (the same `ApprovalView`, "What you sign (exact)", Face ID) and
    comes back when signed or rejected; answered ones as "Answered, denied or lapsed"; while the router awaits one, a
    spinner with its deadline; then "Nothing more to approve." and Done. Web: the card's Review opens the `call` page
    with the same sections; follow-ups show their rows and "Approve in the iPhone app", with Deny.
71. **Failed sessions, a session's repo, API calls in a batch** (docs/DECISIONS.md 181-183; Deyao, 2026-10-15). Both apps
    show Resume for every failed session (one with a machine finishes its pause first, router-side), and a destroy that
    ends "kill: …" asks "The machine wasn't destroyed" → Destroy anyway (`?force=1`), like a failed archive. A repo
    request a session made shows "Then: Add store github-… to the session that asked" and the session under "What you
    sign"; the iPhone takes ONE Face ID (`PhoneKeys.authorize`) for the key and the add-store the finish names
    (`followups`), which it checks to be exactly that store for that session before signing (`expectAddStore`); the web
    page shows an "Into session" row. A batch's API call is an item of its own ("API call, runs as you (no
    signature)"): Allow all approves it; what it brings about shows below as "What the API calls bring about", each
    opening the call's sheet already approved (its follow-ups under their own Face ID), then Done. The web page's batch
    card has "Review call" for its API calls.
72. **Disk, More disk, kept machines and volume backups** (docs/DECISIONS.md 175–178; 2026-10-15). Web: the card's Machine
    row adds "X of Y GB disk free" (the volume when the machine has one). A low-disk episode is a red callout like the
    memory one, with "More disk (N GB)" (POST …/disk, busy label "Adding disk…", then the job's phases) or, on a machine
    without a volume, why it can't grow. A kept machine (`snapshotFailed`) gets a red callout with Pause again and Destroy
    anyway; a line that won't resume (`noSnapshot`) gets one naming the newest volume backup and its expiry. "Volume
    backups" lists the newest three backups on the card (snapshot id, volume id, taken, kept until, whether the machine
    also signed its own snapshot, size; Copy buttons where the clipboard works). No action restores from a backup.

## Unfinished / known gaps

- Free text (prompt, title) reaches the machine signed only with a core that vouches (the held core doesn't).
- Content stores: the web page has the Content tab and both apps pick them on New session (66); the iPhone app has Settings → Content (list, files, delete, new store; uploads are the web page's). Devices and lease pills are in the web page only (65); attachments are images only (no other files).
- After a reinstall that loses the Keychain, the phone's keys and device key are new: an already-recovered core refuses a
  second claim; restart the core (a new, empty core) and Recover.
