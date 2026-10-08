# Design decisions in the Jarvis 2 app (for Deyao to review)

Carried over from the mock (DE0CH/jarvis2-mock DECISIONS.md) unless marked new.

1. **New session is split.** The React Native form (normal mode) keeps prompt, title, permission mode, model
   and size; its button says **Continue** and pushes the shell's secure page, where the **secret stores** and
   the **harness** are chosen for real, then **Create**. Create asks the router to start the machine, waits
   for the core's challenge (20–60 s, "Starting the machine…"), checks it carries exactly the stores and
   harness picked on that page, and signs it (one Face ID). The form's other fields travel along unsigned.
2. **Sensitive stores:** the React Native form (and the web form) never lists them; normal mode may
   pre-select non-sensitive stores only. A sensitive store is added only by a tap on the secure page, which
   then shows an amber warning. Any approval whose challenge includes a sensitive store shows the warning
   too (the core marks them in the signed challenge, so the router can't hide it).
3. **New: one secure page per approval kind, opened from a "Waiting for you" section** at the top of the
   Sessions tab (Review). The page reads the kind from the challenge's own fields and refuses when the
   router's label disagrees: new session (predecessor null), resume on the latest image (a core-signed burn
   cert naming the predecessor, same harness), add a store (the same machine, the added store in the set).
   It shows stores, harness, the image the core read from Fly, and Approve / Reject.
4. **New: Resume with latest image** is in the session's More menu (paused sessions); after the router has
   burned the old machine and started the new one, the app opens the approval page by itself.
5. **New: stores page in the shell** (Stores tab → "Unlock / lock…"): each store with Unlock (Face ID →
   the Enclave's share → sealed to the core's one-off key), the core's signed list of open unlocks (with my
   nonce) each with Lock, and "Mark sensitive…" with an inline confirm (the mark can't be undone). Lock
   needs no Face ID (it only removes access). The React Native Stores tab and the web page list the stores
   unverified, view only.
6. **New: pairing page in the shell.** Shows `jarvis2-phone:<signing>:<agreement>` (copy button) and takes the
   pasted `jarvis2-core:…` string, kept in the shell's Keychain. It opens by itself at launch until a core
   is paired ("Later" leaves it; the app can still view, nothing can be signed). Replacing the core key later
   needs Face ID/passcode. If the router reports a different core key, the pairing page says so (amber); the
   app never takes the key from the network.
7. **Phone keys:** two Secure Enclave P-256 keys (signing + key agreement), `.biometryAny`, Face ID on every
   use; public keys made at first launch without Face ID. The **simulator** uses software keys (its Face ID
   can't be driven from CI); the secure banner says which.
8. **New: sign-in belongs to the shell.** ASWebAuthenticationSession on `/api/auth/start?redirect=jarvis2://auth`,
   the token in the shell's Keychain, handed to the React Native UI over XPC with the router's address (one
   source: the shell's Info.plist). A refusal (ended on cloudflareaccess.com, a non-JSON 401/403, or the
   router's "Access login required") opens the sheet again and retries once. No sign-in screen on launch:
   the first refused request opens the sheet.
9. **Cut from the React Native app** (the router doesn't have them): tasks, schedules, terminal, content,
   search, wakeups, remotes, devices, repos, environments editor, usage, transcripts, attachments, one-shot,
   auto-pause, API proxy, Fly account. Their code and dependencies are gone, not hidden.
10. **The image** shows as the ref the core read from Fly (on approval pages); the GitHub build attestation
    ("CI build from <date>") isn't checked yet.
11. **iPhone only** (`TARGETED_DEVICE_FAMILY = 1`), portrait + landscape.
12. **The web page** can view everything, request a new session (non-sensitive stores; harness on the form),
    reject approvals, pause/resume/destroy; approvals happen only in the app.
13. **TestFlight from GitHub Actions** (not Xcode Cloud): the archive is built unsigned and the export signs
    it with Apple's cloud-managed distribution certificate (App Store Connect API key in repo secrets) —
    signing at archive time would mint a development certificate per runner, and the team is at its limit.
    Build number = the workflow's run number; internal group "Owner" (all builds). App record "Jarvis 2"
    (6820459076); icon = the Jarvis icon unchanged. `workflow_dispatch` with `only=testflight` ships without
    rerunning the walkthrough.
15. **React Native's frameworks sit in the app's `Frameworks/`**, not inside the extension (App Store
    validation refuses an extension that carries its own); the extension loads them via its rpath. The shell
    binary links none of them.
14. **CI walkthrough** runs twice (light, dark), each against a fresh core + router and a reset simulator
    keychain, because the core keeps the phone's keys in memory and refuses a second pairing.

## Unfinished / known gaps

- **Keyboard avoidance for React Native forms** still comes only from React Native (lessons/73: the
  extension sees keyboard height 0; the shell should resize the extension's area).
- **Free text** (prompt, title) goes to the machine unsigned (SECRETS-CONTROLLER.md "Open").
- **Fake machines never become `started`** in CI (nothing pulls secrets), so the walkthrough pauses and
  resumes sessions in `initialising`; the Pause button is offered there too.
- Approval pages show the router's session label (unsigned) next to the signed content.
- No GitHub build-attestation check of the session image (item 10).
