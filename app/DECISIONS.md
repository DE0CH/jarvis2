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
6. **Recovery page in the shell (replaces pairing).** It opens by itself at launch when no core is pinned,
   or when the router reports a core other than the pinned one ("Later" leaves it; the app can still view,
   nothing can be signed); also from Settings → Recovery. It shows the core's identity as 8 words only after
   checking the box key's signature (keys/box.pub from GitHub), then takes the kit (item 16), reads, checks
   and decrypts the backups, and sends the master-signed statement + the sealed bundle to
   `api/core/recover`. On the core's signed `recovered` it pins the core's two keys in the shell's Keychain
   and forgets the kit. The keys pinned are the ones the box vouched for and the core accepted the master's
   statement about — never taken from the router alone.
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
    (6820459076); icon = the Jarvis ring with a "2" at its centre (`app/scripts/make-icon.py`). `workflow_dispatch` with `only=testflight` ships without
    rerunning the walkthrough.
15. **React Native's frameworks sit in the app's `Frameworks/`**, not inside the extension (App Store
    validation refuses an extension that carries its own); the extension loads them via its rpath. The shell
    binary links none of them.
14. **CI walkthrough** runs twice (light, dark), each against a fresh core + router and a reset simulator
    keychain, because a core is recovered once: recovery (words checked against the core's log) → stores
    (create, unlock; the core's own and the harness's stores hidden, a marker-sensitive store sensitive) → new
    session → pause → resume → resume with the latest image → destroy → records → the master key page.

16. **New: the recovery kit formats** (what Deyao keeps in the password manager, two entries):
    `jarvis2-master:<base64 PKCS#8 DER of the P-256 private key>` (the body of a PEM "PRIVATE KEY" block, so
    `openssl pkey` reads it; the page also accepts the PEM itself) and `jarvis2-s3:<access key>:<secret key>`
    (read credentials for `jarvis2-backup-de0ch` at `https://fsn1.your-objectstorage.com`, region fsn1 — the
    endpoint and bucket are built in, not part of the kit). Both live only in the page's memory: wiped on
    success, on leaving the page, and 10 minutes after they were pasted.
17. **New: master key page** (Settings → Master key, or from the recovery page): a P-256 pair made in software
    on the iPhone (it must be exportable, so not the Enclave), the private kit shown once with Copy (clipboard
    local-only, expires after 2 minutes) and the public key (base64 X9.63, for keys/master.pub) with Copy.
    Never stored; leaving the page forgets it.
18. **New: what the shell trusts comes from GitHub, not the router**: `keys/box.pub` (the core's identity) and
    `keys/setup.pub` (the backups' signatures) are fetched from
    `https://raw.githubusercontent.com/DE0CH/jarvis2/main/keys/` when needed (no cache). The backups are read
    straight from the bucket (S3 SigV4 with CryptoKit's HMAC, no AWS SDK). Only a CI build can point both
    elsewhere: the code that reads the overrides is compiled only with `JARVIS_CI` (`JARVIS_CI_FLAG`, set on
    the simulator job's xcodebuild line), and the TestFlight job fails if the archive's Info.plist carries
    any override.
19. **New: the S3 stand-in in CI is `rclone serve s3`** (MinIO's downloads are gone, HTTP 410; moto doesn't
    check signatures) — it checks SigV4, so a wrong secret fails as on Hetzner. `ios/ci/standin.py` seeds it
    by calling infra/setup.py's own `backup` / `mark_sensitive_backup` with a per-run setup key and the public
    TEST master key; extra buckets hold a backup signed by another key and one without the core store (both
    must be refused). The keys are served by a local `http.server`.
20. **New: harness stores are hidden** (GET `api/policy`): not offered in any picker, left out of the
    session/record/approval summaries; the secure approval page still lists them (badged "Harness") since
    they are part of what is signed. The `core` store never shows (the core keeps it out of its list).
21. **The `core` store must be in the backups** (`infra/setup.py backup-core`): recovery refuses without it.
22. **Backups are refused whole** when any object under `stores/` or `sensitive/` isn't signed by the setup
    key, names another store, or doesn't open with the master key: a tampered bucket stops the recovery rather
    than quietly dropping a store.

## Unfinished / known gaps

- **Keyboard avoidance for React Native forms** still comes only from React Native (lessons/73: the
  extension sees keyboard height 0; the shell should resize the extension's area).
- **Free text** (prompt, title) goes to the machine unsigned (SECRETS-CONTROLLER.md "Open").
- **Fake machines never become `started`** in CI (nothing pulls secrets), so the walkthrough pauses and
  resumes sessions in `initialising`; the Pause button is offered there too.
- Approval pages show the router's session label (unsigned) next to the signed content.
- No GitHub build-attestation check of the session image (item 10).
- The app doesn't compare the master key's public half with keys/master.pub (it doesn't exist until Deyao
  makes the pair); a wrong key fails at the backups (they don't open) and at the core (403).
- After a reinstall the phone's keys are new, but an already-recovered core refuses a second recovery (409):
  the core has to be restarted (= a new core) and recovered again.
