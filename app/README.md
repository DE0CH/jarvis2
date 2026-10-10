# Jarvis 2 — the app

One Expo (React Native) codebase that is both the **web page** the router serves at `/` and the **iPhone
app** "Jarvis 2" (`dev.de0ch.jarvis2`, TestFlight). The iPhone app is a small trusted **Swift shell** that
owns the window, the keys and the secure pages, hosting the React Native UI in a bundled **ExtensionKit
extension** (its own process) — claude-env `selfhost/SECRETS-CONTROLLER.md`, lessons/73. It talks to the
router exactly as `docs/API.md` says. Design choices to review: [DECISIONS.md](DECISIONS.md).

```
src/                 React Native UI (expo-router): sessions + approvals, stores, previous sessions, settings, new
                     session, and the pages: terminal, transcript, grants, schedules
ios/Shell/           the shell (Swift, Apple frameworks only)
  CoreCrypto.swift   the core's formats, the master key and the kit, the checks around signing (no UI/network)
                     — also compiled into ios/interop
  CoreSetup.swift    Reset and Recover without UI: the core's identity and state checked, the backups (setup-key
                     signatures, master-key decryption), the claim and the wipe — also compiled into ios/interop
  KeySource.swift    keys/box.pub + keys/setup.pub from GitHub
  PhoneKeys.swift    Secure Enclave keys (simulator: software keys), the shell's Keychain, the pinned core + master
  RouterClient.swift sign-in (ASWebAuthenticationSession) + the router/core calls, every core answer verified
  SecurePages.swift  New session, approvals (new-session / resume-upgrade / add-store), stores
  SetupPage.swift    Reset or recover: the only two paths; one plain sentence per error, details folded away
  Grants.swift       the grant page: a feature in a session for minutes, or a standing rule (signed here)
  Jarvis2App.swift   window, normal ⇄ secure mode, XPC with the extension
ios/Extension/       the extension: React Native started like Expo's AppDelegate; ShellBridge (JS ⇄ shell)
ios/Shared/          the XPC protocols
ios/UITests/         the simulator walkthrough
ios/interop/         CoreCrypto + CoreSetup against the real core binary and router (swift run)
ios/ci/              CI stand-ins: throwaway box/setup keys, the backup bucket on rclone's S3 server
```

## Web page → the router

```bash
cd app && npm ci && npx expo export --platform web --output-dir ../web    # = npm run build:web
```

The output is **`web/` at the repo root**; the images workflow runs exactly this command and the router
image serves that directory (`WEB_DIR`). The web page views everything and can request a new session,
reject an approval and pause/resume/destroy; approvals happen only in the app (it has no keys).

## CI (`.github/workflows/app.yml`, GitHub's free macOS runners — the repo is public)

- **web** — typecheck + the web export.
- **interop** — `ios/ci/standins.sh` (throwaway box + setup keys, the backups on `rclone serve s3` seeded by
  infra/setup.py's code and sealed to the public TEST master key, the core built with `-tags fakefly`, a router
  reading the stand-in bucket), then `swift run Interop` (env in its header). Locally on Linux a swift.org toolchain uses swift-crypto.
- **simulator** — the same stand-ins + router (`NO_ACCESS=1`, `SNAPSHOT_WAIT_SECONDS=2`, a test policy) on
  the runner (the core in a restart loop, as under Kubernetes), the app built with
  `JARVIS_BASE=http://127.0.0.1:18080/` and `JARVIS_CI_FLAG=JARVIS_CI` (keys from the stand-in), then the UI
  walkthrough once light, once dark (fresh core, router and simulator keychain each time): Recover with the TEST
  kit → stores → new session (secure page, software key) → pause → grants → schedules → terminal → resume (prompt)
  → resume with the latest image (approval) → destroy → previous → search (conversations, iCloud) → settings →
  Reset. Screenshots: the
  run's `results` artifact (`light/`, `dark/`).
- **testflight** (main only, after the others pass) — archive with cloud signing (App Store Connect API key:
  repo secrets `ASC_KEY_ID` / `ASC_ISSUER_ID` / `ASC_PRIVATE_KEY`), upload; build number = the run number.
  App Store Connect app "Jarvis 2" (id 6820459076); internal group "Owner" gets every build.

Release builds talk to `https://jarvis2.deyaochen.com/` (`JARVIS_BASE` in `ios/project.yml`).
