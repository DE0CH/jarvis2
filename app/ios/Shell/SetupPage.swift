// The shell's one page for setting Jarvis 2 up — the only two paths there are (Deyao, 2026-10-10):
//   Reset    make new: this page makes the master key pair, shows the recovery kit (the ONE string Deyao saves),
//            and once he says it is saved, sets the empty core up with it. The stores start empty.
//   Recover  Deyao pastes his kit: the page reads the backups through the router, checks and opens them, and
//            sets the empty core up with every store.
// Neither path waits on anyone else. Before either, the page checks the core itself: the box key (keys/box.pub,
// from GitHub) signed its keys, and the core signed its state (empty, or set up with which master key). A core
// that is already set up is ended first, only with the kit it was set up with (CoreSetup.wipe); a new, empty core
// takes its place. The master private key lives only in this page's memory and in the kit.
import CryptoKit
import SwiftUI
import UIKit

/// an error as Deyao reads it: one plain sentence, the technical part behind "Details"
struct Plain: Equatable { let message: String; let detail: String }

func plain(_ e: Error, _ message: String) -> Plain {
  let d = errText(e)
  if case TrustError.badKit(let s) = e { return Plain(message: s, detail: d) }
  if e is RouterClient.CoreNotRunning { return Plain(message: "Jarvis 2 isn't answering right now. Try again in a minute.", detail: "the router reports no core (503)") }
  if (e as? URLError) != nil { return Plain(message: "Couldn't reach Jarvis 2.", detail: d) }
  return Plain(message: message, detail: d)
}

struct ErrorBox: View {
  let p: Plain
  @State private var open = false
  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Callout(text: p.message, color: .red).accessibilityIdentifier("secure-error")
      KitButton(title: open ? "Hide details" : "Details", variant: .ghost, color: .gray, size: 1, id: "secure-error-details") { open.toggle() }
      if open { CodeBox(text: p.detail, id: "secure-error-detail") }
    }
    .padding(.top, 16)
  }
}

/// a pasted kit's field: monospaced, no autocorrect, hidden from screenshots
func secretField(_ ph: String, _ text: Binding<String>, _ id: String, onChange: @escaping (String) -> Void) -> some View {
  KitTextArea(placeholder: ph, text: text, rows: 3, mono: true, id: id)
    .privacySensitive()
    .padding(.top, 8)
    .onChange(of: text.wrappedValue) { _, v in onChange(v) }
}

struct SetupPage: View {
  let shell: Shell
  enum Step: Equatable { case loading, unreachable, choose, recover, confirmRestart, resetAuth, newKit, done }
  @State private var step: Step = .loading
  @State private var core: PublicKeys?
  @State private var state: CoreSetup.State?
  @State private var status: CoreSetup.Status = .empty
  @State private var kitText = ""
  @State private var newKey: MasterKey?
  @State private var copied = false
  @State private var busy: String?
  @State private var failure: Plain?
  @State private var doneText = ""
  @State private var wipeTimer: Task<Void, Never>?

  private var action: (title: String, id: String, disabled: Bool)? {
    switch step {
    case .recover: return ("Recover", "setup-recover-go", kitText.isEmpty)
    case .resetAuth: return ("Continue", "setup-reset-go", kitText.isEmpty)
    default: return nil
    }
  }

  var body: some View {
    SecureFrame(shell: shell, title: step == .done ? "Jarvis 2" : "Reset or recover", action: action, busy: busy,
                run: { Task { step == .recover ? await recover() : await authoriseReset() } },
                backTitle: step == .done ? "Done" : "← Back", onBack: backAction) {
      switch step {
      case .loading:
        ProgressView().frame(maxWidth: .infinity).padding(.top, 24)
      case .unreachable:
        P(text: "Jarvis 2 isn't answering right now.").padding(.top, 16)
        HStack { KitButton(title: "Try again", variant: .soft, id: "setup-retry") { Task { await load() } }; Spacer() }.padding(.top, 12)
      case .choose:
        P(text: headline).padding(.top, 16).accessibilityIdentifier("setup-state-\(statusName)")
        VStack(spacing: 8) {
          ChoiceCard(on: false, id: "setup-choose-reset", action: { pick(reset: true) }) {
            ChoiceText(title: "Reset", sub: "Start fresh with a new recovery kit. Everything starts empty.")
          }
          ChoiceCard(on: false, id: "setup-choose-recover", action: { pick(reset: false) }) {
            ChoiceText(title: "Recover", sub: "Bring everything back with the recovery kit in your password manager.")
          }
        }.padding(.top, 16)
        if status != .empty {
          Muted(text: "Both need the recovery kit Jarvis 2 is set up with now, and end what is running on it.").padding(.top, 12)
        }
      case .recover:
        Lbl(text: "Recovery kit")
        Muted(text: "Paste it from your password manager.")
        secretField("jarvis2-kit:2:…", $kitText, "setup-kit-field") { v in if !v.isEmpty { armWipe() } }
      case .confirmRestart:
        Callout(text: "Jarvis 2 is running with this kit. Recovering restarts it, and the sessions running on it end.", amber: true).padding(.top, 16)
        HStack(spacing: 8) {
          KitButton(title: "Restart and recover", color: .red, busy: busy != nil, id: "setup-restart-confirm") { Task { await recover(restart: true) } }
          KitButton(title: "Cancel", variant: .soft, color: .gray, disabled: busy != nil, id: "setup-restart-cancel") { forget(); step = .choose }
          Spacer()
        }.padding(.top, 12)
      case .resetAuth:
        Callout(text: "Resetting ends Jarvis 2 as it is now: its stores and the sessions running on it.", amber: true).padding(.top, 16)
        Lbl(text: "The recovery kit it is set up with")
        Muted(text: "Paste it from your password manager.")
        secretField("jarvis2-kit:2:…", $kitText, "setup-kit-field") { v in if !v.isEmpty { armWipe() } }
      case .newKit:
        if let k = newKey {
          Lbl(text: "Your new recovery kit")
          Muted(text: "Save it in your password manager. It is the only way to recover Jarvis 2.")
          CodeBox(text: RecoveryKit(master: k).string, id: "setup-kit").privacySensitive().padding(.top, 8)
          HStack(spacing: 8) {
            KitButton(title: copied ? "Copied" : "Copy", variant: .soft, color: copied ? .green : .blue, disabled: busy != nil, id: "setup-kit-copy") { copy(RecoveryKit(master: k).string) }
            KitButton(title: busy ?? "I've saved it", busy: busy != nil, id: "setup-kit-saved") { Task { await claimNew() } }
            Spacer()
          }.padding(.top, 12)
        }
      case .done:
        Callout(text: doneText, color: .blue).padding(.top, 16).accessibilityIdentifier("setup-done")
      }
      if let failure { ErrorBox(p: failure) }
    }
    .task { await load() }
    .onDisappear { forget(); newKey = nil }
  }

  /// Back: a step goes back to the choice; Done leaves as finished; otherwise the page closes
  private var backAction: (() -> Void)? {
    if step == .done { return { shell.exitSecure("set up", done: true) } }
    if [Step.recover, .resetAuth, .newKit, .confirmRestart].contains(step) {
      return { forget(); newKey = nil; failure = nil; step = .choose }
    }
    return nil
  }

  private var statusName: String {
    switch status { case .empty: return "empty"; case .mine: return "mine"; case .otherPhone: return "other-phone"; case .foreign: return "foreign" }
  }
  private var headline: String {
    switch status {
    case .empty: return "Jarvis 2 is empty. Choose one:"
    case .mine: return "Jarvis 2 is set up on this iPhone."
    case .otherPhone: return "Jarvis 2 is set up with your recovery kit, for another iPhone."
    case .foreign: return "Jarvis 2 is set up with a different recovery kit."
    }
  }

  private func pick(reset: Bool) {
    failure = nil
    if reset {
      if status == .empty { newKey = MasterKey.generate(); copied = false; step = .newKit } else { step = .resetAuth }
    } else { step = .recover }
  }

  /// forget a pasted kit (it never outlives the page, and goes after 10 minutes)
  private func forget() { kitText = ""; wipeTimer?.cancel(); wipeTimer = nil }
  private func armWipe() {
    guard wipeTimer == nil else { return }
    wipeTimer = Task { @MainActor in
      try? await Task.sleep(nanoseconds: 600_000_000_000)
      guard !Task.isCancelled else { return }
      kitText = ""; wipeTimer = nil
    }
  }

  /// the core as it is now: checked against the box key, its state signed by itself
  private func look() async throws -> (PublicKeys, CoreSetup.State) {
    let id = try await RouterClient.shared.identity()
    let box = try await KeySource.key("box.pub")
    let (k, st) = try CoreSetup.check(id, boxKey: box)
    return (k, st)
  }

  private func load() async {
    failure = nil; step = .loading
    do {
      let (k, st) = try await look()
      core = k; state = st
      status = CoreSetup.status(st, myMaster: CoreTrust.master, myPhone: try PhoneKeys.shared.publicKeys())
      if status == .mine, CoreTrust.pinned != k { CoreTrust.pin(k, master: st.master) } // set up from here, never pinned
      step = .choose
    } catch is RouterClient.CoreNotRunning { step = .unreachable }
    catch {
      step = .unreachable
      failure = plain(error, error is TrustError ? "This doesn't look like your Jarvis 2, so the app stopped." : "Couldn't reach Jarvis 2.")
    }
  }

  /// after a wipe: the old core ends and Kubernetes starts a new, empty one (new keys)
  private func waitForEmptyCore(after old: PublicKeys) async throws -> (PublicKeys, CoreSetup.State) {
    for _ in 0..<90 {
      try await Task.sleep(nanoseconds: 2_000_000_000)
      if let r = try? await look(), r.0 != old, r.1.master.isEmpty { return r }
    }
    throw Plain2(Plain(message: "Jarvis 2 didn't come back after the restart. Try again in a few minutes.", detail: "no new, empty core within 3 minutes"))
  }

  /// end the core that is running, with the kit it was set up with
  private func wipe(with m: MasterKey) async throws {
    guard let old = core else { return }
    busy = "Restarting Jarvis 2…"
    try await RouterClient.shared.wipe(try CoreSetup.wipe(core: old, master: m), core: old)
    let (k, st) = try await waitForEmptyCore(after: old)
    core = k; state = st; status = .empty
  }

  /// the pasted kit; for a core that is set up, it must be the kit it was set up with
  private func pastedKit(mustMatch: Bool) throws -> MasterKey {
    let m = try RecoveryKit.parse(kitText).master
    if mustMatch, let st = state, !m.matches(st.master) {
      throw Plain2(Plain(message: "This isn't the recovery kit Jarvis 2 is set up with.", detail: "the kit's master key \(m.publicKey.prefix(16))… ≠ the core's \(st.master.prefix(16))…"))
    }
    return m
  }

  // ---- Recover ----
  private func recover(restart: Bool = false) async {
    failure = nil
    do {
      busy = "Checking the kit…"
      let m = try pastedKit(mustMatch: status != .empty)
      if status != .empty {
        if !restart { busy = nil; step = .confirmRestart; return }
        try await wipe(with: m)
      }
      guard let c = core else { return }
      busy = "Reading the backups…"
      let setupKey = try await KeySource.key("setup.pub")
      let stores = try CoreSetup.readBackups(try await RouterClient.shared.backups(), master: m, setupKey: setupKey)
      busy = "Restoring…"
      let phone = try PhoneKeys.shared.publicKeys()
      let n = try await RouterClient.shared.claim(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: try CoreSetup.bundle(stores)), core: c)
      finish(c, master: m.publicKey, log: "recovered: \(n) stores", text: "Jarvis 2 is recovered.")
    } catch {
      busy = nil
      if step == .confirmRestart { step = .recover }
      failure = (error as? Plain2)?.p ?? plain(error, error is TrustError ? "The backups couldn't be opened with this kit." : "Recovering didn't work.")
    }
  }

  // ---- Reset ----
  /// a core that is set up: end it with its current kit, then make the new kit
  private func authoriseReset() async {
    failure = nil
    do {
      busy = "Checking the kit…"
      let m = try pastedKit(mustMatch: true)
      try await wipe(with: m)
      forget(); busy = nil
      newKey = MasterKey.generate(); copied = false; step = .newKit
    } catch { busy = nil; failure = (error as? Plain2)?.p ?? plain(error, "Resetting didn't work.") }
  }

  /// "I've saved it": the new master key sets the empty core up, with no stores
  private func claimNew() async {
    guard let m = newKey, let c = core else { return }
    failure = nil
    do {
      busy = "Setting up…"
      let phone = try PhoneKeys.shared.publicKeys()
      _ = try await RouterClient.shared.claim(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: try CoreSetup.bundle([])), core: c)
      finish(c, master: m.publicKey, log: "reset: a new master key", text: "Jarvis 2 is reset. Its stores start empty.")
    } catch { busy = nil; failure = plain(error, "Setting up didn't work. Your kit is still the one shown; try again.") }
  }

  private func finish(_ c: PublicKeys, master: String, log: String, text: String) {
    CoreTrust.pin(c, master: master)
    forget(); newKey = nil; busy = nil
    shell.prefetched = nil
    shell.log(log)
    doneText = text
    step = .done
  }

  private func copy(_ s: String) {
    UIPasteboard.general.setItems([["public.utf8-plain-text": s]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)])
    copied = true
  }
}

/// a Plain carried as an Error
struct Plain2: Error { let p: Plain; init(_ p: Plain) { self.p = p } }
