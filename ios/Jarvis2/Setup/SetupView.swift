// Reset or recover: the only two ways to set Jarvis 2 up, both Deyao's alone (Deyao, 2026-10-10).
//   Reset    this page makes the master key pair and shows the recovery kit (the ONE string Deyao saves); once he says
//            it is saved, it sets the empty secrets up with it. The stores start empty.
//   Recover  Deyao pastes his kit; the page reads the backups through the router, checks and opens them, and sets the
//            empty secrets up with every store.
// Before either, the page checks secrets itself: the box key (keys/box.pub, from GitHub) signed its keys, and secrets
// signed its state. A secrets that is set up is ended first, only with the kit it was set up with. The master private key
// lives only in this page's memory and in the kit; a pasted kit is forgotten on leaving and 10 minutes after pasting.
// Either makes this iPhone's keys fresh (phone, agreement and root: PhoneKeys.renew) and names the phone and root keys in
// the master-signed claim; then the page asks for root's ⊤ on the sink, signed with the new root key on its own warning
// screen (RootKeyView) and kept by the router, which every new session's grant is cut from.
import SwiftUI

/// an error as Deyao reads it: one plain sentence, the technical part behind "Details"
struct Plain: Error, Equatable { let message: String; let detail: String }

func plain(_ e: Error, _ message: String) -> Plain {
  if let p = e as? Plain { return p }
  let d = errText(e)
  if case TrustError.badKit(let s) = e { return Plain(message: s, detail: d) }
  if e is RouterClient.CoreNotRunning { return Plain(message: "Jarvis 2 isn't answering right now. Try again in a minute.", detail: "the router reports no secrets (503)") }
  if e is URLError { return Plain(message: "Couldn't reach Jarvis 2.", detail: d) }
  return Plain(message: message, detail: d)
}

struct SetupView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
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
  @State private var showDetail = false
  @State private var doneText = ""
  @State private var wipeTimer: Task<Void, Never>?
  /// secrets says it is set up for this iPhone, but it isn't the one this iPhone pinned
  @State private var unpinned = false
  /// root's ⊤ on the sink went to the router after this setup
  @State private var rootGranted = false

  var body: some View {
    NavigationStack {
      Form {
        content
        if let failure {
          Section {
            ErrorRow(text: failure.message, id: "secure-error")
            DisclosureGroup("Details", isExpanded: $showDetail) {
              Text(failure.detail).font(.footnote.monospaced()).textSelection(.enabled).accessibilityIdentifier("secure-error-detail")
            }
            .accessibilityIdentifier("secure-error-details")
          }
        }
        Section { SigningFooter() }
      }
      .navigationTitle(step == .done ? "Jarvis 2" : "Reset or recover")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar { toolbar }
      .interactiveDismissDisabled(busy != nil)
      .task { await load() }
      .onDisappear { forget(); newKey = nil }
    }
  }

  @ViewBuilder private var content: some View {
    switch step {
    case .loading:
      Section { ProgressView() }
    case .unreachable:
      Section {
        Text("Jarvis 2 isn't answering right now.")
        Button("Try again") { Task { await load() } }.accessibilityIdentifier("setup-retry")
      }
    case .choose:
      Section {
        LabeledContent("Jarvis 2") { StatusPill(text: statusText, color: unpinned || status == .foreign ? .orange : status == .mine ? .green : .secondary) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("setup-state-\(statusName)")
      }
      Section {
        Button { pick(reset: true) } label: {
          Label { VStack(alignment: .leading) { Text("Reset").foregroundStyle(Color.primary); Text("New recovery kit, everything empty").font(.footnote).foregroundStyle(Color.secondary) } }
            icon: { Image(systemName: "sparkles") }
        }
        .accessibilityIdentifier("setup-choose-reset")
        Button { pick(reset: false) } label: {
          Label { VStack(alignment: .leading) { Text("Recover").foregroundStyle(Color.primary); Text("With your recovery kit").font(.footnote).foregroundStyle(Color.secondary) } }
            icon: { Image(systemName: "arrow.counterclockwise") }
        }
        .accessibilityIdentifier("setup-choose-recover")
      } footer: {
        if status != .empty { Text("Both need the current recovery kit and end the running sessions.") }
      }
    case .recover:
      kitField(header: "Recovery kit")
    case .confirmRestart:
      Section {
        Label("Restarts Jarvis 2 · running sessions end", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        Button(busy ?? "Restart and recover", role: .destructive) { Task { await recover(restart: true) } }
          .disabled(busy != nil).accessibilityElement(children: .combine).accessibilityIdentifier("setup-restart-confirm")
        Button("Cancel") { forget(); step = .choose }.disabled(busy != nil).accessibilityIdentifier("setup-restart-cancel")
      }
    case .resetAuth:
      Section {
        Label("Deletes every store · running sessions end", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
      }
      kitField(header: "Current recovery kit")
    case .newKit:
      if let k = newKey {
        let kit = RecoveryKit(master: k).string
        Section {
          Text(kit).font(.footnote.monospaced()).textSelection(.enabled).privacySensitive()
            .accessibilityLabel(kit).accessibilityIdentifier("setup-kit")
          Button(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc") { copy(kit) }
            .disabled(busy != nil).accessibilityIdentifier("setup-kit-copy")
          Button(busy ?? "I've saved it") { Task { await claimNew() } }
            .disabled(busy != nil).bold().accessibilityIdentifier("setup-kit-saved")
        } header: { Text("Your new recovery kit") } footer: {
          Text("Save it in your password manager: the only way to recover Jarvis 2.")
        }
      }
    case .done:
      Section { Label(doneText, systemImage: "checkmark.seal.fill").foregroundStyle(.green).accessibilityElement(children: .combine).accessibilityIdentifier("setup-done") }
      Section {
        if rootGranted {
          LabeledContent("Root grant") { StatusPill(text: "Signed", color: .green) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("setup-root-granted")
        } else {
          NavigationLink { RootKeyView(onDone: { rootGranted = true }) } label: {
            Label("Sign the root grant", systemImage: "exclamationmark.shield")
          }
          .accessibilityIdentifier("setup-root-grant")
        }
      } footer: { if !rootGranted { Text("New sessions start only once the root grant is signed.") } }
    }
  }

  @ToolbarContentBuilder private var toolbar: some ToolbarContent {
    ToolbarItem(placement: .cancellationAction) {
      if step == .done {
        Button("Done") { finishPage() }.accessibilityIdentifier("secure-back")
      } else if [Step.recover, .resetAuth, .newKit, .confirmRestart].contains(step) {
        Button("Back") { forget(); newKey = nil; failure = nil; step = .choose }.disabled(busy != nil).accessibilityIdentifier("secure-back")
      } else {
        Button("Close") { dismiss() }.accessibilityIdentifier("secure-back")
      }
    }
    if step == .recover || step == .resetAuth {
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? (step == .recover ? "Recover" : "Continue")) { Task { step == .recover ? await recover() : await authoriseReset() } }
          .disabled(kitText.isEmpty || busy != nil)
          .accessibilityIdentifier(step == .recover ? "setup-recover-go" : "setup-reset-go")
      }
    }
  }

  private func kitField(header: String) -> some View {
    Section {
      TextField("jarvis2-kit:2:…", text: $kitText, axis: .vertical)
        .font(.footnote.monospaced())
        .lineLimit(3...6)
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .privacySensitive()
        .accessibilityIdentifier("setup-kit-field")
        .onChange(of: kitText) { _, v in if !v.isEmpty { armWipe() } }
    } header: { Text(header) } footer: { Text("Paste it from your password manager.") }
  }

  private var statusName: String {
    switch status { case .empty: "empty"; case .mine: "mine"; case .otherPhone: "other-phone"; case .foreign: "foreign" }
  }
  private var statusText: String {
    if unpinned { return "Not the secrets this iPhone set up" }
    return switch status {
    case .empty: "Empty"
    case .mine: "Set up on this iPhone"
    case .otherPhone: "Set up for another iPhone"
    case .foreign: "Set up with another kit"
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
    wipeTimer = Task {
      try? await Task.sleep(for: .seconds(600))
      guard !Task.isCancelled else { return }
      kitText = ""; wipeTimer = nil
    }
  }
  private func finishPage() {
    model.showSetup = false
    Task { await model.loadLists(); await model.refresh() }
  }

  /// secrets as it is now: checked against the box key, its state signed by itself
  private func look() async throws -> (PublicKeys, CoreSetup.State) {
    let x = try await RouterClient.shared.identity()
    let box = try await KeySource.key("box.pub")
    return try CoreSetup.check(x.id, state: x.state, boxKey: box)
  }
  private func load() async {
    failure = nil; step = .loading
    do {
      let (k, st) = try await look()
      core = k; state = st
      status = CoreSetup.status(st, myMaster: CoreTrust.master, myPhone: try PhoneKeys.shared.publicKeys())
      // never pinned silently (audit finding 7): a secrets that says "this iPhone" but isn't the one pinned here could be
      // an impostor holding the box key (the master and phone keys are public). Only a Reset or Recover pins one.
      unpinned = status == .mine && CoreTrust.pinned != k
      step = .choose
    } catch is RouterClient.CoreNotRunning { step = .unreachable }
    catch {
      step = .unreachable
      failure = plain(error, error is TrustError ? "This doesn't look like your Jarvis 2, so the app stopped." : "Couldn't reach Jarvis 2.")
    }
  }
  /// after a wipe: the old secrets ends and Kubernetes starts a new, empty one (new keys)
  private func waitForEmptyCore(after old: PublicKeys) async throws -> (PublicKeys, CoreSetup.State) {
    for _ in 0..<90 {
      try await Task.sleep(for: .seconds(2))
      if let r = try? await look(), r.0 != old, r.1.master.isEmpty { return r }
    }
    throw Plain(message: "Jarvis 2 didn't come back after the restart. Try again in a few minutes.", detail: "no new, empty secrets within 3 minutes")
  }
  /// end the secrets that is running, with the kit it was set up with
  private func wipe(with m: MasterKey) async throws {
    guard let old = core else { return }
    busy = "Restarting Jarvis 2…"
    try await RouterClient.shared.wipe(try await withDevice(try CoreSetup.wipe(core: old, master: m, device: try PhoneKeys.shared.devicePublic())), core: old)
    let (k, st) = try await waitForEmptyCore(after: old)
    core = k; state = st; status = .empty
  }
  /// the pasted kit; for a secrets that is set up, it must be the kit it was set up with
  private func pastedKit(mustMatch: Bool) throws -> MasterKey {
    let m = try RecoveryKit.parse(kitText).master
    if mustMatch, let st = state, !m.matches(st.master) {
      throw Plain(message: "This isn't the recovery kit Jarvis 2 is set up with.", detail: "the kit's master key \(m.publicKey.prefix(16))… ≠ secrets' \(st.master.prefix(16))…")
    }
    return m
  }

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
      let setupKey = try await KeySource.key("setup.pub"), boxKey = try await KeySource.key("box.pub")
      let stores = try CoreSetup.readBackups(try await RouterClient.shared.backups(), master: m, setupKey: setupKey, boxKey: boxKey)
      busy = "Restoring…"
      // a new pairing: fresh phone and root keys, bound to the faces enrolled now (.biometryCurrentSet)
      PhoneKeys.shared.renew()
      let phone = try PhoneKeys.shared.publicKeys()
      let device = try PhoneKeys.shared.devicePublic(), root = try PhoneKeys.shared.rootPublic()
      // every key wrapped here on its own to secrets' store key (secrets never sees them in the clear)
      let sk = try await RouterClient.shared.storeKey(coreKey: c.signingKey)
      _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: try CoreSetup.keysBundle(stores, storeKey: sk),
                                                                                       root: root, device: device)), core: c)
      finish(c, master: m.publicKey, text: "Recovered")
    } catch {
      busy = nil
      if step == .confirmRestart { step = .recover }
      failure = plain(error, error is TrustError ? "The backups couldn't be opened with this kit." : "Recovering didn't work.")
    }
  }
  /// a secrets that is set up: end it with its current kit, then make the new kit
  private func authoriseReset() async {
    failure = nil
    do {
      busy = "Checking the kit…"
      let m = try pastedKit(mustMatch: true)
      try await wipe(with: m)
      forget(); busy = nil
      newKey = MasterKey.generate(); copied = false; step = .newKit
    } catch { busy = nil; failure = plain(error, "Resetting didn't work.") }
  }
  /// "I've saved it": the new master key sets the empty secrets up, with no stores
  private func claimNew() async {
    guard let m = newKey, let c = core else { return }
    failure = nil
    do {
      busy = "Setting up…"
      PhoneKeys.shared.renew()
      let phone = try PhoneKeys.shared.publicKeys()
      let sk = try await RouterClient.shared.storeKey(coreKey: c.signingKey)
      let bundle = try CoreSetup.keysBundle([], storeKey: sk)
      _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: bundle, root: try PhoneKeys.shared.rootPublic(),
                                                                                       device: try PhoneKeys.shared.devicePublic())), core: c)
      finish(c, master: m.publicKey, text: "Reset")
    } catch { busy = nil; failure = plain(error, "Setting up didn't work. Your kit is still the one shown; try again.") }
  }
  /// this install's device key countersigns the statement (claim or wipe): the setup session trusts a new master only
  /// from the device it pinned
  private func withDevice(_ body: [String: Any]) async throws -> [String: Any] {
    guard let st = body["statement"] as? String else { return body }
    var b = body
    let sig = try await offMain { try PhoneKeys.shared.deviceSign(st, reason: "Pair this iPhone with Jarvis 2") }
    b["deviceKey"] = try PhoneKeys.shared.devicePublic()
    b["deviceSig"] = sig.base64EncodedString()
    return b
  }

  private func finish(_ c: PublicKeys, master: String, text: String) {
    CoreTrust.pin(c, master: master)
    forget(); newKey = nil; busy = nil; rootGranted = false
    doneText = text
    step = .done
  }
  private func copy(_ s: String) {
    // local only (not to other devices), and gone from the clipboard after two minutes
    UIPasteboard.general.setItems([["public.utf8-plain-text": s]], options: [.localOnly: true, .expirationDate: Date.now.addingTimeInterval(120)])
    copied = true
  }
}
