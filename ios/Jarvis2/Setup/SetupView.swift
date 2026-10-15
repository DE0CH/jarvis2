// Reset or recover: the only two ways to set Jarvis 2 up, both Deyao's alone (Deyao, 2026-10-10).
//   Reset    this page makes the master key pair and shows the recovery kit (the ONE string Deyao saves); once he says
//            it is saved, it sets the empty core up with it. The stores start empty.
//   Recover  Deyao pastes his kit; the page reads the backups through the router, checks and opens them, and sets the
//            empty core up with every store.
// Before either, the page checks the core itself: the box key (keys/box.pub, from GitHub) signed its keys, and the core
// signed its state. A core that is set up is ended first, only with the kit it was set up with. The master private key
// lives only in this page's memory and in the kit; a pasted kit is forgotten on leaving and 10 minutes after pasting.
import SwiftUI

/// an error as Deyao reads it: one plain sentence, the technical part behind "Details"
struct Plain: Error, Equatable { let message: String; let detail: String }

func plain(_ e: Error, _ message: String) -> Plain {
  if let p = e as? Plain { return p }
  let d = errText(e)
  if case TrustError.badKit(let s) = e { return Plain(message: s, detail: d) }
  if e is RouterClient.CoreNotRunning { return Plain(message: "Jarvis 2 isn't answering right now. Try again in a minute.", detail: "the router reports no core (503)") }
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
  /// the core says it is set up for this iPhone, but it isn't the one this iPhone pinned
  @State private var unpinned = false
  /// the core takes a seed (core/continuity.go): its keys come from the kit, so a Recover keeps the sessions
  @State private var takesSeed = false
  /// the Recover asked for is alongside the serving core (standby until it hands over)
  @State private var alongside = false

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
        // blue/green (core/continuity.go): this core is Recovered while the one before it still serves, and takes over
        // when that one hands over; only a core that takes a seed, and only an empty one (the router shows it)
        if takesSeed && status == .empty { alongsideButton }
      } footer: {
        if status != .empty {
          if state?.derived == true { Text("Both need the current recovery kit. Recover keeps the sessions; Reset ends them.") }
          else { Text("Both need the current recovery kit and end the running sessions.") }
        }
      }
    case .recover:
      kitField(header: "Recovery kit")
    case .confirmRestart:
      Section {
        if state?.derived == true {
          Label("Restarts Jarvis 2 · sessions carry on", systemImage: "arrow.clockwise").foregroundStyle(.orange)
        } else {
          Label("Restarts Jarvis 2 · running sessions end", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
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
      Section {
        Label(doneText, systemImage: "checkmark.seal.fill").foregroundStyle(.green).accessibilityElement(children: .combine).accessibilityIdentifier("setup-done")
      } footer: {
        if state?.serving == "standby" { Text("Waiting for the running core to hand over.") }
      }
    }
  }

  private var alongsideButton: some View {
    Button { failure = nil; alongside = true; step = .recover } label: {
      Label {
        VStack(alignment: .leading) {
          Text("Recover alongside").foregroundStyle(Color.primary)
          Text("The running core keeps serving until it hands over").font(.footnote).foregroundStyle(Color.secondary)
        }
      } icon: { Image(systemName: "arrow.left.arrow.right") }
    }
    .accessibilityIdentifier("setup-choose-recover-alongside")
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
    if unpinned { return "Not the core this iPhone set up" }
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
    } else { alongside = false; step = .recover }
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

  /// the core as it is now: checked against the box key, its state signed by itself
  private func look() async throws -> (PublicKeys, CoreSetup.State) {
    let id = try await RouterClient.shared.identity()
    let box = try await KeySource.key("box.pub")
    let (k, st) = try CoreSetup.check(id, boxKey: box)
    if k == CoreTrust.pinned { LineWitness.saw(k.signingKey, st.lineSeq) }
    takesSeed = id.takesSeed
    return (k, st)
  }
  private func load() async {
    failure = nil; step = .loading
    do {
      let (k, st) = try await look()
      core = k; state = st
      status = CoreSetup.status(st, myMaster: CoreTrust.master, myPhone: try PhoneKeys.shared.publicKeys())
      // never pinned silently (audit finding 7): a core that says "this iPhone" but isn't the core pinned here could be
      // an impostor holding the box key (the master and phone keys are public). Only a Reset or Recover pins a core.
      unpinned = status == .mine && CoreTrust.pinned != k
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
      try await Task.sleep(for: .seconds(2))
      if let r = try? await look(), r.0 != old, r.1.master.isEmpty { return r }
    }
    throw Plain(message: "Jarvis 2 didn't come back after the restart. Try again in a few minutes.", detail: "no new, empty core within 3 minutes")
  }
  /// end the core that is running, with the kit it was set up with
  private func wipe(with m: MasterKey) async throws {
    guard let old = core else { return }
    busy = "Restarting Jarvis 2…"
    try await RouterClient.shared.wipe(try await withDevice(try CoreSetup.wipe(core: old, master: m, device: try PhoneKeys.shared.devicePublic())), core: old)
    let (k, st) = try await waitForEmptyCore(after: old)
    core = k; state = st; status = .empty
  }
  /// the pasted kit; for a core that is set up, it must be the kit it was set up with
  private func pastedKit(mustMatch: Bool) throws -> MasterKey {
    let m = try RecoveryKit.parse(kitText).master
    if mustMatch, let st = state, !m.matches(st.master) {
      throw Plain(message: "This isn't the recovery kit Jarvis 2 is set up with.", detail: "the kit's master key \(m.publicKey.prefix(16))… ≠ the core's \(st.master.prefix(16))…")
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
      // the phone keeps its keys: the sessions' certs name them (grants), and the deploy-key stores the core brings back
      // are wrapped to them. Keys the Enclave would refuse (other faces enrolled since) are made again: a new pairing.
      PhoneKeys.shared.keepOrRenew()
      let phone = try PhoneKeys.shared.publicKeys()
      let device = try PhoneKeys.shared.devicePublic()
      // a core that takes a seed (core/continuity.go) becomes the core the kit derives, with the record of the
      // sessions the router kept from the earlier one: the sessions carry on
      var seed: Data?, derived: PublicKeys?, line: CoreSetup.LineStateDoc?
      if takesSeed {
        let sd = CoreContinuity.seed(m)
        let dk = try CoreContinuity.keys(seed: sd)
        seed = sd; derived = dk
        if let l = try await RouterClient.shared.lineState() {
          do { _ = try CoreSetup.checkLineState(l, coreKey: dk.signingKey, atLeast: LineWitness.seen(dk.signingKey)); line = l }
          catch { throw Plain(message: "The router served an older or altered record of the sessions.", detail: errText(error)) }
        }
      }
      // a core whose identity says bundle "keys" gets every key wrapped here on its own (it never sees them in the
      // clear); a core from before keys.go (until the held core is live) takes blobs, and an earlier core (no store key,
      // or 400 "bad bundle") the stores sealed to it as before
      var claimed = false
      let keys = try await RouterClient.shared.coreTakesKeys()
      if keys {
        guard let sk = try await RouterClient.shared.storeKey(coreKey: c.signingKey, core: derived?.agreementKey) else { throw TrustError.stale("store key") }
        let bundle = try CoreSetup.keysBundle(stores, storeKey: sk, coreSeed: seed, lineState: line)
        let standby = alongside && derived != nil
        _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: bundle, device: device, identity: derived, standby: standby)),
                                                core: c, answeredBy: derived?.signingKey)
        claimed = true
      } else if let sk = try await RouterClient.shared.storeKey(coreKey: c.signingKey) {
        do {
          _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: try CoreSetup.blobsBundle(stores, storeKey: sk), device: device)), core: c)
          claimed = true
        } catch let e as RouterError where e.status == 400 && e.message.contains("bad bundle") {}
      }
      if !claimed {
        _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: try CoreSetup.bundle(stores), device: device)), core: c)
      }
      finish(try await settled(c, derived: derived, master: m), master: m.publicKey, text: alongside && derived != nil ? "Recovered alongside" : "Recovered")
    } catch {
      busy = nil
      if step == .confirmRestart { step = .recover }
      failure = plain(error, error is TrustError ? "The backups couldn't be opened with this kit." : "Recovering didn't work.")
    }
  }
  /// a core that is set up: end it with its current kit, then make the new kit
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
  /// "I've saved it": the new master key sets the empty core up, with no stores
  private func claimNew() async {
    guard let m = newKey, let c = core else { return }
    failure = nil
    do {
      busy = "Setting up…"
      PhoneKeys.shared.renew()
      let phone = try PhoneKeys.shared.publicKeys()
      // a core with a store key takes only the app's blobs form (R2); an earlier core, the older empty bundle
      // a core whose identity says bundle "keys" takes the keys form; a core from before keys.go (until the held core is
      // live) the app's blobs form (R2); an earlier core, the older empty bundle
      // a core that takes a seed becomes the core the new kit derives (its sessions then outlive a restart)
      let seed: Data? = takesSeed ? CoreContinuity.seed(m) : nil
      let derived = try seed.map { try CoreContinuity.keys(seed: $0) }
      let sk = try await RouterClient.shared.storeKey(coreKey: c.signingKey, core: derived?.agreementKey)
      let bundle: Data
      if try await RouterClient.shared.coreTakesKeys(), let sk { bundle = try CoreSetup.keysBundle([], storeKey: sk, coreSeed: seed) }
      else { bundle = try sk.map { try CoreSetup.blobsBundle([], storeKey: $0) } ?? CoreSetup.bundle([]) }
      _ = try await RouterClient.shared.claim(try await withDevice(try CoreSetup.claim(core: c, phone: phone, master: m, bundle: bundle, device: try PhoneKeys.shared.devicePublic(), identity: derived)), core: c, answeredBy: derived?.signingKey)
      finish(try await settled(c, derived: derived, master: m), master: m.publicKey, text: "Reset")
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

  /// the keys to pin after a claim: the boot keys, or for a seeded claim the derived ones — the core now answers with
  /// them (checked against the box key and its own signed state, as before). The derived keys come from the kit itself,
  /// so they are pinned even if that check can't be made right now; a core that answers other keys is refused.
  private func settled(_ boot: PublicKeys, derived: PublicKeys?, master m: MasterKey) async throws -> PublicKeys {
    guard let derived else { return boot }
    for i in 0..<5 {
      if i > 0 { try await Task.sleep(for: .seconds(1)) }
      guard let r = try? await look() else { continue }
      let (k, st) = r
      guard k == derived, m.matches(st.master) else {
        throw Plain(message: "Jarvis 2 didn't take the keys of your recovery kit.", detail: "the core answers \(k.signingKey.prefix(16))…, the kit derives \(derived.signingKey.prefix(16))…")
      }
      LineWitness.saw(k.signingKey, st.lineSeq)
      core = k; state = st
      break
    }
    return derived
  }

  private func finish(_ c: PublicKeys, master: String, text: String) {
    // the lines this iPhone knows stay pinned when the core is the one it had (a Recover with the same kit)
    if CoreTrust.pinned != c { LinePins.clear() }
    CoreTrust.pin(c, master: master)
    forget(); newKey = nil; busy = nil
    doneText = text
    step = .done
  }
  private func copy(_ s: String) {
    // local only (not to other devices), and gone from the clipboard after two minutes
    UIPasteboard.general.setItems([["public.utf8-plain-text": s]], options: [.localOnly: true, .expirationDate: Date.now.addingTimeInterval(120)])
    copied = true
  }
}
