// The shell's secure pages: drawn only by the shell (the React Native UI's view is gone while one is up).
// What they show comes from the core's signed answers (checked against the core keys pinned at recovery); what the
// phone signs is checked first (CoreCrypto.swift, Checks).
import CryptoKit
import LocalAuthentication
import SwiftUI
import UIKit

/// the app's Page top bar (src/ui/page.tsx): ← Back · title · primary action, then the secure banner
struct SecureFrame<Content: View>: View {
  let shell: Shell
  let title: String
  var action: (title: String, id: String, disabled: Bool)? = nil
  var busy: String? = nil
  var run: () -> Void = {}
  var backTitle = "← Back"
  /// Back to another secure page instead of leaving secure mode
  var onBack: (() -> Void)? = nil
  @ViewBuilder let content: () -> Content
  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 12) {
        KitButton(title: backTitle, variant: .soft, color: .gray, disabled: busy != nil, id: "secure-back") { if let onBack { onBack() } else { shell.exitSecure("back") } }
        Text(title).font(.system(size: K.fontSize[4], weight: .bold)).foregroundStyle(Radix.gray.s[12]).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
        if let a = action { KitButton(title: busy ?? a.title, disabled: a.disabled, busy: busy != nil, id: a.id, action: run) }
      }
      .padding(.horizontal, 20).padding(.vertical, 16)
      .overlay(alignment: .bottom) { Rectangle().fill(Radix.gray.a[5]).frame(height: 1) }
      ScrollView {
        VStack(alignment: .leading, spacing: 0) {
          HStack(spacing: 6) {
            Image(systemName: "lock.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(Radix.blue.a[11])
            Text("Secure — drawn by the Jarvis 2 shell, signed with \(PhoneKeys.shared.how)")
              .font(.system(size: K.fontSize[1], weight: .medium)).foregroundStyle(Radix.blue.a[11])
          }
          .padding(.horizontal, 8).padding(.vertical, 6)
          .background(RoundedRectangle(cornerRadius: K.radius[2]).fill(Radix.blue.a[3]))
          .padding(.top, 12)
          .accessibilityIdentifier("secure-banner")
          content()
          Spacer(minLength: 48)
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: 720)
        .frame(maxWidth: .infinity)
      }
    }
    .background(Radix.background.ignoresSafeArea())
  }
}

let HARNESSES: [(id: String, title: String, sub: String)] = [("claude", "Claude Code", "Claude subscription · Claude app"), ("opencode", "OpenCode · OpenRouter", "Paseo app + web UI"), ("openclaw", "claw-code · OpenClaw", "Claude subscription · OpenClaw app + Control UI")]
func harnessName(_ h: String) -> String {
  if h.hasPrefix("task:") { return "Task script “\(h.dropFirst(5))” (runs the template, no agent)" }
  return HARNESSES.first { $0.id == h }?.title ?? h
}
func errText(_ e: Error) -> String { (e as? LocalizedError)?.errorDescription ?? e.localizedDescription }
/// key use waits for Face ID: keep it off the main thread
func offMain<T: Sendable>(_ fn: @escaping @Sendable () throws -> T) async throws -> T { try await Task.detached(priority: .userInitiated) { try fn() }.value }

/// the stores a challenge carries, sensitive ones marked
struct StoreLines: View {
  let stores: [String]
  let sensitive: [String]
  var harness: [String] = []
  var body: some View {
    VStack(spacing: 8) {
      if stores.isEmpty { Muted(text: "No stores.") }
      ForEach(stores, id: \.self) { s in
        HStack(spacing: 6) {
          Text(s).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
          if sensitive.contains(s) { Badge(text: "Sensitive", color: .red) }
          if harness.contains(s) { Badge(text: "Harness") }
          Spacer()
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.surface))
        .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).strokeBorder(Radix.gray.a[6], lineWidth: 1))
        .accessibilityIdentifier("store-line-\(s)")
      }
    }
  }
}

// ---- New session: the stores, the harness, then Create (one Face ID) ----------------------------------
struct SecureNewSession: View {
  let shell: Shell
  let options: [String: Any]
  @State private var stores: [StoreView] = []
  @State private var harnessStores: [String: [String]] = [:]
  @State private var picked: Set<String> = []
  @State private var harness = "claude"
  @State private var mode = "auto"
  @State private var loaded = false
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String { (options["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "New session" }
  /// the stores any harness brings: the router adds them, the picker doesn't offer them
  private var hidden: Set<String> { Set(harnessStores.values.flatMap { $0 }) }
  private var offered: [StoreView] { stores.filter { !$0.isCore && !hidden.contains($0.name) } }
  private var pickedSensitive: [String] { stores.filter { $0.sensitive && picked.contains($0.name) }.map(\.name) }

  var body: some View {
    SecureFrame(shell: shell, title: "New session", action: ("Create", "secure-create", !loaded), busy: busy, run: { Task { await create() } }) {
      Lbl(text: "Session")
      Muted(text: title)
      Lbl(text: "Secret stores")
      if let loadError { Callout(text: loadError, color: .red) }
      else if !loaded { ProgressView().frame(maxWidth: .infinity) }
      else if offered.isEmpty { Muted(text: "No stores to add.") }
      VStack(spacing: 8) {
        ForEach(offered) { s in
          ChoiceCard(on: picked.contains(s.name), check: true, id: "secure-store-\(s.name)", action: { toggle(s.name) }) {
            HStack(spacing: 6) {
              Text(s.name).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              if !s.unlocked { Badge(text: "Locked") }
            }
            if s.empty { Text("empty").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11]) }
          }
        }
      }
      if !pickedSensitive.isEmpty {
        Callout(text: "This session will hold sensitive secrets: \(pickedSensitive.joined(separator: ", ")). Only pick them for a session you'll treat with care.", amber: true)
          .padding(.top, 12).accessibilityIdentifier("secure-sensitive-warning")
      }
      Lbl(text: "Harness")
      VStack(spacing: 8) {
        ForEach(HARNESSES, id: \.id) { h in
          ChoiceCard(on: harness == h.id, id: "secure-harness-\(h.id)", action: { harness = h.id }) { ChoiceText(title: h.title, sub: h.sub) }
        }
      }
      if let hs = harnessStores[harness], !hs.isEmpty { Muted(text: "The harness brings its own: \(hs.joined(separator: ", ")).").padding(.top, 8) }
      Lbl(text: "Permission mode")
      VStack(spacing: 8) {
        ChoiceCard(on: mode == "auto", id: "secure-mode-auto", action: { mode = "auto" }) { ChoiceText(title: "Auto", sub: "Safe actions run; the permission classifier gates the rest") }
        ChoiceCard(on: mode == "bypass", id: "secure-mode-bypass", action: { mode = "bypass" }) { ChoiceText(title: "Bypass", sub: "No permission prompts at all (--dangerously-skip-permissions)") }
      }
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
    }
    .task { await load() }
  }

  private func toggle(_ n: String) { if picked.contains(n) { picked.remove(n) } else { picked.insert(n) } }
  private func apply(_ list: [StoreView]) {
    stores = list
    // pre-selection from normal mode: offered, NON-sensitive stores only
    let pre = (options["stores"] as? [String]) ?? []
    if picked.isEmpty { picked = Set(pre.filter { n in offered.contains { $0.name == n && !$0.sensitive } }) }
    else { picked = picked.intersection(offered.map(\.name)) }
  }
  private func load() async {
    if let h = options["harness"] as? String, HARNESSES.contains(where: { $0.id == h }) { harness = h }
    if (options["permissionMode"] as? String) == "bypass" { mode = "bypass" }
    harnessStores = await RouterClient.shared.harnessStores()
    if let p = shell.prefetched { apply(p); loaded = true }
    do { let p = try await RouterClient.shared.stores(); shell.prefetched = p; apply(p); loaded = true }
    catch { if !loaded { loadError = errText(error) } }
  }

  private func create() async {
    failure = nil
    let want = picked.sorted(), rid = (options["requestId"] as? String) ?? CoreCrypto.nonce()
    do {
      let key = try CoreTrust.key()
      busy = "Requesting…"
      var body: [String: Any] = ["requestId": rid, "stores": want, "harness": harness, "permissionMode": mode]
      for k in ["label", "prompt", "model", "size", "oneShot", "autoPause", "repos", "apiProxy"] { if let v = options[k] { body[k] = v } }
      try await RouterClient.shared.createSession(body)
      // the core's challenge comes before any machine exists
      var found: RouterClient.ApprovalDTO?
      let until = Date().addingTimeInterval(60)
      while found == nil && Date() < until {
        let st = try await RouterClient.shared.state()
        if let s = st.sessions.first(where: { $0.createRequestId == rid }) {
          if s.state == "failed" { throw RouterError(message: "The router couldn't make the request.") }
          found = st.approvals.first { $0.session == s.id && $0.kind == "new-session" }
        }
        if found == nil { try await Task.sleep(nanoseconds: 700_000_000) }
      }
      guard let a = found else { throw RouterError(message: "No approval yet — it will wait at the top of the session list.") }
      let r = try Checks.review(challenge: a.challenge, coreKey: key)
      try Checks.matchesPicked(r, stores: want, harnessStores: harnessStores[harness] ?? [], harness: harness, permissionMode: mode)  // sign only what was chosen here
      busy = "Signing…"
      let payload = a.challenge.payload, reason = "Create \"\(title)\""
      let sig = try await offMain { try PhoneKeys.shared.sign(payload, reason: reason) }
      busy = "Creating…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.answerFor(r, answer: ans.answer, coreKey: key)
      shell.log("created \(ans.session)")
      busy = nil
      shell.exitSecure("created \(ans.session)", done: true, id: ans.session)
    } catch {
      busy = nil
      failure = errText(error)
    }
  }
}

// ---- an approval (new session from the web, resume on the latest image, add a store) -------------------
struct SecureApproval: View {
  let shell: Shell
  let approvalId: String
  @State private var a: RouterClient.ApprovalDTO?
  @State private var r: Checks.Reviewed?
  @State private var harnessStores: [String] = []
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String {
    switch r?.kind { case .resumeUpgrade: return "Approve resume"; case .addStore: return "Add a store"; case .newSession: return "Approve new session"; default: return "Approve" }
  }
  var body: some View {
    SecureFrame(shell: shell, title: title, action: ("Approve", "secure-approve", r == nil), busy: busy, run: { Task { await approve() } }) {
      if let loadError { Callout(text: loadError, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      else if let r, let a {
        Lbl(text: "Session")
        Muted(text: (a.label ?? "").isEmpty ? (a.session ?? "") : a.label!)
        switch r.kind {
        case .addStore:
          Muted(text: "The running machine asks for one more store; it keeps its keys.").padding(.top, 8)
          Lbl(text: "Add this store")
          StoreLines(stores: [r.addedStore ?? ""], sensitive: r.sensitive)
          Lbl(text: "It already has")
          StoreLines(stores: r.stores.filter { $0 != r.addedStore }, sensitive: r.sensitive, harness: harnessStores)
        case .resumeUpgrade:
          Muted(text: "The paused session continues on a new machine running the image and in the permission mode below, with the same stores and harness. Nothing happens until you approve; Reject leaves it paused.").padding(.top, 8)
          Lbl(text: "Secret stores"); StoreLines(stores: r.stores, sensitive: r.sensitive, harness: harnessStores)
        case .newSession:
          if let rs = a.options?["restore"], !rs.isEmpty {
            Muted(text: "Restores the archived session \(rs): its first machine restores that snapshot (the router's word — not part of what you sign).").padding(.top, 8).accessibilityIdentifier("secure-restore")
          } else {
            Muted(text: "Requested outside this app (the web page or another device): check it is yours.").padding(.top, 8)
          }
          if a.options?["oneShot"] == "1" { Muted(text: "One-shot: it runs its prompt, then is archived and destroyed.").padding(.top, 4) }
          Lbl(text: "Secret stores"); StoreLines(stores: r.stores, sensitive: r.sensitive, harness: harnessStores)
        case .other:
          Muted(text: "A request this page has no special view for — what you sign is below.").padding(.top, 8)
          Lbl(text: "Secret stores"); StoreLines(stores: r.stores, sensitive: r.sensitive, harness: harnessStores)
          Lbl(text: "The challenge"); Text(r.challenge.request.kind).font(.system(size: K.fontSize[1], design: .monospaced))
        }
        let warn = r.kind == .addStore ? r.sensitive.filter { $0 == r.addedStore } : r.sensitive
        if !warn.isEmpty {
          Callout(text: "This session will hold sensitive secrets: \(warn.joined(separator: ", ")).", amber: true).padding(.top, 12).accessibilityIdentifier("secure-sensitive-warning")
        }
        Lbl(text: "Harness"); Muted(text: harnessName(r.harness))
        if r.kind != .addStore {
          Lbl(text: "Permission mode")
          if r.permissionMode == "bypass" {
            Callout(text: "Permission mode: bypass — no permission prompts at all", amber: true).accessibilityIdentifier("secure-mode")
          } else {
            Muted(text: "Permission mode: auto").accessibilityIdentifier("secure-mode")
          }
        }
        Lbl(text: "Session image"); Muted(text: r.image).textSelection(.enabled)
        HStack { KitButton(title: "Reject", variant: .soft, color: .red, disabled: busy != nil, id: "secure-reject") { Task { await reject() } }; Spacer() }.padding(.top, 20)
        if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      } else { ProgressView().frame(maxWidth: .infinity).padding(.top, 24) }
    }
    .task { await load() }
  }
  private func load() async {
    do {
      guard let x = try await RouterClient.shared.approval(approvalId) else { loadError = "This approval is gone (answered or rejected elsewhere)."; return }
      let rv = try Checks.review(challenge: x.challenge, coreKey: try CoreTrust.key())
      harnessStores = (await RouterClient.shared.harnessStores())[rv.harness] ?? []
      r = rv; a = x
    } catch { loadError = errText(error) }
  }
  private func approve() async {
    guard let a, let r else { return }
    failure = nil
    do {
      busy = "Signing…"
      let payload = a.challenge.payload, reason = title
      let sig = try await offMain { try PhoneKeys.shared.sign(payload, reason: reason) }
      busy = "Approving…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.answerFor(r, answer: ans.answer, coreKey: try CoreTrust.key())
      busy = nil
      shell.exitSecure("approved \(a.id)", done: true, id: ans.session)
    } catch { busy = nil; failure = errText(error) }
  }
  private func reject() async {
    guard let a else { return }
    do { busy = "Rejecting…"; try await RouterClient.shared.reject(a.id); busy = nil; shell.exitSecure("rejected \(a.id)", done: true, id: a.session) }
    catch { busy = nil; failure = errText(error) }
  }
}

// ---- stores: unlock (Face ID, split key), lock, mark sensitive; the core's signed unlocked list ---------
struct SecureStores: View {
  let shell: Shell
  @State private var stores: [StoreView] = []
  @State private var open: [UnlockRow] = []
  @State private var loaded = false
  @State private var busy: String?
  @State private var failure: String?
  @State private var confirmMark: String?
  @State private var newName = ""

  var body: some View {
    SecureFrame(shell: shell, title: "Stores", busy: busy) {
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      Lbl(text: "Stores")
      if !loaded && failure == nil { ProgressView().frame(maxWidth: .infinity) }
      VStack(spacing: 8) {
        ForEach(stores) { s in
          VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
              Text(s.name).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              Badge(text: s.unlocked ? "Unlocked" : "Locked", color: s.unlocked ? .blue : .gray)
              Spacer()
            }
            if s.empty { Text("empty — written by the setup session").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11]) }
            if confirmMark == s.name {
              Callout(text: "Mark \(s.name) sensitive? The mark can never be removed.", amber: true)
              HStack(spacing: 8) {
                KitButton(title: "Cancel", variant: .soft, color: .gray, id: "mark-cancel-\(s.name)") { confirmMark = nil }
                KitButton(title: "Mark sensitive", color: .red, id: "mark-confirm-\(s.name)") { Task { await mark(s.name) } }
              }
            } else {
              HStack(spacing: 8) {
                KitButton(title: s.unlocked ? "Unlock again" : "Unlock", variant: s.unlocked ? .soft : .solid, disabled: busy != nil || s.empty, id: "unlock-\(s.name)") { Task { await unlock(s.name) } }
                if !s.sensitive { KitButton(title: "Mark sensitive…", variant: .soft, color: .gray, disabled: busy != nil, id: "mark-\(s.name)") { confirmMark = s.name } }
              }
            }
          }
          .padding(12)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.surface))
          .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).strokeBorder(Radix.gray.a[6], lineWidth: 1))
        }
      }
      Lbl(text: "New store")
      Muted(text: "An empty store that is NOT sensitive (you can mark it later; never back). The setup session writes its values.")
      HStack(spacing: 8) {
        TextField("name (a–z, 0–9, -)", text: $newName)
          .font(.system(size: K.fontSize[2])).textInputAutocapitalization(.never).autocorrectionDisabled()
          .padding(.horizontal, 10).frame(height: 32).background(RoundedRectangle(cornerRadius: K.radius[2]).strokeBorder(Radix.gray.a[7], lineWidth: 1))
          .accessibilityIdentifier("store-new-name")
        KitButton(title: "Create", variant: .soft, disabled: busy != nil || newName.isEmpty, id: "store-create") { Task { await create() } }
      }
      Lbl(text: "Open unlocks")
      Muted(text: "Every unlock the core holds open, signed by the core with this page's nonce: genuine, complete and fresh. A store's secrets leave the core's memory when its last unlock is locked.")
      VStack(spacing: 8) {
        if loaded && open.isEmpty { Muted(text: "None — every store is locked.").accessibilityIdentifier("unlocks-none") }
        ForEach(open) { u in
          HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
              Text(u.store).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
              Text("since \(SecureStores.date(u.since)) · \(u.id.prefix(8))").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11])
            }
            Spacer()
            KitButton(title: "Lock", variant: .soft, color: .red, disabled: busy != nil, id: "lock-\(u.store)") { Task { await lock(u.id) } }
          }
          .padding(12)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.surface))
          .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).strokeBorder(Radix.gray.a[6], lineWidth: 1))
        }
      }.padding(.top, 8)
    }
    .task { await reload() }
  }
  private func reload() async {
    do { stores = try await RouterClient.shared.stores(); open = try await RouterClient.shared.unlocked(); shell.prefetched = stores; loaded = true }
    catch { failure = errText(error) }
  }
  private func run(_ label: String, _ fn: () async throws -> Void) async {
    failure = nil; busy = label
    do { try await fn() } catch { failure = errText(error) }
    busy = nil
    await reload()
  }
  private func unlock(_ name: String) async {
    await run("Unlocking…") {
      let b = try await RouterClient.shared.unlockBegin(name)
      let e = b.e
      let x = try await offMain { try PhoneKeys.shared.share(with: e, reason: "Unlock \(name)") }
      try await RouterClient.shared.unlockFinish(b, share: try CoreCrypto.sealShare(x, to: b.t))
    }
  }
  private func create() async {
    let n = newName.trimmingCharacters(in: .whitespaces).lowercased()
    await run("Creating…") { try await RouterClient.shared.createStore(n); newName = "" }
  }
  private func lock(_ id: String) async { await run("Locking…") { try await RouterClient.shared.lock(id) } }
  private func mark(_ name: String) async { confirmMark = nil; await run("Marking…") { try await RouterClient.shared.markSensitive(name) } }
  static func date(_ iso: String) -> String {
    guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
    return d.formatted(date: .abbreviated, time: .shortened)
  }
}

// ---- recovery: the core's identity (8 words), then the recovery kit → every store into the new core --------
/// a pasted secret's field: monospaced, no autocorrect, hidden from screenshots
func secretField(_ ph: String, _ text: Binding<String>, _ id: String, onChange: @escaping (String) -> Void) -> some View {
  TextField(ph, text: text, axis: .vertical)
    .font(.system(size: K.fontSize[1], design: .monospaced)).textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
    .padding(10).background(RoundedRectangle(cornerRadius: K.radius[2]).strokeBorder(Radix.gray.a[7], lineWidth: 1))
    .padding(.top, 8).accessibilityIdentifier(id)
    .onChange(of: text.wrappedValue) { _, v in onChange(v) }
}

struct RecoveryPage: View {
  let shell: Shell
  @State private var id: PublicKeys?
  @State private var words = ""
  @State private var idError: String?
  @State private var notRunning = false // no core yet (first setup): a plain note, not an error
  @State private var kit = ""
  @State private var busy: String?
  @State private var failure: String?
  @State private var note: String?
  /// keys/master.pub, to say whether this iPhone holds its private half
  @State private var repoPub: String?
  @State private var wipe: Task<Void, Never>?

  private var already: Bool { id != nil && id == CoreTrust.pinned }
  var body: some View {
    SecureFrame(shell: shell, title: "Recovery", action: id == nil || already ? nil : ("Recover", "recovery-go", kit.isEmpty), busy: busy,
                run: { Task { await recover() } }, backTitle: CoreTrust.pinned == nil ? "Later" : "← Back") {
      Lbl(text: "The core")
      if notRunning {
        Muted(text: "The core isn't set up yet. First time: make a master key pair below.").accessibilityIdentifier("recovery-core-not-running")
        HStack { KitButton(title: "Make a master key pair…", disabled: busy != nil, id: "recovery-make-master-first") { clear(); shell.route = .masterKey }; Spacer() }.padding(.top, 12)
        Muted(text: "Once its public half is in the repo the core starts, and this page shows its 8 words.").padding(.top, 8)
        HStack { KitButton(title: "Check again", variant: .soft, color: .gray, disabled: busy != nil, id: "recovery-retry") { Task { await load() } }; Spacer() }.padding(.top, 8)
      }
      else if let idError { Callout(text: idError, color: .red).accessibilityIdentifier("recovery-identity-error") }
      else if id == nil { ProgressView().frame(maxWidth: .infinity) }
      else {
        Muted(text: "Check these words against the ones the box logged for this core. Its keys are vouched for by the box key (keys/box.pub, from GitHub\(KeySource.isCI ? " — CI stand-in" : "")).")
        Text(words).font(.system(size: K.fontSize[4], weight: .semibold, design: .monospaced)).foregroundStyle(Radix.gray.s[12])
          .padding(12).frame(maxWidth: .infinity, alignment: .leading)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
          .padding(.top, 8).accessibilityIdentifier("recovery-words").accessibilityLabel(words)
        if already {
          Callout(text: "This iPhone already trusts this core.", color: .blue).padding(.top, 12).accessibilityIdentifier("recovery-done")
        } else {
          Lbl(text: "Recovery kit")
          Muted(text: "From your password manager: jarvis2-kit:1:…")
          secretField("jarvis2-kit:1:…", $kit, "recovery-kit") { v in if !v.isEmpty { armWipe() } }
          Muted(text: "It stays in this page's memory only, for at most 10 minutes. The app checks its master key against keys/master.pub, reads every store's backup with its bucket keys, checks each was written by the setup key, decrypts them with the master key, and hands the stores to this core sealed to its key, with the master key's signature naming the core and this iPhone.").padding(.top, 8)
        }
      }
      if let note { Callout(text: note).padding(.top, 12) }
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      if !notRunning {
        Lbl(text: "No recovery kit yet")
        Muted(text: "It is made on the iPhone that made the master key pair (it holds the private half, never shown), with the backup bucket's read keys the setup session sealed to that key.")
        if let repoPub {
          if let h = HeldMaster.publicKey, MasterKey.same(h, repoPub) {
            Callout(text: "This iPhone holds the master private key for keys/master.pub: make the recovery kit.", color: .blue).padding(.top, 8).accessibilityIdentifier("recovery-holds-master")
          } else {
            Callout(text: "This iPhone holds no master private key for keys/master.pub. Without a recovery kit for that key, make a new master key pair and send Claude the public key.", amber: true).padding(.top, 8).accessibilityIdentifier("recovery-no-master")
          }
        }
        HStack { KitButton(title: "Make the recovery kit…", variant: .soft, disabled: busy != nil, id: "recovery-make-kit") { clear(); shell.kitReturnsToRecovery = true; shell.route = .recoveryKit }; Spacer() }.padding(.top, 8)
        Lbl(text: "A new master key")
        HStack { KitButton(title: "Make a master key pair…", variant: .soft, color: .gray, disabled: busy != nil, id: "recovery-make-master") { clear(); shell.route = .masterKey }; Spacer() }
      }
    }
    .task { await load() }
    .onDisappear { clear() }
  }
  private func clear() { kit = ""; wipe?.cancel(); wipe = nil }
  /// the kit is forgotten 10 minutes after it was pasted
  private func armWipe() {
    guard wipe == nil else { return }
    wipe = Task { @MainActor in
      try? await Task.sleep(nanoseconds: 600_000_000_000)
      guard !Task.isCancelled else { return }
      kit = ""; wipe = nil
      note = "The pasted kit was wiped after 10 minutes. Paste it again to recover."
    }
  }
  private func load() async {
    idError = nil
    repoPub = try? await KeySource.key("master.pub")
    do {
      let x = try await RouterClient.shared.identity()
      notRunning = false
      let k = PublicKeys(signingKey: x.signingKey, agreementKey: x.agreementKey)
      let box = try await KeySource.key("box.pub")
      guard CoreCrypto.identityVouched(k, boxSig: x.boxSig, boxKey: box) else {
        idError = "The core's identity is NOT signed by the box key in git (keys/box.pub). Don't recover this core."; return
      }
      words = CoreCrypto.identityWords(k, words: KeySource.words)
      id = k
    } catch is RouterClient.CoreNotRunning { notRunning = true }
    catch { notRunning = false; idError = "Couldn't read the core's identity: " + errText(error) }
  }
  private func recover() async {
    guard let core = id else { return }
    failure = nil; note = nil
    do {
      let k = try RecoveryKit.parse(kit)
      busy = "Checking the kit…"
      let masterPub = try await KeySource.key("master.pub")
      guard k.master.matches(masterPub) else {
        throw TrustError.badKit("This kit's master key isn't the one in the repo (keys/master.pub): the backups are sealed to that one.")
      }
      busy = "Reading the backups…"
      let setupKey = try await KeySource.key("setup.pub")
      let stores = try await Recovery.readBackups(S3Reader(bucket: KeySource.bucket, creds: k.bucket), master: k.master, setupKey: setupKey) { s in Task { @MainActor in busy = s } }
      let bundle = try Recovery.bundle(stores)
      busy = "Signing…"
      let phone = try PhoneKeys.shared.publicKeys()
      let body = try Recovery.request(core: core, phone: phone, master: k.master, bundle: bundle)
      busy = "Recovering the core…"
      let n = try await RouterClient.shared.recover(body, core: core)
      CoreTrust.pin(core)
      clear()
      shell.prefetched = nil
      shell.log("recovered: \(n) stores")
      busy = nil
      shell.exitSecure("recovered", done: true)
    } catch { busy = nil; failure = errText(error) }
  }
}

// ---- the recovery kit: the master key held on this iPhone + the backup bucket's read keys → the ONE string ----
/// The read keys come from the setup session through the router, sealed to the master public key and signed by
/// the setup key: the page checks the signature against keys/setup.pub (from GitHub, like box.pub), opens them
/// with the master private key this iPhone has held since it made the pair (HeldMaster, Face ID), checks they
/// read the bucket, and shows the kit. Once Deyao says the kit is saved, the held key is deleted and the kit is
/// its only copy. The kit itself is never stored: leaving the page forgets it.
struct RecoveryKitPage: View {
  let shell: Shell
  @State private var heldPub: String? = HeldMaster.publicKey
  @State private var repoPub: String?
  @State private var busy: String?
  @State private var failure: String?
  @State private var missing = false
  @State private var kit: String?
  @State private var about = ""
  @State private var copied = false
  @State private var deleted = false
  @State private var wipe: Task<Void, Never>?

  /// does this iPhone hold the private half of keys/master.pub? nil until keys/master.pub is fetched
  private var holds: Bool? { repoPub.map { r in heldPub.map { MasterKey.same($0, r) } ?? false } }

  var body: some View {
    SecureFrame(shell: shell, title: "Recovery kit", action: kit != nil || holds != true ? nil : (missing ? "Check again" : "Make kit", "kit-make", false),
                busy: busy, run: { Task { await make() } }, backTitle: kit != nil ? "Done" : "← Back",
                onBack: shell.kitReturnsToRecovery ? { forget(); shell.kitReturnsToRecovery = false; shell.route = .recovery } : nil) {
      if let kit {
        if deleted {
          Callout(text: "The master private key is deleted from this iPhone. The recovery kit in your password manager is now its only copy.", color: .blue).padding(.top, 12).accessibilityIdentifier("kit-key-deleted")
        } else {
          Lbl(text: "Your recovery kit — the password manager")
          Muted(text: "Save this one string in your password manager as the Jarvis 2 recovery kit. It holds the master private key and the backup bucket's read keys\(about); recovery needs only it. It is never stored: leaving this page forgets it. The copy expires from the clipboard after 2 minutes and doesn't go to your other devices.")
          Text(kit).font(.system(size: K.fontSize[1], design: .monospaced)).foregroundStyle(Radix.gray.s[12]).textSelection(.enabled).privacySensitive()
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
            .padding(.top, 8).accessibilityIdentifier("kit-string").accessibilityLabel(kit)
          HStack { KitButton(title: copied ? "Copied" : "Copy recovery kit", id: "kit-copy") { copy(kit) }; Spacer() }.padding(.top, 8)
          Lbl(text: "Saved it?")
          Muted(text: "Then delete the master key from this iPhone: from then on the kit is its only copy. Until you do, it stays here behind Face ID, so the kit can be made again.")
          HStack { KitButton(title: "I've saved the kit — delete the key here", color: .red, id: "kit-saved") { HeldMaster.delete(); heldPub = nil; deleted = true; shell.log("held master key deleted") }; Spacer() }.padding(.top, 8)
        }
      } else {
        Lbl(text: "Master key")
        if let holds {
          if holds {
            Callout(text: "This iPhone holds the master private key for keys/master.pub (made here, never shown). Making the kit asks for Face ID.", color: .blue).padding(.top, 8).accessibilityIdentifier("kit-held-master")
          } else {
            Callout(text: heldPub == nil ? "This iPhone holds no master private key." : "The master key this iPhone holds isn't the one in keys/master.pub.", amber: true).padding(.top, 8).accessibilityIdentifier("kit-no-master")
            Muted(text: "Make a new master key pair and send Claude the public key. Once Claude has put it in keys/master.pub and sealed the backup bucket's read keys to it, come back here.").padding(.top, 8)
            HStack { KitButton(title: "Make a master key pair…", variant: .soft, disabled: busy != nil, id: "kit-make-master") { forget(); shell.route = .masterKey }; Spacer() }.padding(.top, 8)
          }
        } else if failure == nil { ProgressView().frame(maxWidth: .infinity).padding(.top, 8) }
        Muted(text: "The backup bucket's read keys come from the setup session through the router, sealed to the master key: the app checks they were signed by the setup key (keys/setup.pub, from GitHub\(KeySource.isCI ? " — CI stand-in" : "")), opens them with the master key and tries them on the bucket. The router can't read them.").padding(.top, 8)
        if missing {
          Callout(text: "The setup session hasn't sent the read keys yet (infra/setup.py recovery-keys). Check again once it has.").padding(.top, 12).accessibilityIdentifier("kit-missing")
        }
      }
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
    }
    .task { await loadRepo() }
    .onDisappear { forget() }
  }
  private func forget() { kit = nil; wipe?.cancel(); wipe = nil }
  private func loadRepo() async {
    do { repoPub = try await KeySource.key("master.pub") } catch { failure = errText(error) }
  }
  /// the kit is forgotten 10 minutes after it was made (the held key isn't)
  private func armWipe() {
    guard wipe == nil else { return }
    wipe = Task { @MainActor in
      try? await Task.sleep(nanoseconds: 600_000_000_000)
      guard !Task.isCancelled else { return }
      kit = nil; wipe = nil
      if !deleted { failure = "The kit was wiped from this page after 10 minutes. Make it again to copy it." }
    }
  }
  private func make() async {
    failure = nil
    do {
      busy = "Checking the master key…"
      let masterPub = try await KeySource.key("master.pub")
      repoPub = masterPub
      let raw = try await offMain { try HeldMaster.load(reason: "Make the Jarvis 2 recovery kit")?.signing.rawRepresentation }
      heldPub = HeldMaster.publicKey
      guard let raw, let k = try? P256.Signing.PrivateKey(rawRepresentation: raw) else { busy = nil; heldPub = nil; return }
      let m = MasterKey(signing: k)
      guard m.matches(masterPub) else { busy = nil; return }
      busy = "Fetching the read keys…"
      guard let sealed = try await RouterClient.shared.recoveryKeys() else { busy = nil; missing = true; return }
      missing = false
      let setupKey = try await KeySource.key("setup.pub")
      let (creds, doc) = try Recovery.openKeys(sealed, setupKey: setupKey, master: m)
      busy = "Trying them on the bucket…"
      let n = try await S3Reader(bucket: KeySource.bucket, creds: creds).list(prefix: "stores/").count
      var parts: [String] = []
      if let c = doc.credential, !c.isEmpty { parts.append("credential \(c)") }
      if let at = doc.at { parts.append("sealed " + Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)) }
      parts.append("\(n) store backup\(n == 1 ? "" : "s") readable")
      about = " (" + parts.joined(separator: ", ") + ")"
      kit = RecoveryKit(master: m, bucket: creds).string
      armWipe()
      busy = nil
    } catch { busy = nil; failure = errText(error) }
  }
  private func copy(_ s: String) {
    UIPasteboard.general.setItems([["public.utf8-plain-text": s]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)])
    copied = true
  }
}

// ---- the master key pair: made on this iPhone, only its public half shown ----------------------------------
/// The private half goes straight into the shell's Keychain (HeldMaster) and is never shown: Deyao sends the
/// public half to Claude, who puts it in keys/master.pub and seals the backup bucket's read keys to it; then the
/// Recovery kit page makes the ONE string from the held key and deletes it.
struct MasterKeyPage: View {
  let shell: Shell
  @State private var heldPub: String? = HeldMaster.publicKey
  @State private var repoPub: String?
  @State private var confirmNew = false
  @State private var copied = false
  @State private var failure: String?
  private var inRepo: Bool { guard let h = heldPub, let r = repoPub else { return false }; return MasterKey.same(h, r) }
  var body: some View {
    SecureFrame(shell: shell, title: "Master key", backTitle: "Done") {
      Callout(text: "A new master key pair is the root of a new setup: the core, the machines and the backups trust only the key in keys/master.pub, so a new one means a new core, backups sealed again and a new recovery kit.", amber: true).padding(.top, 12)
      if let k = heldPub {
        Lbl(text: "Public key — send it to Claude")
        Muted(text: inRepo
          ? "It is keys/master.pub in the repo. Once Claude has sealed the backup bucket's read keys to it, make the recovery kit."
          : "Send it to Claude: it becomes keys/master.pub in the repo (the core, the machines and the setup session trust it). The private half stays in this iPhone's Keychain (this device only, Face ID) and is never shown; it goes into the recovery kit.")
          .accessibilityIdentifier(inRepo ? "master-in-repo" : "master-not-in-repo")
        Text(k).font(.system(size: K.fontSize[1], design: .monospaced)).foregroundStyle(Radix.gray.s[12]).textSelection(.enabled)
          .padding(12).frame(maxWidth: .infinity, alignment: .leading)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
          .padding(.top, 8).accessibilityIdentifier("master-public").accessibilityLabel(k)
        HStack { KitButton(title: copied ? "Copied" : "Copy public key", variant: .soft, id: "master-copy-public") { copy(k) }; Spacer() }.padding(.top, 8)
        Lbl(text: "Then — the recovery kit")
        HStack { KitButton(title: "Make the recovery kit…", variant: .soft, id: "master-make-kit") { shell.route = .recoveryKit }; Spacer() }.padding(.top, 8)
        Lbl(text: "A different pair")
        if confirmNew {
          Muted(text: "This deletes the private key held here. Only do it if this public key isn't in keys/master.pub, or you mean to replace that key too.")
          HStack(spacing: 8) {
            KitButton(title: "Cancel", variant: .soft, color: .gray, id: "master-new-cancel") { confirmNew = false }
            KitButton(title: "Make a new pair", color: .red, id: "master-new-confirm") { make() }
            Spacer()
          }.padding(.top, 8)
        } else {
          HStack { KitButton(title: "Make a new pair instead…", variant: .soft, color: .gray, id: "master-new") { confirmNew = true }; Spacer() }
        }
      } else {
        Lbl(text: "No master key on this iPhone")
        Muted(text: "Make a pair here. Only the public half is shown, for you to send to Claude; the private half stays in this iPhone's Keychain (this device only, Face ID) until it goes into your recovery kit.")
        HStack { KitButton(title: "Make a master key pair", id: "master-make") { make() }; Spacer() }.padding(.top, 8)
      }
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
    }
    .task { repoPub = try? await KeySource.key("master.pub") }
  }
  private func make() {
    failure = nil; confirmNew = false; copied = false
    do { let k = MasterKey.generate(); try HeldMaster.hold(k); heldPub = k.publicKey; shell.log("master key pair made; private half held") }
    catch { failure = errText(error) }
  }
  private func copy(_ s: String) {
    UIPasteboard.general.setItems([["public.utf8-plain-text": s]], options: [.localOnly: true])
    copied = true
  }
}
