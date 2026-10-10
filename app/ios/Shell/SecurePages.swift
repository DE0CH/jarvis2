// The shell's secure pages: drawn only by the shell (the React Native UI's view is gone while one is up).
// What they show comes from the core's signed answers (checked against the core keys pinned at setup); what the
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
      // page.tsx TopBar: ← Back (soft gray) · Heading size 4 · the primary action; 20 / 16 padding, a hairline below
      HStack(spacing: 12) {
        KitButton(title: backTitle, variant: .soft, color: .gray, disabled: busy != nil, id: "secure-back") { if let onBack { onBack() } else { shell.exitSecure("back") } }
        Text(title).kitHeading(4).foregroundStyle(Radix.gray.s[12]).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
        if let a = action { KitButton(title: busy ?? a.title, disabled: a.disabled, busy: busy != nil, id: a.id, action: run) }
      }
      .padding(.horizontal, 20).padding(.vertical, 16)
      .frame(maxWidth: K.pageMax).frame(maxWidth: .infinity)
      .background(Radix.background)
      .overlay(alignment: .bottom) { Rectangle().fill(Radix.gray.a[5]).frame(height: 1) }
      ScrollView {
        // page.tsx's body: 720 wide, 16 at the sides, 8 on top, 48 below
        VStack(alignment: .leading, spacing: 0) {
          HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: "lock.fill").font(.system(size: 10, weight: .semibold)).foregroundStyle(Radix.blue.a[11])
            Text("Secure — drawn by the Jarvis 2 shell, signed with \(PhoneKeys.shared.how)")
              .kitText(1, weight: .medium).foregroundStyle(Radix.blue.a[11])
          }
          .padding(.horizontal, 8).padding(.vertical, 4)
          .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(Radix.blue.a[3]))
          .padding(.top, 8)
          .accessibilityIdentifier("secure-banner")
          content()
          Spacer(minLength: 48)
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: K.pageMax)
        .frame(maxWidth: .infinity)
      }
    }
    .background(Radix.background.ignoresSafeArea())
    // one layer: a shadow the shell puts on the whole page (the push motion) must not land on every text run
    .compositingGroup()
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
        KitCard(size: 1) {
          HStack(spacing: 6) {
            Text(s).kitText(2, weight: .medium).foregroundStyle(Radix.gray.s[12])
            if sensitive.contains(s) { Badge(text: "Sensitive", color: .red) }
            if harness.contains(s) { Badge(text: "Harness") }
            Spacer()
          }
        }
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
              Text(s.name).kitText(2, weight: .medium).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              if !s.unlocked { Badge(text: "Locked") }
            }
            if s.empty { Text("empty").kitText(1).foregroundStyle(Radix.gray.a[11]) }
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
          Lbl(text: "The challenge"); Text(r.challenge.request.kind).kitText(1, mono: true).foregroundStyle(Radix.gray.s[12])
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
          KitCard(size: 1) { VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
              Text(s.name).kitText(2, weight: .medium).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              Badge(text: s.unlocked ? "Unlocked" : "Locked", color: s.unlocked ? .blue : .gray)
              Spacer()
            }
            if s.empty { Text("empty — written by the setup session").kitText(1).foregroundStyle(Radix.gray.a[11]) }
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
          } }
        }
      }
      Lbl(text: "New store")
      Muted(text: "An empty store that is NOT sensitive (you can mark it later; never back). The setup session writes its values.")
      HStack(spacing: 8) {
        KitTextField(placeholder: "name (a–z, 0–9, -)", text: $newName, id: "store-new-name")
        KitButton(title: "Create", variant: .soft, disabled: busy != nil || newName.isEmpty, id: "store-create") { Task { await create() } }
      }.padding(.top, 8)
      Lbl(text: "Open unlocks")
      Muted(text: "Every unlock the core holds open, signed by the core with this page's nonce: genuine, complete and fresh. A store's secrets leave the core's memory when its last unlock is locked.")
      VStack(spacing: 8) {
        if loaded && open.isEmpty { Muted(text: "None — every store is locked.").accessibilityIdentifier("unlocks-none") }
        ForEach(open) { u in
          KitCard(size: 1) { HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 0) {
              Text(u.store).kitText(2, weight: .medium).foregroundStyle(Radix.gray.s[12])
              Text("since \(SecureStores.date(u.since)) · \(u.id.prefix(8))").kitText(1).foregroundStyle(Radix.gray.a[11])
            }
            Spacer()
            KitButton(title: "Lock", variant: .soft, color: .red, disabled: busy != nil, id: "lock-\(u.store)") { Task { await lock(u.id) } }
          } }
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

