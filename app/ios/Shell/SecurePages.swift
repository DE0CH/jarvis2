// The shell's secure pages: drawn only by the shell (the React Native UI's view is gone while one is up).
// What they show comes from the core's signed answers (checked against the paired core key); what the
// phone signs is checked first (CoreCrypto.swift, Checks).
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
  @ViewBuilder let content: () -> Content
  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 12) {
        KitButton(title: backTitle, variant: .soft, color: .gray, disabled: busy != nil, id: "secure-back") { shell.exitSecure("back") }
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

let HARNESSES: [(id: String, title: String, sub: String)] = [("claude", "Claude Code", "Claude subscription · Claude app"), ("opencode", "OpenCode · OpenRouter", "Paseo app + web UI")]
func harnessName(_ h: String) -> String { HARNESSES.first { $0.id == h }?.title ?? h }
func errText(_ e: Error) -> String { (e as? LocalizedError)?.errorDescription ?? e.localizedDescription }
/// key use waits for Face ID: keep it off the main thread
func offMain<T: Sendable>(_ fn: @escaping @Sendable () throws -> T) async throws -> T { try await Task.detached(priority: .userInitiated) { try fn() }.value }

/// the stores a challenge carries, sensitive ones marked
struct StoreLines: View {
  let stores: [String]
  let sensitive: [String]
  var body: some View {
    VStack(spacing: 8) {
      if stores.isEmpty { Muted(text: "No stores.") }
      ForEach(stores, id: \.self) { s in
        HStack(spacing: 6) {
          Text(s).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
          if sensitive.contains(s) { Badge(text: "Sensitive", color: .red) }
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
  @State private var picked: Set<String> = []
  @State private var harness = "claude"
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String { (options["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "New session" }
  private var pickedSensitive: [String] { stores.filter { $0.sensitive && picked.contains($0.name) }.map(\.name) }

  var body: some View {
    SecureFrame(shell: shell, title: "New session", action: ("Create", "secure-create", stores.isEmpty), busy: busy, run: { Task { await create() } }) {
      Lbl(text: "Session")
      Muted(text: title)
      Lbl(text: "Secret stores")
      if let loadError { Callout(text: loadError, color: .red) }
      else if stores.isEmpty { ProgressView().frame(maxWidth: .infinity) }
      VStack(spacing: 8) {
        ForEach(stores) { s in
          ChoiceCard(on: picked.contains(s.name), check: true, id: "secure-store-\(s.name)", action: { toggle(s.name) }) {
            HStack(spacing: 6) {
              Text(s.name).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              if !s.unlocked { Badge(text: "Locked") }
            }
            Text("\(s.keys.count) key\(s.keys.count == 1 ? "" : "s")").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11])
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
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
    }
    .task { await load() }
  }

  private func toggle(_ n: String) { if picked.contains(n) { picked.remove(n) } else { picked.insert(n) } }
  private func apply(_ list: [StoreView]) {
    stores = list.filter { !$0.isCore }  // the core's own store never goes to a session
    // pre-selection from normal mode: known, NON-sensitive stores only
    let pre = (options["stores"] as? [String]) ?? []
    if picked.isEmpty { picked = Set(pre.filter { n in stores.contains { $0.name == n && !$0.sensitive } }) }
  }
  private func load() async {
    if let p = shell.prefetched { apply(p) }
    if (options["harness"] as? String) == "opencode" { harness = "opencode" }
    do { let p = try await RouterClient.shared.stores(); shell.prefetched = p; let keep = picked; apply(p); if !keep.isEmpty { picked = keep.intersection(stores.map(\.name)) } }
    catch { if stores.isEmpty { loadError = errText(error) } }
  }

  private func create() async {
    failure = nil
    let want = picked.sorted(), rid = (options["requestId"] as? String) ?? CoreCrypto.nonce()
    do {
      let key = try CoreTrust.key()
      busy = "Starting…"
      var body: [String: Any] = ["requestId": rid, "stores": want, "harness": harness]
      for k in ["label", "prompt", "model", "permissionMode", "size"] { if let v = options[k] { body[k] = v } }
      try await RouterClient.shared.createSession(body)
      // the machine comes up (20–60 s), then the router asks the core for the challenge
      busy = "Starting the machine…"
      var found: RouterClient.ApprovalDTO?
      let until = Date().addingTimeInterval(180)
      while found == nil && Date() < until {
        let st = try await RouterClient.shared.state()
        if let s = st.sessions.first(where: { $0.createRequestId == rid }) {
          if s.state == "failed" { throw RouterError(message: "The router couldn't start the machine.") }
          found = st.approvals.first { $0.session == s.id && $0.kind == "new-session" }
        }
        if found == nil { try await Task.sleep(nanoseconds: 1_500_000_000) }
      }
      guard let a = found else { throw RouterError(message: "No approval yet — it will wait at the top of the session list.") }
      let r = try Checks.review(challenge: a.challenge, routerKind: a.kind, burnCert: a.burnCert, coreKey: key)
      try Checks.matchesPicked(r, stores: want, harness: harness)  // sign only what was chosen here
      busy = "Signing…"
      let payload = a.challenge.payload, reason = "Create \"\(title)\""
      let sig = try await offMain { try PhoneKeys.shared.sign(payload, reason: reason) }
      busy = "Creating…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.certFor(r, cert: ans.cert, coreKey: key)
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
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String {
    switch r?.kind { case .resumeUpgrade: return "Resume on the latest image"; case .addStore: return "Add a store"; default: return "Approve new session" }
  }
  var body: some View {
    SecureFrame(shell: shell, title: title, action: ("Approve", "secure-approve", r == nil), busy: busy, run: { Task { await approve() } }) {
      if let loadError { Callout(text: loadError, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      else if let r, let a {
        Lbl(text: "Session")
        Muted(text: (a.label ?? "").isEmpty ? (a.session ?? "") : a.label!)
        switch r.kind {
        case .addStore:
          Lbl(text: "Add this store")
          StoreLines(stores: [r.addedStore ?? ""], sensitive: r.sensitive)
          Lbl(text: "It already has")
          StoreLines(stores: r.stores.filter { $0 != r.addedStore }, sensitive: r.sensitive)
        case .resumeUpgrade:
          Muted(text: "The old machine is burned (the core's burn cert checks out); a new machine on the latest image continues the session with the same stores and harness.").padding(.top, 8)
          Lbl(text: "Secret stores"); StoreLines(stores: r.stores, sensitive: r.sensitive)
        case .newSession:
          Muted(text: "Requested outside this app (the web page or another device): check it is yours.").padding(.top, 8)
          Lbl(text: "Secret stores"); StoreLines(stores: r.stores, sensitive: r.sensitive)
        }
        let warn = r.kind == .addStore ? r.sensitive.filter { $0 == r.addedStore } : r.sensitive
        if !warn.isEmpty {
          Callout(text: "This session will hold sensitive secrets: \(warn.joined(separator: ", ")).", amber: true).padding(.top, 12).accessibilityIdentifier("secure-sensitive-warning")
        }
        Lbl(text: "Harness"); Muted(text: harnessName(r.harness))
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
      r = try Checks.review(challenge: x.challenge, routerKind: x.kind, burnCert: x.burnCert, coreKey: try CoreTrust.key())
      a = x
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
      try Checks.certFor(r, cert: ans.cert, coreKey: try CoreTrust.key())
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

  var body: some View {
    SecureFrame(shell: shell, title: "Stores", busy: busy) {
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      Lbl(text: "Stores")
      if !loaded && failure == nil { ProgressView().frame(maxWidth: .infinity) }
      VStack(spacing: 8) {
        ForEach(stores) { s in
          VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
              Text(s.title).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
              if s.sensitive { Badge(text: "Sensitive", color: .red) }
              Badge(text: s.unlocked ? "Unlocked" : "Locked", color: s.unlocked ? .blue : .gray)
              Spacer()
            }
            Text("\(s.keys.count) key\(s.keys.count == 1 ? "" : "s")").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11])
            if confirmMark == s.name {
              Callout(text: "Mark \(s.name) sensitive? The mark can never be removed.", amber: true)
              HStack(spacing: 8) {
                KitButton(title: "Cancel", variant: .soft, color: .gray, id: "mark-cancel-\(s.name)") { confirmMark = nil }
                KitButton(title: "Mark sensitive", color: .red, id: "mark-confirm-\(s.name)") { Task { await mark(s.name) } }
              }
            } else {
              HStack(spacing: 8) {
                KitButton(title: s.unlocked ? "Unlock again" : "Unlock", variant: s.unlocked ? .soft : .solid, disabled: busy != nil, id: "unlock-\(s.name)") { Task { await unlock(s.name) } }
                if !s.sensitive { KitButton(title: "Mark sensitive…", variant: .soft, color: .gray, disabled: busy != nil, id: "mark-\(s.name)") { confirmMark = s.name } }
              }
            }
          }
          .padding(12)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.surface))
          .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).strokeBorder(Radix.gray.a[6], lineWidth: 1))
        }
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
  private func lock(_ id: String) async { await run("Locking…") { try await RouterClient.shared.lock(id) } }
  private func mark(_ name: String) async { confirmMark = nil; await run("Marking…") { try await RouterClient.shared.markSensitive(name) } }
  static func date(_ iso: String) -> String {
    guard let d = ISO8601DateFormatter().date(from: iso) else { return iso }
    return d.formatted(date: .abbreviated, time: .shortened)
  }
}

// ---- pairing: this iPhone's keys out, the core's key in ---------------------------------------------
struct PairingPage: View {
  let shell: Shell
  @State private var phone: String = ""
  @State private var phoneError: String?
  @State private var paste = ""
  @State private var paired = CoreTrust.paired
  @State private var replacing = false
  @State private var failure: String?
  @State private var copied = false
  @State private var routerKey: String?

  var body: some View {
    SecureFrame(shell: shell, title: "Pairing", action: showField ? ("Save", "pair-save", paste.isEmpty) : nil, run: { Task { await save() } }, backTitle: paired == nil ? "Later" : "← Back") {
      Lbl(text: "This iPhone")
      Muted(text: "Its two public keys (signing + key agreement, \(PhoneKeys.shared.usesEnclave ? "in the Secure Enclave, Face ID on every use" : "software keys on the simulator")). Give this string to the session setting up the core.")
      if let phoneError { Callout(text: phoneError, color: .red) }
      Text(phone).font(.system(size: K.fontSize[1], design: .monospaced)).foregroundStyle(Radix.gray.s[12]).textSelection(.enabled)
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
        .padding(.top, 8)
        .accessibilityIdentifier("pair-phone").accessibilityLabel(phone)
      HStack { KitButton(title: copied ? "Copied" : "Copy", variant: .soft, id: "pair-copy") { UIPasteboard.general.string = phone; copied = true }; Spacer() }.padding(.top, 8)

      Lbl(text: "The core")
      if let p = paired, !replacing {
        Muted(text: "Paired. Every document from the core is checked against this key; it is never taken from the network.")
        Text(p.text).font(.system(size: K.fontSize[1], design: .monospaced)).foregroundStyle(Radix.gray.s[11]).textSelection(.enabled)
          .padding(12).frame(maxWidth: .infinity, alignment: .leading)
          .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
          .padding(.top, 8).accessibilityIdentifier("pair-core")
        if let rk = routerKey, rk != p.signingKey {
          Callout(text: "The router now reports a different core key — the core was restarted (a new controller) or something is wrong. Pair again only with a key from the session that set the core up.", amber: true).padding(.top, 8).accessibilityIdentifier("pair-core-changed")
        }
        HStack { KitButton(title: "Replace…", variant: .soft, color: .gray, id: "pair-replace") { Task { await startReplace() } }; Spacer() }.padding(.top, 8)
      } else {
        Muted(text: "Paste the core's string (jarvis2-core:…) from the session that set the core up.")
        TextField("jarvis2-core:…", text: $paste, axis: .vertical)
          .font(.system(size: K.fontSize[1], design: .monospaced)).textInputAutocapitalization(.never).autocorrectionDisabled()
          .padding(10).background(RoundedRectangle(cornerRadius: K.radius[2]).strokeBorder(Radix.gray.a[7], lineWidth: 1))
          .padding(.top, 8).accessibilityIdentifier("pair-core-field")
      }
      if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
    }
    .task {
      do { phone = try PhoneKeys.shared.publicString().text } catch { phoneError = errText(error) }
      routerKey = await RouterClient.shared.coreKeyNow()
    }
  }
  private var showField: Bool { paired == nil || replacing }
  private func startReplace() async {
    // replacing the trusted key needs the owner (Face ID or passcode) on a real iPhone
    if PhoneKeys.shared.usesEnclave {
      let ctx = LAContext()
      do { try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Replace the core's key") } catch { failure = errText(error); return }
    }
    replacing = true
  }
  private func save() async {
    failure = nil
    do {
      let p = try KeyPairString.parse(paste, role: "core")
      CoreTrust.save(p)
      paired = p; replacing = false; paste = ""
      shell.prefetched = nil
      shell.exitSecure("paired", done: true)
    } catch { failure = errText(error) }
  }
}
