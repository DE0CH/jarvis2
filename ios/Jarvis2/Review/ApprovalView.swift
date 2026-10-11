// An approval the router holds (a new line made elsewhere: the web page, a restore, a task; a resume on the latest
// image or in another mode; adding a store to a running machine). The kind comes from the core-signed challenge's own
// fields, never the router's label; the page shows what the challenge carries and signs it under one Face ID (which
// also unlocks the stores a new line gets, for that session only); the core's answer must be for this challenge.
import SwiftUI

struct ApprovalView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let approvalId: String
  let inbox: String?
  let request: SecureRequest
  @State private var a: RouterClient.ApprovalDTO?
  @State private var r: Checks.Reviewed?
  /// the session it continues, from the predecessor's core-signed cert (nil for a new line)
  @State private var ident: LineIdentity?
  /// whether CI signed the image the challenge names (nil: the challenge names no new image)
  @State private var attest: ImageAttestation?
  @State private var harnessStores: [String] = []
  @State private var toUnlock: [String] = []
  @State private var scoped = false
  @State private var signed: String?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String {
    switch r?.kind {
    case .resumeUpgrade: "Approve resume"
    case .addStore: "Add a store"
    case .newSession: "Approve new session"
    default: "Approve"
    }
  }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if let r, let a {
        Section {
          if let ident { IdentityRows(ident: ident) }
          else if r.kind == .newSession { Text(Self.signedLabel(r) ?? "A new, untitled session").font(.headline).accessibilityIdentifier("secure-session") }
          if let l = a.label, !l.isEmpty { Text("Listed by the router as “\(l)” (unverified)").font(.footnote).foregroundStyle(.secondary) }
          switch r.kind {
          case .addStore: Text("The running machine asks for one more store; it keeps its keys.").foregroundStyle(.secondary)
          case .resumeUpgrade: Text("The paused session continues on a new machine running the image and in the permission mode below, with the same stores and harness. Nothing happens until you approve; Reject leaves it paused.").foregroundStyle(.secondary)
          case .newSession:
            if let rs = a.options?["restore"], !rs.isEmpty {
              Text(r.config?["restore"] != nil ? "Restores the archived session \(rs): the snapshot below is part of what you sign." : "Restores the archived session \(rs) (this core doesn't sign which snapshot: the machine restores none).")
                .foregroundStyle(.secondary).accessibilityIdentifier("secure-restore")
            } else {
              Text("Requested outside this app (the web page, a task or another device): check it is yours.").foregroundStyle(.secondary)
            }
          case .other: Text("A request this page has no special view for: what you sign is below.").foregroundStyle(.secondary)
          }
        } header: { Text("Session (as signed)") }
        if r.kind == .addStore {
          Section("Add this store") { StoreLines(stores: [r.addedStore ?? ""], sensitive: r.sensitive) }
          Section("It already has") { StoreLines(stores: r.stores.filter { $0 != r.addedStore }, sensitive: r.sensitive, harness: harnessStores) }
        } else {
          Section("Secret stores") { StoreLines(stores: r.stores, sensitive: r.sensitive, harness: harnessStores) }
        }
        SignedSettingsSection(r: r)
        let warn = r.kind == .addStore ? r.sensitive.filter { $0 == r.addedStore } : r.sensitive
        Section {
          if !warn.isEmpty {
            Label("This session will hold sensitive secrets: \(warn.joined(separator: ", ")).", systemImage: "exclamationmark.triangle.fill")
              .foregroundStyle(.orange).accessibilityIdentifier("secure-sensitive-warning")
          }
          LabeledContent("Harness", value: Harness.name(r.harness))
          if r.kind != .addStore {
            if r.permissionMode == "bypass" {
              Label("Permission mode: bypass (no permission prompts at all)", systemImage: "exclamationmark.shield").foregroundStyle(.orange).accessibilityIdentifier("secure-mode")
            } else {
              Text("Permission mode: auto").accessibilityIdentifier("secure-mode")
            }
          }
          LabeledContent("Session image") { Text(r.image).font(.footnote.monospaced()).textSelection(.enabled) }
          if let attest {
            Label(attest.words, systemImage: attest == .attested ? "checkmark.seal" : "questionmark.diamond")
              .font(.footnote).foregroundStyle(attest == .attested ? .green : .orange).accessibilityIdentifier("secure-image-attest")
          }
          if r.kind == .other { LabeledContent("The challenge", value: r.challenge.request.kind) }
        }
        Section {
          if !toUnlock.isEmpty {
            Text("Approve also unlocks \(toUnlock.joined(separator: ", ")) (locked now) for this session only, with the same Face ID; the core locks \(toUnlock.count == 1 ? "it" : "them") again once the machine has its secrets.")
              .accessibilityIdentifier("secure-unlocks")
          }
          Button("Reject", role: .destructive) { Task { await reject() } }.disabled(busy != nil).accessibilityIdentifier("secure-reject")
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else {
        Section { ProgressView() }
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Approve") { Task { await approve() } }.disabled(r == nil || busy != nil).accessibilityIdentifier("secure-approve")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  static func signedLabel(_ r: Checks.Reviewed) -> String? { (r.config?["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } }

  private func load() async {
    do {
      guard let x = try await RouterClient.shared.approval(approvalId) else { loadError = "This approval is gone (answered or rejected elsewhere)."; return }
      let rv = try Checks.review(challenge: x.challenge, coreKey: try CoreTrust.key())
      // which session this continues comes from the signed predecessor, never the router's label (audit findings 1, 5)
      let id = try Checks.continues(rv, coreKey: try CoreTrust.key())
      if let id, let sid = x.session {
        try LinePins.check(session: sid, line: id.line)
        try Checks.sameSession(id, expectedLabel: model.session(sid)?.j["label"].text)
      }
      if (rv.kind == .resumeUpgrade || rv.kind == .addStore) && id == nil { throw TrustError.mismatch("a resume or added store that names no predecessor") }
      ident = id
      if rv.kind == .newSession || rv.kind == .resumeUpgrade { attest = try await ImageAttestation.check(image: rv.image, sig: x.imageSig) }
      harnessStores = PinnedPolicy.stores(rv.harness, router: model.policy)
      let doc = try await RouterClient.shared.storesDoc()
      let want: [String] = rv.kind == .addStore ? [rv.addedStore ?? ""] : rv.kind == .newSession ? rv.stores : []
      scoped = doc.scopedUnlocks == true
      // only with a core that unlocks for one session (an older core's unlocks would stay open to every session)
      toUnlock = scoped ? want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } } : []
      r = rv; a = x
      signed = SignedAction.approval(rv, of: id) + SignedAction.alsoUnlocks(toUnlock, scoped: scoped)
    } catch { loadError = errText(error) }
  }
  private func approve() async {
    guard let a, let r else { return }
    failure = nil
    do {
      busy = "Signing…"
      let payload = a.challenge.payload, reason = title + (toUnlock.isEmpty ? "" : " and unlock \(toUnlock.joined(separator: ", "))")
      let sig: Data
      if toUnlock.isEmpty {
        sig = try await offMain { try PhoneKeys.shared.sign(payload, reason: reason) }
      } else {
        guard let s = try await StoreUnlock.signAndUnlock(payload: payload, stores: toUnlock, reason: reason, for: r.challenge.nonce) else { throw TrustError.stale("signature") }
        sig = s
      }
      busy = "Approving…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.answerFor(r, answer: ans.answer, coreKey: try CoreTrust.key())
      model.secureCompleted(true)
    } catch { busy = nil; failure = errText(error) }
  }
  private func reject() async {
    guard let a else { return }
    do { busy = "Rejecting…"; try await RouterClient.shared.reject(a.id); model.secureCompleted(true) }
    catch { busy = nil; failure = errText(error) }
  }
}

/// the signed settings and one-time inputs of a challenge (core Options.Config / Once), as signed: what the machine takes
struct SignedSettingsSection: View {
  let r: Checks.Reviewed
  var body: some View {
    let c = r.config ?? [:], o = r.once ?? [:]
    let s = { (k: String) -> String in (c[k] as? String) ?? "" }
    if r.kind == .newSession || !o.isEmpty {
      Section("What the machine takes (signed)") {
        if r.kind == .newSession {
          if !s("label").isEmpty { LabeledContent("Title", value: s("label")).accessibilityIdentifier("signed-label") }
          if !s("prompt").isEmpty {
            VStack(alignment: .leading) { Text("First prompt").font(.footnote).foregroundStyle(.secondary); Text(s("prompt")).textSelection(.enabled) }
              .accessibilityElement(children: .combine).accessibilityIdentifier("signed-prompt")
          }
          if let atts = c["attachments"] as? [[String: Any]], !atts.isEmpty {
            LabeledContent("Attachments (checked by hash)", value: atts.map { "\(($0["name"] as? String) ?? "?") (\((($0["sha256"] as? String) ?? "").prefix(12))…)" }.joined(separator: "\n"))
              .accessibilityIdentifier("signed-attachments")
          }
          if let rs = c["restore"] as? [String: Any] {
            LabeledContent("Restores", value: "the archived snapshot of machine \((rs["machine"] as? String) ?? "?") (sha256 \(((rs["sha256"] as? String) ?? "").prefix(12))…)")
              .accessibilityIdentifier("signed-restore")
          }
          if let repos = c["repos"] as? [String], !repos.isEmpty { LabeledContent("Repos", value: repos.joined(separator: "\n")).accessibilityIdentifier("signed-repos") }
          if !s("model").isEmpty { LabeledContent("Model", value: s("model")) }
          if (c["oneShot"] as? Bool) == true { Text("One-shot: it runs its prompt, then is archived and destroyed.") }
          if (c["apiProxy"] as? Bool) == true { Text("API proxy: every API request and response is logged into ~/artifacts/api-log.") }
          if let t = c["task"] as? [String: Any] { LabeledContent("Task", value: "\((t["name"] as? String) ?? "") · \(Checks.compact(t["params"]))") }
          if r.config == nil { Text("This core doesn't carry settings in the cert: no prompt, title, model or repos beyond the stores' own.").foregroundStyle(.secondary) }
        }
        if let p = o["prompt"] as? String, !p.isEmpty {
          VStack(alignment: .leading) { Text("Prompt typed into the resumed conversation").font(.footnote).foregroundStyle(.secondary); Text(p).textSelection(.enabled) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("signed-once-prompt")
        }
        if let m = o["rollback"] as? String, !m.isEmpty {
          Label("Rolls the conversation back: every transcript line from the first containing “\(m)” is dropped.", systemImage: "arrow.uturn.backward")
            .foregroundStyle(.orange).accessibilityIdentifier("signed-once-rollback")
        }
      }
    }
  }
}

/// a session as its core-signed cert names it: the title and first prompt Deyao gave it, its line and machine, when the
/// cert was issued, and whether it holds a sensitive store
struct IdentityRows: View {
  let ident: LineIdentity
  var body: some View {
    Text(ident.label.map { "“\($0)”" } ?? "An untitled session").font(.headline).accessibilityIdentifier("secure-session")
    if let p = ident.prompt { LabeledContent("First prompt", value: Fmt.clip(p, 140)) }
    LabeledContent("Line") { Text(ident.line).font(.footnote.monospaced()).textSelection(.enabled) }
    if let m = ident.machine, m != ident.line { LabeledContent("Machine") { Text(m).font(.footnote.monospaced()) } }
    if let at = ident.issuedAt?.isoDate { LabeledContent("Its cert", value: "issued \(Fmt.ago(at))") }
    if ident.sensitive {
      Label("This session holds a sensitive store.", systemImage: "exclamationmark.octagon.fill").foregroundStyle(.red).accessibilityIdentifier("secure-session-sensitive")
    }
    if ident.label == nil {
      Label("This core doesn't sign the session's title: check the line and the stores before you approve.", systemImage: "questionmark.circle").font(.footnote).foregroundStyle(.orange)
    }
  }
}
