// An approval the router holds (docs/API.md "Approvals"): a new session made elsewhere (the web page, a restore, a task,
// a session's proposal), a resume from a snapshot with a change (a newer image, a prompt, a rollback), or an add-on for a
// running session (a terminal, a command, another store). What it is comes from the drafts' own payloads, never the
// router's label: the page shows every draft as signed (SignedAction.approval: the source's image and settings, the
// machine object with its keys, every right and condition), checks it for its kind (Checks.review) and, for an add-on,
// that the machine is the session's (Checks.machineOf, the spawner's spawn cert). Approve signs every draft under ONE
// Face ID, which also unlocks the stores the session gets that are locked.
import SwiftUI

struct ApprovalView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let approvalId: String
  let inbox: String?
  let request: SecureRequest
  @State private var a: ApprovalDTO?
  @State private var r: ReviewedApproval?
  /// the session's title as signed: a source's settings, or for an add-on the settings of the source its machine came from
  @State private var signedTitle: String?
  /// whether CI signed the image a new source names (nil: no new image)
  @State private var attest: ImageAttestation?
  @State private var harnessStores: [String] = []
  @State private var toUnlock: [String] = []
  /// keys sessions wrote into the stores it unlocks (shown before Face ID; the unlock refuses one not shown)
  @State private var writes: [SessionWrite] = []
  /// sensitive stores, from secrets' signed store list
  @State private var sens: [String] = []
  @State private var signed: [SignedFact]?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String {
    switch r?.kind ?? a?.kind {
    case "resume-upgrade": "Approve resume"
    case "terminal": "Open a terminal"
    case "command": "Run a command"
    case "add-store": "Add a store"
    case "new-session": "Approve new session"
    default: "Approve"
    }
  }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError {
        // nothing can be signed, but the approval can still be rejected here
        Section {
          ErrorRow(text: loadError, id: "secure-error")
          Text("This page can't be approved on this iPhone. Reject it, or ask for it again after updating the app.")
            .font(.footnote).foregroundStyle(.secondary).accessibilityIdentifier("secure-cant-approve")
        }
        rejectSection
      } else if let r, let a {
        summary(r, a)
        if inbox == nil { SignedFactsSection(facts: signed) }
        if let cmd = a.cmd, r.kind == "command" {
          Section("Command (signed by its sha256)") {
            Text(cmd).font(.body.monospaced()).textSelection(.enabled).accessibilityIdentifier("secure-command")
          }
        }
        if r.kind == "new-session" || r.kind == "resume-upgrade" {
          Section("Secret stores") { StoreLines(stores: r.stores, sensitive: sens, harness: harnessStores) }
          SignedAttachmentsSection(r: r, session: a.session)
        }
        SessionWritesSection(writes: writes)
        Section {
          if !toUnlock.isEmpty {
            LabeledContent {
              Text(toUnlock.joined(separator: "\n")).multilineTextAlignment(.trailing)
            } label: {
              Label("Also unlocks", systemImage: "lock.open")
            }
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-unlocks")
          }
          Button("Reject", role: .destructive) { Task { await reject() } }.disabled(busy != nil).accessibilityIdentifier("secure-reject")
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else {
        Section { ProgressView() }
        rejectSection
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

  @ViewBuilder private var rejectSection: some View {
    Section {
      Button(busy == "Rejecting…" ? "Rejecting…" : "Reject", role: .destructive) { Task { await reject() } }
        .disabled(busy != nil).accessibilityIdentifier("secure-reject")
      if let failure { ErrorRow(text: failure, id: "secure-reject-error") }
    } footer: { if r == nil && loadError == nil { Text("Approve shows once the page has read and checked the approval.") } }
  }

  /// the few facts that decide: the action, the session (as signed), what it gets, and what stands out
  @ViewBuilder private func summary(_ r: ReviewedApproval, _ a: ApprovalDTO) -> some View {
    Section {
      Text(signedTitle ?? "Untitled").font(.headline).accessibilityIdentifier("secure-session")
      if signedTitle == nil { Label("Title not signed", systemImage: "questionmark.circle").font(.footnote).foregroundStyle(.orange) }
      if let l = a.label, !l.isEmpty, l != signedTitle {
        LabeledContent { Text(l) } label: { HStack { Text("Router's label"); StatusPill(text: "Unverified", color: .orange) } }
          .accessibilityElement(children: .combine)
      }
      LabeledContent("Action", value: Self.actionName(r.kind)).accessibilityIdentifier("secure-action")
      LabeledContent("Session") { Text(r.session).font(.footnote.monospaced()).textSelection(.enabled) }
      switch r.kind {
      case "new-session", "resume-upgrade":
        if let rs = a.options?["restore"], !rs.isEmpty {
          LabeledContent("Restores") { Text(rs).font(.footnote.monospaced()) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-restore")
        }
        if !r.source.snapshot.isEmpty {
          LabeledContent("Starts from snapshot") { Text(String(r.source.snapshot.prefix(16)) + "…").font(.footnote.monospaced()) }
        }
        LabeledContent("Harness", value: Harness.name(r.harness))
        LabeledContent {
          Text(r.permissionMode)
        } label: {
          if r.permissionMode == "bypass" { Label("Permission mode", systemImage: "exclamationmark.shield") } else { Text("Permission mode") }
        }
        .foregroundStyle(r.permissionMode == "bypass" ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
        .accessibilityElement(children: .combine).accessibilityIdentifier("secure-mode")
        LabeledContent("Session image") { Text(r.source.image).font(.footnote.monospaced()).textSelection(.enabled) }
        if let attest {
          LabeledContent("Image build") { StatusPill(text: attest.badge, color: attest == .attested ? .green : .orange) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-image-attest")
        }
      case "add-store":
        LabeledContent("Store") { Text(a.store ?? "").font(.body.monospaced()) }.accessibilityIdentifier("secure-store")
      default:
        if let t = r.until { LabeledContent("Until", value: t.formatted(date: .omitted, time: .shortened)).accessibilityIdentifier("secure-until") }
        LabeledContent("Runs as", value: "The session's user")
      }
      if let m = r.machine {
        LabeledContent("Running machine") { Text(m.id).font(.footnote.monospaced()) }.accessibilityIdentifier("secure-machine")
      }
      let warn = r.kind == "add-store" ? sens.filter { $0 == a.store } : r.stores.filter { sens.contains($0) }
      if !warn.isEmpty {
        LabeledContent {
          Text(warn.joined(separator: "\n")).multilineTextAlignment(.trailing)
        } label: {
          Label("Sensitive", systemImage: "exclamationmark.triangle.fill")
        }
        .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("secure-sensitive-warning")
      }
    } header: { Text("Session (as signed)") }
  }

  static func actionName(_ k: String) -> String {
    switch k {
    case "new-session": "New session"
    case "resume-upgrade": "Continue from a snapshot"
    case "terminal": "Open a terminal"
    case "command": "Run a command"
    case "add-store": "Add a store"
    default: k
    }
  }

  private func load() async {
    do {
      guard let x = try await RouterClient.shared.approval(approvalId) else { loadError = "This approval is gone (answered or rejected elsewhere)."; return }
      let roster = try await KernelTrust.roster()
      let rv = try Checks.review(x, notaryKey: roster.keys["notary"])
      if rv.isAddOn {
        // the machine it reaches is the session's: the spawner's notarized spawn cert names it, out of this session's source
        guard let spawn = try await RouterClient.shared.chain(rv.session).spawn else { throw TrustError.mismatch("the session's spawn cert (it doesn't run)") }
        let st = try Checks.machineOf(rv, spawn: spawn, roster: roster)
        signedTitle = (st["title"] as? String).flatMap { $0.isEmpty ? nil : $0 }
      } else {
        signedTitle = rv.title
        attest = try await ImageAttestation.check(image: rv.source.image, sig: x.imageSig)
      }
      harnessStores = PinnedPolicy.stores(rv.harness, router: model.policy)
      let doc = try await RouterClient.shared.storesDoc()
      sens = doc.stores.filter(\.sensitive).map(\.name)
      let want: [String] = rv.kind == "add-store" ? [x.store ?? ""] : rv.isAddOn ? [] : rv.stores
      toUnlock = want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
      writes = await SessionWrites.load(toUnlock)
      r = rv; a = x
      signed = SignedAction.approval(rv, cmd: x.cmd) + SignedAction.alsoUnlocks(toUnlock) + SessionWrites.fact(writes)
    } catch { loadError = errText(error) }
  }
  private func approve() async {
    guard let a, let r else { return }
    failure = nil
    do {
      busy = "Signing…"
      let payloads = r.drafts.map(\.payload), reason = title + (toUnlock.isEmpty ? "" : " and unlock \(toUnlock.joined(separator: ", "))")
      let sigs: [Data]
      if toUnlock.isEmpty {
        sigs = try await offMain { try PhoneKeys.shared.signAndShares(payloads, es: [], reason: reason).signatures }
      } else {
        sigs = try await StoreUnlock.signAndUnlock(payloads: payloads, stores: toUnlock, reason: reason, shown: writes)
      }
      busy = "Approving…"
      _ = try await RouterClient.shared.respond(a.id, signatures: sigs)
      model.secureCompleted(true)
    } catch { busy = nil; failure = errText(error) }
  }
  /// Reject needs no signature: it works even when the page couldn't read or check the approval
  private func reject() async {
    failure = nil
    do { busy = "Rejecting…"; try await RouterClient.shared.reject(a?.id ?? approvalId); model.secureCompleted(false) }
    catch { busy = nil; failure = errText(error) }
  }
}

/// the first prompt's images a source's settings name, each read back from the router and hashed against the signed
/// sha256 and size
struct SignedAttachmentsSection: View {
  let r: ReviewedApproval
  var session: String? = nil
  var body: some View {
    if let c = r.settings, let atts = Checks.attachments(c), !atts.isEmpty {
      Section {
        ForEach(atts, id: \.name) { SignedAttachmentRow(session: session, ref: $0) }
      } header: { Text("Images (signed)").accessibilityIdentifier("signed-attachments") }
    }
  }
}
