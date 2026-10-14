// A batch from the Inbox (docs/DESIGN.md "Requests", router/batches.go): several items a caller filed together,
// reviewed on one page and allowed under ONE Face ID. On top, the caller's summary (unverified, its words); below it
// every item with its own "What you sign (exact)", rendered from that item's signed content exactly as its own page
// renders it, and the call and reason the router recorded. Allow all: one Face ID (PhoneKeys.authorize), then every
// item is signed and sent on its own, exactly as from its own page (each approval's own drafts, each unlock's and each
// deploy key's own begin document): the kernel verifies each one unchanged. The root key never signs in a batch. An item
// that fails is shown failed; the ones before it already went through (they left the Inbox), so Retry reads the
// failed ones again and asks for one more Face ID. Deny all drops the batch; an item can be denied on its own.
import SwiftUI

/// one item, read and checked: what it signs and how to sign it under the batch's Face ID
struct BatchPrepared {
  let facts: [SignedFact]
  /// why it can't be signed (a short fixed label), as its own page would refuse it
  var refusal: String?
  let run: @MainActor (PhoneAuth) async throws -> Void
}

@MainActor
enum BatchPrepare {
  static func load(_ it: InboxItem, model: AppModel) async throws -> BatchPrepared {
    guard let req = SecureRequest.fromInbox(it) else { throw TrustError.mismatch("an item this app can't open") }
    switch req {
    case .approval(let id, _): return try await approval(id, model: model)
    case .unlock(let s, _, _): return try await unlock(s, model: model)
    case .repoKey(let a, let r, let sens, _): return try await repoKey(a, r, sens)
    case .newSession, .batch, .restore, .rootGrant: throw TrustError.mismatch("an item this app can't open")
    }
  }

  /// as ApprovalView.load / approve
  static func approval(_ approvalId: String, model: AppModel) async throws -> BatchPrepared {
    guard let x = try await RouterClient.shared.approval(approvalId) else { throw TrustError.stale("the approval (answered or rejected elsewhere)") }
    let roster = try await KernelTrust.roster()
    let rv = try Checks.review(x, notaryKey: roster.keys["notary"])
    var facts = SignedAction.approval(rv, cmd: x.cmd)
    if rv.isAddOn {
      guard let spawn = try await RouterClient.shared.chain(rv.session).spawn else { throw TrustError.mismatch("the session's spawn cert (it doesn't run)") }
      _ = try Checks.machineOf(rv, spawn: spawn, roster: roster)
    } else {
      let attest = try await ImageAttestation.check(image: rv.source.image, sig: x.imageSig)
      facts.append(.init(id: "image-build", label: "Image build", value: attest.badge, style: attest == .attested ? .plain : .warning))
    }
    if let rs = x.options?["restore"], !rs.isEmpty {
      facts.append(.init(id: "restore-router", label: "Restores (router's words)", value: rs, style: .code))
    }
    let doc = try await RouterClient.shared.storesDoc()
    let want: [String] = rv.kind == "add-store" ? [x.store ?? ""] : rv.isAddOn ? [] : rv.stores
    let toUnlock = want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    let writes = await SessionWrites.load(toUnlock)
    facts += SignedAction.alsoUnlocks(toUnlock) + SessionWrites.fact(writes)
    let payloads = rv.drafts.map(\.payload)
    return BatchPrepared(facts: facts) { auth in
      let reason = "Approve"
      let sigs: [Data]
      if toUnlock.isEmpty {
        sigs = try await offMain { try PhoneKeys.shared.signAndShares(payloads, es: [], reason: reason, auth: auth).signatures }
      } else {
        sigs = try await StoreUnlock.signAndUnlock(payloads: payloads, stores: toUnlock, reason: reason, shown: writes, auth: auth)
      }
      _ = try await RouterClient.shared.respond(approvalId, signatures: sigs)
    }
  }

  /// as UnlockReviewView.load / allow
  static func unlock(_ sessionId: String, model: AppModel) async throws -> BatchPrepared {
    let held = try await UnlockReviewView.sessionStores(sessionId)
    let doc = try await RouterClient.shared.storesDoc()
    let locked = held.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    let writes = await SessionWrites.load(locked)
    return BatchPrepared(facts: SignedAction.unlock(stores: locked, session: sessionId) + SessionWrites.fact(writes), refusal: locked.isEmpty ? "Nothing locked" : nil) { auth in
      try await StoreUnlock.signAndUnlock(payloads: [], stores: locked, reason: "Unlock \(locked.joined(separator: ", "))", shown: writes, auth: auth)
    }
  }

  /// as RepoKeyView.begin / go (the sensitivity asked for; Jarvis 2's own repo always sensitive)
  static func repoKey(_ action: String, _ repo: String, _ sensitiveAsked: Bool) async throws -> BatchPrepared {
    let want = sensitiveAsked || repo.lowercased() == "de0ch/jarvis2"
    let r = try await RouterClient.shared.deployKeyBegin(action: action, repo: repo, sensitive: want)
    let payload = r.doc.payload, b = r.begin
    let e = b.e
    return BatchPrepared(facts: SignedAction.deployKey(b)) { auth in
      let reason = (action == "add" ? "Add repo" : "Remove repo") + ": \(b.repo)"
      let x = try await offMain { try PhoneKeys.shared.signAndShare(payload, e: e, reason: reason, auth: auth) }
      _ = try await RouterClient.shared.deployKeyFinish(b, signature: x.signature, share: x.share)
    }
  }
}

struct BatchReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let batchId: String
  @State private var batch: InboxBatch?
  @State private var items: [InboxItem] = []
  @State private var prepared: [String: BatchPrepared] = [:]
  @State private var loadErrors: [String: String] = [:]
  /// per item after Allow all: "Allowed" or the error
  @State private var outcome: [String: Result<Void, Error>] = [:]
  @State private var gone = false
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var open: [InboxItem] { items.filter { !isDone($0) } }
  private func isDone(_ it: InboxItem) -> Bool { if case .success? = outcome[it.id] { return true }; return false }
  /// every item still to sign is read and signable
  private var ready: Bool {
    !open.isEmpty && open.allSatisfy { prepared[$0.id] != nil && prepared[$0.id]?.refusal == nil && loadErrors[$0.id] == nil }
  }
  private var allowTitle: String { outcome.values.contains { if case .failure = $0 { return true }; return false } ? "Retry" : "Allow all" }

  var body: some View {
    Form {
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if gone {
        Section { Label("No longer in the Inbox", systemImage: "tray").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("request-gone") }
      } else if let batch {
        Section {
          LabeledContent("Caller", value: batch.callerText).accessibilityIdentifier("batch-caller")
          Text(batch.callLine).font(.footnote.monospaced()).textSelection(.enabled).accessibilityIdentifier("batch-call")
          LabeledContent("Items", value: "\(items.count)").accessibilityIdentifier("batch-count")
          if let e = batch.expires { LabeledContent("Expires", value: Fmt.when(e)) }
        } header: { Label("Requested via (router)", systemImage: "arrow.left.arrow.right") }
        Section {
          if batch.summary.isEmpty {
            Text("None given").foregroundStyle(.secondary).accessibilityIdentifier("batch-summary")
          } else {
            Text(batch.summary)
              .italic()
              .padding(.leading, 10)
              .overlay(alignment: .leading) { Rectangle().fill(.orange.opacity(0.6)).frame(width: 2) }
              .textSelection(.enabled)
              .accessibilityIdentifier("batch-summary")
          }
        } header: {
          Label("Summary (unverified)", systemImage: "quote.bubble")
        } footer: {
          Text("Written by the caller. Each item below shows what you sign.")
        }
        ForEach(Array(items.enumerated()), id: \.element.id) { n, it in itemSection(n + 1, it) }
        Section {
          Button(busy == "Denying…" ? "Denying…" : "Deny all", role: .destructive) { Task { await denyAll() } }
            .disabled(busy != nil).accessibilityIdentifier("batch-deny")
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        } footer: {
          Text("Allow all signs every item, each on its own, under one Face ID.")
        }
      } else {
        Section { ProgressView() }
      }
    }
    .navigationTitle("Batch")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? allowTitle) { Task { await allowAll() } }.disabled(!ready || busy != nil).accessibilityIdentifier("batch-allow")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  @ViewBuilder private func itemSection(_ n: Int, _ it: InboxItem) -> some View {
    Section {
      if let e = loadErrors[it.id] { ErrorRow(text: e, id: "batch-item-error-\(n)") }
      else if let p = prepared[it.id] {
        if let r = p.refusal {
          Label(r, systemImage: "hand.raised").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("batch-item-refused-\(n)")
        }
        DisclosureGroup {
          ForEach(p.facts) { SignedFactRow(fact: $0) }
        } label: {
          Label("What you sign (exact)", systemImage: "signature")
        }
        .accessibilityIdentifier("batch-item-signed-\(n)")
      } else {
        LabeledContent("Reading") { ProgressView() }
      }
      Text(it.callLine).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      if !it.explanation.isEmpty {
        Text(it.explanation).italic().foregroundStyle(.secondary).accessibilityIdentifier("batch-item-reason-\(n)")
      }
      if !isDone(it) {
        Button("Deny this one", role: .destructive) { Task { await denyOne(it) } }.disabled(busy != nil).accessibilityIdentifier("batch-item-deny-\(n)")
      }
    } header: {
      HStack {
        Text("\(n). \(it.actionTitle)")
        Spacer()
        switch outcome[it.id] {
        case .some(.success): StatusPill(text: "Allowed", color: .green)
        case .some(.failure): StatusPill(text: "Failed", color: .red)
        case .none: EmptyView()
        }
      }
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier("batch-item-\(n)")
    } footer: {
      if case .failure(let e)? = outcome[it.id] { Text(errText(e)).foregroundStyle(.red).accessibilityIdentifier("batch-item-failure-\(n)") }
    }
  }

  /// the batch and its items; each item still to sign is read and checked as its own page would (again on Retry)
  private func load() async {
    do {
      let got = try await RouterClient.shared.inboxBatch(batchId)
      guard let g = got else { if outcome.isEmpty { gone = true } else { model.secureCompleted(true) }; return }
      batch = g.batch
      // items that went through stay listed (Allowed) until the page closes
      let done = items.filter(isDone)
      items = done + g.items.filter { x in !done.contains { $0.id == x.id } }
      for it in g.items where !isDone(it) {
        loadErrors[it.id] = nil
        do { prepared[it.id] = try await BatchPrepare.load(it, model: model) }
        catch { prepared[it.id] = nil; loadErrors[it.id] = errText(error) }
      }
    } catch { loadError = errText(error) }
  }

  private func allowAll() async {
    failure = nil
    let todo = open
    guard !todo.isEmpty else { return }
    if outcome.values.contains(where: { if case .failure = $0 { return true }; return false }) {
      // Retry: the failed items read and checked afresh first (a deploy key's begin is spent on any failure)
      busy = "Reading…"
      for it in todo { outcome[it.id] = nil }
      await load()
      busy = nil
      guard ready else { return }
    }
    let runs = open.compactMap { it in prepared[it.id].map { (it, $0) } }
    do {
      busy = "Face ID…"
      let n = runs.count
      let auth = try await offMain { try PhoneKeys.shared.authorize(reason: "Allow \(n) requests") }
      defer { auth.invalidate() }
      for (i, (it, p)) in runs.enumerated() {
        busy = "Signing \(i + 1) of \(n)…"
        do {
          try await p.run(auth)
          outcome[it.id] = .success(())
          if !it.isApproval { await RouterClient.shared.inboxDone(it.id) }
        } catch { outcome[it.id] = .failure(error) }
      }
      busy = nil
      if open.isEmpty { model.secureCompleted(true) }
      else { failure = "Some items failed; the others went through." }
    } catch { busy = nil; failure = errText(error) }
  }

  private func denyAll() async {
    do { busy = "Denying…"; try await RouterClient.shared.inboxDenyBatch(batchId); busy = nil; model.secureCompleted(true) }
    catch { busy = nil; failure = errText(error) }
  }

  private func denyOne(_ it: InboxItem) async {
    do {
      busy = "Denying…"
      try await RouterClient.shared.inboxDeny(it.id)
      busy = nil
      items.removeAll { $0.id == it.id }
      prepared[it.id] = nil
      if items.isEmpty { model.secureCompleted(true) }
    } catch { busy = nil; failure = errText(error) }
  }
}

extension InboxItem {
  /// the action the entry leads to: a fixed name per kind
  var actionTitle: String {
    let p = params
    switch kind {
    case "repo-key": return p["action"].string == "remove" ? "Remove deploy key" : "Add deploy key"
    case "unlock": return "Unlock stores"
    case "add-store": return "Add a store"
    case "terminal": return "Open a terminal"
    case "command": return "Run a command"
    case "resume-upgrade": return "Resume from a snapshot"
    case "api-call": return "API call"
    case "restore": return "Restore store"
    default: return j["options"]["restore"].text != nil ? "Restore" : "New session"
    }
  }
}
