// Unlock a session's locked stores (a session waiting on a locked store): which stores the session holds comes from
// its main grant (made by the grant mover or merger, checked against their keys as the box key vouches for them),
// which of them are locked from secrets' signed store list. Allow opens them all under one Face ID. An unlock is per
// store and serves every grant that names it until it is locked (Stores → Lock).
import SwiftUI

struct UnlockReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let sessionId: String
  let label: String
  let inbox: String?
  let request: SecureRequest
  @State private var locked: [String]?
  @State private var held: [String] = []
  /// keys sessions wrote into the locked stores (shown before Face ID; the unlock refuses one not shown)
  @State private var writes: [SessionWrite] = []
  @State private var signed: [SignedFact]?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      if loadError != nil, let failure { Section { ErrorRow(text: failure, id: "secure-deny-error") } }
      else if locked != nil {
        if inbox == nil { SignedFactsSection(facts: signed) }
        Section("Session") {
          Text(label.isEmpty ? sessionId : label).font(.headline).accessibilityIdentifier("secure-session")
          LabeledContent("Session id") { Text(sessionId).font(.footnote.monospaced()).textSelection(.enabled) }
        }
        Section("Stores (its signed grant)") { StoreLines(stores: held) }
        SessionWritesSection(writes: writes)
        Section {
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else { Section { ProgressView() } }
    }
    .navigationTitle("Unlock stores")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Deny") { deny() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Allow") { Task { await allow() } }.disabled((locked ?? []).isEmpty || busy != nil).accessibilityIdentifier("secure-unlock-allow")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  /// the stores a session's main grant names (its finite `store:` strings), the grant checked against the mover's or the
  /// merger's vouched key and naming this session
  static func sessionStores(_ sessionId: String) async throws -> [String] {
    guard let main = try await RouterClient.shared.chain(sessionId).main else { throw TrustError.mismatch("the session has no grant yet") }
    let g = try Kernel.openGrant(main, roster: try await KernelTrust.roster())
    guard g.pair.conditions.contains("session:" + sessionId) else { throw TrustError.mismatch("a grant for another session") }
    guard !g.pair.allowed.cofinite else { throw TrustError.mismatch("a grant that names every store") }
    return g.pair.allowed.elems.compactMap { $0.hasPrefix("store:") ? String($0.dropFirst(6)) : nil }.filter { $0 != StoreView.coreStore }
  }

  /// Deny: opened from the Inbox, the request is dropped (the session that asked hears "denied") and the page closes;
  /// opened from the app itself, nothing was asked for, so the page just closes. An error stays on the page.
  private func deny() {
    guard let inbox else { dismiss(); return }
    Task {
      failure = nil
      busy = "Denying…"
      do { try await RouterClient.shared.inboxDeny(inbox); model.secureCompleted(false) }
      catch { busy = nil; failure = errText(error) }
    }
  }

  private func load() async {
    do {
      held = try await Self.sessionStores(sessionId)
      let doc = try await RouterClient.shared.storesDoc()
      let l = held.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
      writes = await SessionWrites.load(l)
      locked = l
      signed = SignedAction.unlock(stores: l, session: sessionId) + SessionWrites.fact(writes)
    } catch { loadError = errText(error) }
  }
  private func allow() async {
    guard let locked, !locked.isEmpty else { return }
    failure = nil
    do {
      busy = "Unlocking…"
      try await StoreUnlock.signAndUnlock(payloads: [], stores: locked, reason: "Unlock \(locked.joined(separator: ", "))", shown: writes)
      model.secureCompleted(true)
    } catch { busy = nil; failure = errText(error) }
  }
}
