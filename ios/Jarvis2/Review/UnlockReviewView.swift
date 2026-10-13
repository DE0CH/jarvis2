// Unlock a session's locked stores (a session waiting at boot on a locked store): what it unlocks comes from the core's
// signed documents only, the session's cert (its stores) and the store list (which are locked). Allow opens them all
// under one Face ID, for that session's cert only when the core takes such unlocks.
import SwiftUI

struct UnlockReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let sessionId: String
  let label: String
  let inbox: String?
  let request: SecureRequest
  @State private var locked: [String]?
  @State private var certStores: [String] = []
  /// the session as its core-signed cert names it (audit finding 4)
  @State private var ident: LineIdentity?
  @State private var certNonce: String?
  @State private var scoped = false
  @State private var signed: [SignedFact]?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      if loadError != nil, let failure { Section { ErrorRow(text: failure, id: "secure-deny-error") } }
      else if let locked {
        if inbox == nil { SignedFactsSection(facts: signed) }
        Section("Session (as signed)") {
          if let ident { IdentityRows(ident: ident) }
          if !label.isEmpty && label != ident?.label {
            LabeledContent { Text(label) } label: { HStack { Text("Asked for as"); StatusPill(text: "Unverified", color: .orange) } }
              .accessibilityElement(children: .combine)
          }
        }
        Section("Stores (signed cert)") { StoreLines(stores: certStores) }
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
      let c = try await RouterClient.shared.sessionCert(sessionId)
      try LinePins.check(session: sessionId, line: c.line)
      let id = LineIdentity(cert: c)
      try Checks.sameSession(id, expectedLabel: model.session(sessionId)?.j["label"].text)
      ident = id
      let doc = try await RouterClient.shared.storesDoc()
      scoped = !(c.nonce ?? "").isEmpty  // every core takes unlocks for one session; a cert without a nonce can't be named
      certNonce = scoped ? c.nonce : nil
      certStores = (c.stores ?? []).filter { $0 != StoreView.coreStore }
      let l = certStores.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
      locked = l
      signed = SignedAction.unlock(stores: l, session: id, scoped: scoped)
    } catch { loadError = errText(error) }
  }
  private func allow() async {
    guard let locked, !locked.isEmpty else { return }
    failure = nil
    do {
      busy = "Unlocking…"
      try await StoreUnlock.signAndUnlock(payload: nil, stores: locked, reason: "Unlock \(locked.joined(separator: ", "))", for: certNonce)
      model.secureCompleted(true)
    } catch { busy = nil; failure = errText(error) }
  }
}
