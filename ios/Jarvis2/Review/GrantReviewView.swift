// The grant review (docs/DESIGN.md "Grants"): a router feature may run commands in one session for up to 10 minutes (a
// grant) or until a date (a standing rule). What was asked for is shown in plain words, built from the session's
// core-signed cert (its line, stores, whether it is sensitive, the phone it trusts); the router's draft is checked
// field for field against exactly that (Checks.reviewGrant) before the Secure Enclave key signs it under one Face ID.
// Nothing on the page can be changed: Allow or Deny.
import SwiftUI

struct GrantReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let ask: GrantAsk
  let inbox: String?
  let request: SecureRequest
  @State private var cert: SessionCert?
  /// the session as its core-signed cert names it (audit findings 3, 4: never the router's or the request's label)
  @State private var ident: LineIdentity?
  @State private var holderKeys: [String: String] = [:]
  @State private var signed: String?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var holder: String { Holder.all.contains { $0.id == ask.holder } ? ask.holder : "" }
  private var isRule: Bool { ask.kind == "rule" }
  private var minutes: Int { (1...10).contains(ask.minutes) ? ask.minutes : 10 }
  /// a standing rule's end, kept between an hour and a year from now
  private var until: Date {
    let asked = ask.until ?? .now.addingTimeInterval(Double(GrantAsk.ruleDays) * 86400)
    return min(max(asked, .now.addingTimeInterval(3600)), .now.addingTimeInterval(366 * 86400))
  }
  private var refusal: String? {
    if holder.isEmpty { return "The request names no feature this page knows." }
    if isRule && cert?.sensitive == true { return "This session holds a sensitive store: it accepts only a grant from this phone, minutes at a time, no standing rule." }
    if cert != nil && holderKeys[holder] == nil { return "The router lists no key for this feature." }
    return nil
  }
  private var endText: String {
    isRule ? "until \(until.formatted(date: .abbreviated, time: .shortened))"
      : "for \(minutes) minute\(minutes == 1 ? "" : "s") (until \(Date.now.addingTimeInterval(Double(minutes * 60)).formatted(date: .omitted, time: .shortened)))"
  }
  private var sessionWords: String { ident?.words ?? ask.session }
  private var meaning: String {
    "\(Holder.title(holder)) may run commands as the session's user in \(sessionWords) \(endText). \(Holder.sub(holder))."
  }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if let cert {
        Section("What you allow") {
          Text(meaning).font(.body.weight(.medium)).accessibilityIdentifier("grant-meaning")
          if let refusal { Label(refusal, systemImage: "hand.raised").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("grant-refused") }
        }
        Section("Session (as signed)") {
          if let ident { IdentityRows(ident: ident) }
          if !ask.label.isEmpty && ask.label != ident?.label { Text("Asked for as “\(ask.label)” (unverified)").font(.footnote).foregroundStyle(.secondary) }
        }
        Section("Its stores (from the core's cert)") {
          StoreLines(stores: (cert.stores ?? []).filter { $0 != StoreView.coreStore })
        }
        Section {
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        } footer: {
          Text("The session's machine checks the signature against the phone named in its cert. Forgetting it later stops the router using it.")
        }
      } else { Section { ProgressView() } }
    }
    .navigationTitle(isRule ? "Standing rule" : "Allow a feature")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Deny") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Allow") { Task { await allow() } }.disabled(cert == nil || refusal != nil || busy != nil).accessibilityIdentifier("secure-grant-allow")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  private func load() async {
    do {
      let c = try await RouterClient.shared.sessionCert(ask.session)
      try LinePins.check(session: ask.session, line: c.line)
      let id = LineIdentity(cert: c)
      try Checks.sameSession(id, expectedLabel: model.session(ask.session)?.j["label"].text)
      holderKeys = try await RouterClient.shared.holders()
      ident = id
      cert = c
      signed = refusal.map { "Nothing can be signed: \($0)" } ?? SignedAction.grant(meaning: meaning, line: c.line, of: id)
    } catch { loadError = errText(error) }
  }

  private func allow() async {
    guard let cert, refusal == nil, let hk = holderKeys[holder] else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let end = until
      var body: [String: Any] = ["holder": holder, "kind": ask.kind]
      if isRule {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
        body["until"] = f.string(from: end)
      } else { body["minutes"] = minutes }
      let text = try await RouterClient.shared.draftGrant(ask.session, body)
      // what is signed is exactly what this page shows: the draft checked field for field against it
      _ = try Checks.reviewGrant(text: text, cert: cert, phoneKey: phone, holderKey: hk, kind: ask.kind, minutes: minutes, until: end)
      busy = "Signing…"
      let reason = "Allow \(Holder.title(holder)) in \(ident?.label.map { "“\($0)”" } ?? "line \(cert.line)") \(endText)"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Saving…"
      let g = try await RouterClient.shared.addGrant(ask.session, payload: text, sig: sig)
      guard g.holder == holder, g.kind == ask.kind else { throw TrustError.stale("the stored grant") }
      model.secureCompleted(true)
    } catch { busy = nil; failure = errText(error) }
  }
}
