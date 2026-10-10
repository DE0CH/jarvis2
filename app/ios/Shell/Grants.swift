// The grant page (docs/DESIGN.md "Grants"): the phone lets one of the router's features (a holder) run
// commands in one session — for up to 10 minutes (a grant) or until a date (a standing rule). The React Native UI
// asks for one (feature, minutes or end date); this page shows that request in words, built from the session's
// core-signed cert (its line, its stores, whether it is sensitive, the phone it trusts), and the router's draft text
// is checked field for field against exactly what is shown (Checks.reviewGrant) before the signing key — the same
// Secure Enclave key that approves sessions — signs it under one Face ID. No raw text is signed unseen.
import SwiftUI

/// the features that may hold grants (router/grants.go holderNames), in words
let HOLDERS: [(id: String, title: String, sub: String)] = [
  ("terminal", "Terminal", "Read the session's screen and type into it"),
  ("scheduler", "Scheduler", "Deliver your wakeups and crons as messages"),
  ("status", "Status", "Read the screen, press Escape on a prompt left waiting, answer the model-switch dialog"),
  ("login", "Login repair", "Write fresh Claude credentials into the session and send “continue”"),
  ("archive", "Archive check", "List uncommitted and unpushed work before a destroy"),
  ("remote", "Remote page", "Read the web UI's link and the pairing offer or gateway token (OpenCode, OpenClaw)"),
]
func holderName(_ h: String) -> String { HOLDERS.first { $0.id == h }?.title ?? h }

/// The grant page is a review stop (Deyao, 2026-10-10): the React Native side decided what to ask for (which
/// feature, how long) — e.g. a button in the terminal page's error banner — and this page only shows that request in
/// plain words, as it will be signed, with Allow (one Face ID) and Deny. Nothing on it can be changed.
struct SecureGrant: View {
  let shell: Shell
  let sessionId: String
  let options: [String: Any]
  @State private var cert: SessionCert?
  @State private var holderKeys: [String: String] = [:]
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  // the request, as the React Native side made it (only what passes these checks can be allowed)
  private var holder: String { (options["holder"] as? String).flatMap { h in HOLDERS.contains { $0.id == h } ? h : nil } ?? "" }
  private var kind: String { (options["kind"] as? String) == "rule" ? "rule" : "grant" }
  private var minutes: Int { (options["minutes"] as? Int).flatMap { (1...10).contains($0) ? $0 : nil } ?? 10 }
  /// a standing rule's end: the date asked for, kept to between an hour and a year from now
  private var until: Date {
    let asked = (options["until"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date().addingTimeInterval(30 * 86400)
    return min(max(asked, Date().addingTimeInterval(3600)), Date().addingTimeInterval(366 * 86400))
  }
  private var label: String { (options["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? sessionId }
  private var sensitive: Bool { cert?.sensitive == true }
  /// why this request can't be allowed as asked, if it can't
  private var refusal: String? {
    if holder.isEmpty { return "The request names no feature this page knows." }
    if kind == "rule" && sensitive { return "This session holds a sensitive store: it accepts only a grant from this phone, minutes at a time — no standing rule." }
    if cert != nil && holderKeys[holder] == nil { return "The router lists no key for this feature." }
    return nil
  }
  private var endText: String {
    kind == "grant" ? "for \(minutes) minute\(minutes == 1 ? "" : "s") (until \(Date().addingTimeInterval(Double(minutes * 60)).formatted(date: .omitted, time: .shortened)))"
      : "until \(until.formatted(date: .abbreviated, time: .shortened))"
  }
  private var meaning: String {
    let what = HOLDERS.first(where: { $0.id == holder })?.sub ?? ""
    return "\(holderName(holder)) may run commands as the session's user in “\(label)” \(endText). \(what)."
  }

  var body: some View {
    SecureFrame(shell: shell, title: kind == "rule" ? "Standing rule" : "Allow a feature", action: ("Allow", "secure-grant-allow", cert == nil || refusal != nil),
                busy: busy, run: { Task { await allow() } }, backTitle: "Deny") {
      if let loadError { Callout(text: loadError, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      else if let cert {
        Lbl(text: "What you allow")
        Text(meaning).kitText(3, weight: .medium).foregroundStyle(Radix.gray.s[12])
          .frame(maxWidth: .infinity, alignment: .leading).accessibilityIdentifier("grant-meaning")
        if let refusal { Callout(text: refusal, amber: true).padding(.top, 12).accessibilityIdentifier("grant-refused") }
        Lbl(text: "Session")
        Muted(text: label)
        Text("line \(cert.line)").kitText(1, mono: true).foregroundStyle(Radix.gray.a[11])
          .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 2)
        Lbl(text: "Its stores (from the core's cert)")
        StoreLines(stores: (cert.stores ?? []).filter { $0 != StoreView.coreStore }, sensitive: [])
        Muted(text: "Signed with this iPhone's key (\(PhoneKeys.shared.how)); the session's machine checks the signature against the phone named in its cert. Forgetting it later stops the router using it.")
          .padding(.top, 16)
        if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      } else { ProgressView().frame(maxWidth: .infinity).padding(.top, 24) }
    }
    .task { await load() }
  }

  private func load() async {
    do {
      let c = try await RouterClient.shared.sessionCert(sessionId)
      holderKeys = try await RouterClient.shared.holders()
      cert = c
    } catch { loadError = errText(error) }
  }

  private func allow() async {
    guard let cert, refusal == nil, let hk = holderKeys[holder] else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let end = until
      var body: [String: Any] = ["holder": holder, "kind": kind]
      if kind == "grant" { body["minutes"] = minutes }
      else { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; body["until"] = f.string(from: end) }
      let text = try await RouterClient.shared.draftGrant(sessionId, body)
      // what is signed is exactly what this page shows: the draft checked field for field against it
      _ = try Checks.reviewGrant(text: text, cert: cert, phoneKey: phone, holderKey: hk, kind: kind, minutes: minutes, until: end)
      busy = "Signing…"
      let reason = "Allow \(holderName(holder)) in “\(label)” \(endText)"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Saving…"
      let g = try await RouterClient.shared.addGrant(sessionId, payload: text, sig: sig)
      guard g.holder == holder, g.kind == kind else { throw TrustError.stale("the stored grant") }
      shell.exitSecure("granted \(holder) in \(sessionId)", done: true, id: sessionId)
    } catch { busy = nil; failure = errText(error) }
  }
}
