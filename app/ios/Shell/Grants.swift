// The grant page (docs/DESIGN.md "Grants"): the phone lets one of the router's features (a holder) run
// commands in one session — for up to 10 minutes (a grant) or until a date (a standing rule). The page shows
// what that means in words, built from the session's core-signed cert (its line, its stores, whether it is
// sensitive, the phone it trusts) and from what is chosen here; the router's draft text is checked field for
// field against those choices (Checks.reviewGrant) before the signing key — the same Secure Enclave key that
// approves sessions — signs it under one Face ID. No raw text is signed unseen and nothing the React Native UI
// says is signed: it only opens the page with a pre-selection.
import SwiftUI

/// the features that may hold grants (router/grants.go holderNames), in words
let HOLDERS: [(id: String, title: String, sub: String)] = [
  ("terminal", "Terminal", "Read the session's screen and type into it"),
  ("scheduler", "Scheduler", "Deliver your wakeups and crons as messages"),
  ("status", "Status", "Read the screen, press Escape on a prompt left waiting, answer the model-switch dialog"),
  ("login", "Login repair", "Write fresh Claude credentials into the session and send “continue”"),
  ("archive", "Archive check", "List uncommitted and unpushed work before a destroy"),
]
func holderName(_ h: String) -> String { HOLDERS.first { $0.id == h }?.title ?? h }

struct SecureGrant: View {
  let shell: Shell
  let sessionId: String
  let options: [String: Any]
  @State private var cert: SessionCert?
  @State private var holderKeys: [String: String] = [:]
  @State private var holder = "terminal"
  @State private var kind = "grant"
  @State private var minutes = 10
  @State private var until = Date().addingTimeInterval(30 * 86400)
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var label: String { (options["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? sessionId }
  private var sensitive: Bool { cert?.sensitive == true }
  private var endText: String {
    kind == "grant" ? "for \(minutes) minute\(minutes == 1 ? "" : "s") (until \(Date().addingTimeInterval(Double(minutes * 60)).formatted(date: .omitted, time: .shortened)))"
      : "until \(until.formatted(date: .abbreviated, time: .shortened))"
  }
  private var meaning: String {
    "\(holderName(holder)) may run commands as the session's user in “\(label)” \(endText). \(HOLDERS.first { $0.id == holder }?.sub ?? "")."
  }

  var body: some View {
    SecureFrame(shell: shell, title: kind == "rule" ? "Standing rule" : "Allow a feature", action: ("Allow", "secure-grant-allow", cert == nil || holderKeys[holder] == nil),
                busy: busy, run: { Task { await allow() } }) {
      if let loadError { Callout(text: loadError, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      else if let cert {
        Lbl(text: "What you allow")
        Text(meaning).font(.system(size: K.fontSize[3], weight: .medium)).foregroundStyle(Radix.gray.s[12])
          .frame(maxWidth: .infinity, alignment: .leading).accessibilityIdentifier("grant-meaning")
        Lbl(text: "Session")
        Muted(text: label)
        Text("line \(cert.line)").font(.system(size: K.fontSize[1], design: .monospaced)).foregroundStyle(Radix.gray.s[11])
          .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 2)
        Lbl(text: "Its stores (from the core's cert)")
        StoreLines(stores: (cert.stores ?? []).filter { $0 != StoreView.coreStore }, sensitive: [])
        if sensitive {
          Callout(text: "This session holds a sensitive store: it accepts only a grant from this phone, minutes at a time — no standing rule.", amber: true)
            .padding(.top, 12).accessibilityIdentifier("grant-sensitive")
        }
        Lbl(text: "Feature")
        VStack(spacing: 8) {
          ForEach(HOLDERS, id: \.id) { h in
            ChoiceCard(on: holder == h.id, id: "grant-holder-\(h.id)", action: { holder = h.id }) { ChoiceText(title: h.title, sub: h.sub) }
          }
        }
        Lbl(text: "How long")
        VStack(spacing: 8) {
          ChoiceCard(on: kind == "grant", id: "grant-kind-grant", action: { kind = "grant" }) { ChoiceText(title: "Minutes", sub: "Now, while you watch — at most 10 minutes") }
          if !sensitive {
            ChoiceCard(on: kind == "rule", id: "grant-kind-rule", action: { kind = "rule" }) { ChoiceText(title: "Standing rule", sub: "For things that happen while you are away (wakeups, auto-pause), until a date") }
          }
        }
        if kind == "grant" {
          HStack(spacing: 8) {
            ForEach([1, 2, 5, 10], id: \.self) { m in
              KitButton(title: "\(m) min", variant: minutes == m ? .solid : .soft, color: minutes == m ? .blue : .gray, id: "grant-min-\(m)") { minutes = m }
            }
            Spacer()
          }.padding(.top, 12)
        } else {
          DatePicker("Until", selection: $until, in: Date().addingTimeInterval(3600)...Date().addingTimeInterval(366 * 86400))
            .font(.system(size: K.fontSize[2])).padding(.top, 12).accessibilityIdentifier("grant-until")
        }
        Muted(text: "Signed with this iPhone's key (\(PhoneKeys.shared.how)); the session's machine checks the signature against the phone named in its cert. Forgetting it later stops the router using it.")
          .padding(.top, 16)
        if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
      } else { ProgressView().frame(maxWidth: .infinity).padding(.top, 24) }
    }
    .task { await load() }
  }

  private func load() async {
    if let h = options["holder"] as? String, HOLDERS.contains(where: { $0.id == h }) { holder = h }
    if let k = options["kind"] as? String, k == "rule" { kind = "rule" }
    if let m = options["minutes"] as? Int, (1...10).contains(m) { minutes = m }
    do {
      let c = try await RouterClient.shared.sessionCert(sessionId)
      holderKeys = try await RouterClient.shared.holders()
      if c.sensitive == true { kind = "grant" }
      cert = c
    } catch { loadError = errText(error) }
  }

  private func allow() async {
    guard let cert, let hk = holderKeys[holder] else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let end = until
      var body: [String: Any] = ["holder": holder, "kind": kind]
      if kind == "grant" { body["minutes"] = minutes }
      else { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; body["until"] = f.string(from: end) }
      let text = try await RouterClient.shared.draftGrant(sessionId, body)
      _ = try Checks.reviewGrant(text: text, cert: cert, phoneKey: phone, holderKey: hk, kind: kind, minutes: minutes, until: end)
      busy = "Signing…"
      let reason = "Allow \(holderName(holder)) in “\(label)” \(endText)"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Saving…"
      let g = try await RouterClient.shared.addGrant(sessionId, payload: text, sig: sig)
      guard g.holder == holder, g.kind == kind else { throw TrustError.stale("the stored grant") }
      busy = nil
      shell.exitSecure("granted \(holder) in \(sessionId)", done: true, id: sessionId)
    } catch { busy = nil; failure = errText(error) }
  }
}
