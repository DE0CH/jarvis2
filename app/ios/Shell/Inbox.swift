// A request from the Inbox on its review page (docs/DESIGN.md "Requests"). When a secure page was opened for an
// Inbox entry (options carry `inboxId`), SecureFrame puts these three fields at the top, in decreasing trust and
// increasing level of explanation:
//   1. What you sign (exact) — rendered by this shell from the signed content (SignedAction, set by the page once
//      it has checked that content): what happens, mechanically. The one that matters, drawn strongest.
//   2. Requested via (router) — who called which endpoint with which arguments, as the router recorded it (the caller
//      worked out from its credential). The intent; as trustworthy as the router.
//   3. Reason given by <caller> (unverified) — the caller's own words, plain text. The why; not checked by anyone.
// Deny drops the request (an approval is rejected). Allow is the page's own button, unchanged.
import SwiftUI

extension RouterClient {
  /// one Inbox entry, as the router lists it (GET api/requests/:id); nil when it is gone
  func inboxItem(_ id: String) async throws -> [String: Any]? {
    let (status, data) = try await raw("GET", "api/requests/\(id)")
    if status == 404 { return nil }
    guard status == 200, let j = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw RouterError(message: Self.reason(data) ?? "HTTP \(status) from the Inbox")
    }
    return j
  }
  func inboxDeny(_ id: String) async throws { let _: [String: Bool] = try await json("DELETE", "api/requests/\(id)") }
  func inboxDone(_ id: String) async { _ = try? await raw("POST", "api/requests/\(id)/done") }
}

struct RequestReview: View {
  let shell: Shell
  let inboxId: String
  @State private var item: [String: Any]?
  @State private var gone = false
  @State private var loadError: String?
  @State private var busy = false

  private var callerText: String { item?["callerText"] as? String ?? "" }
  private var callLine: String {
    let c = item?["call"] as? [String: Any] ?? [:]
    let path = c["path"] as? String ?? ""
    return path.isEmpty ? "(no API call recorded)" : SignedAction.call(method: c["method"] as? String ?? "", path: path, args: c["args"] as? [String: Any])
  }
  private var explanation: String { item?["explanation"] as? String ?? "" }
  private var isApproval: Bool { item?["approval"] as? Bool ?? false }
  private var mismatch: String {
    guard let o = (item?["open"] as? [String: Any])?["options"] as? [String: Any] else { return "" }
    return SignedAction.mismatch(page: shell.secureOptions, request: o)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      // 1 — the signed part: anchored, strongest
      tierLabel("What you sign (exact)", color: .blue, icon: "signature")
      Text(shell.signedAction ?? "Reading what will be signed…")
        .kitText(3, weight: .bold).foregroundStyle(Radix.gray.s[12])
        .frame(maxWidth: .infinity, alignment: .leading).padding(12)
        .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.blue.a[2]))
        .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).stroke(Radix.blue.a[8], lineWidth: 2))
        .accessibilityIdentifier("request-signed")
      Muted(text: "Drawn by this iPhone from the signed content below. Only this is signed.").padding(.top, 4)

      if let loadError { Callout(text: loadError, color: .red).padding(.top, 12) }
      else if gone { Callout(text: "This request is no longer in the Inbox (answered, denied or expired elsewhere).", amber: true).padding(.top, 12).accessibilityIdentifier("request-gone") }
      else if item != nil {
        // 2 — the router's record: middle weight
        tierLabel("Requested via (router)", color: .gray, icon: "arrow.left.arrow.right")
        VStack(alignment: .leading, spacing: 4) {
          Text("\(callerText) called").kitText(2).foregroundStyle(Radix.gray.a[11])
          Text(callLine).kitText(1, mono: true).foregroundStyle(Radix.gray.s[12]).textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(10)
        .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(Radix.gray.a[3]))
        .accessibilityElement(children: .combine).accessibilityIdentifier("request-call")
        if !mismatch.isEmpty {
          Callout(text: "This request's \(mismatch) differs from what this page will sign. Deny it unless the signed part above is what you want.", color: .red)
            .padding(.top, 8).accessibilityIdentifier("request-mismatch")
        }
        // 3 — the caller's words: lightest, marked as theirs
        tierLabel("Reason given by \(callerText) (unverified)", color: .amber, icon: "quote.bubble")
        Text(explanation.isEmpty ? "No reason given." : explanation)
          .kitText(2).italic().foregroundStyle(Radix.gray.a[11])
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.leading, 10)
          .overlay(alignment: .leading) { Rectangle().fill(Radix.amber.a[6]).frame(width: 2) }
          .accessibilityIdentifier("request-explanation")
        if !isApproval {
          HStack {
            KitButton(title: busy ? "Denying…" : "Deny request", variant: .soft, color: .red, disabled: busy || shell.leaving, id: "request-deny") { Task { await deny() } }
            Spacer()
          }.padding(.top, 14)
        }
      }
      Rectangle().fill(Radix.gray.a[5]).frame(height: 1).padding(.top, 16)
    }
    .padding(.top, 12)
    .task { await load() }
  }

  private func tierLabel(_ text: String, color: KitColor, icon: String) -> some View {
    HStack(spacing: 5) {
      Image(systemName: icon).font(.system(size: 10, weight: .semibold))
      Text(text.uppercased()).modifier(KitFont(size: 11, lineHeight: 16, weight: .medium, tracking: 0.4, mono: false)).lineLimit(2)
    }
    .foregroundStyle(color.a[11]).padding(.top, 14).padding(.bottom, 6)
  }

  private func load() async {
    do {
      if let x = try await RouterClient.shared.inboxItem(inboxId) { item = x } else { gone = true }
    } catch { loadError = errText(error) }
  }

  private func deny() async {
    busy = true
    do {
      try await RouterClient.shared.inboxDeny(inboxId)
      shell.exitSecure("denied request \(inboxId)", done: true)
    } catch { busy = false; loadError = errText(error) }
  }
}
