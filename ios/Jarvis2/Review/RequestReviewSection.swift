// A request from the Inbox on its review page (docs/DESIGN.md "Requests"): three fields at the top, in decreasing trust
// and increasing explanation:
//   1. What you sign (exact): rendered by this app from the signed content (SignedAction, set by the page once it
//      has checked that content). The one that matters, drawn strongest.
//   2. Requested via (router): who called which endpoint with which arguments, as the router recorded it.
//   3. Reason given by <caller> (unverified): the caller's own words, checked by no one.
// Deny drops the request (an approval is rejected). Allow is the page's own button.
import SwiftUI

struct RequestReviewSection: View {
  @Environment(AppModel.self) private var model
  let inboxId: String
  /// what this page signs, rendered from the signed content; nil while the page is still reading it
  let signed: String?
  let request: SecureRequest
  @State private var item: InboxItem?
  @State private var gone = false
  @State private var error: String?
  @State private var denying = false

  var body: some View {
    Section {
      Text(signed ?? "Reading what will be signed…")
        .font(.body.bold())
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.blue.opacity(0.08), in: .rect(cornerRadius: 10))
        .overlay { RoundedRectangle(cornerRadius: 10).stroke(.blue.opacity(0.6), lineWidth: 2) }
        .accessibilityIdentifier("request-signed")
    } header: {
      Label("What you sign (exact)", systemImage: "signature")
    } footer: {
      Text("Drawn by this iPhone from the signed content below. Only this is signed.")
    }
    .task { await load() }
    if let error { Section { ErrorRow(text: error) } }
    else if gone {
      Section { Label("This request is no longer in the Inbox (answered, denied or expired elsewhere).", systemImage: "tray").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("request-gone") }
    } else if let item {
      Section {
        VStack(alignment: .leading, spacing: 4) {
          Text("\(item.callerText) called").font(.subheadline).foregroundStyle(.secondary)
          Text(item.callLine).font(.footnote.monospaced()).textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("request-call")
        if let k = mismatch(item) {
          ErrorRow(text: "This request's \(k) differs from what this page will sign. Deny it unless the signed part above is what you want.", id: "request-mismatch")
        }
      } header: { Label("Requested via (router)", systemImage: "arrow.left.arrow.right") }
      Section {
        Text(item.explanation.isEmpty ? "No reason given." : item.explanation)
          .italic().foregroundStyle(.secondary)
          .padding(.leading, 10)
          .overlay(alignment: .leading) { Rectangle().fill(.orange.opacity(0.6)).frame(width: 2) }
          .accessibilityIdentifier("request-explanation")
        if !item.isApproval {
          Button(denying ? "Denying…" : "Deny request", role: .destructive) { Task { await deny() } }
            .disabled(denying)
            .accessibilityIdentifier("request-deny")
        }
      } header: { Label("Reason given by \(item.callerText) (unverified)", systemImage: "quote.bubble") }
    }
  }

  private func mismatch(_ it: InboxItem) -> String? {
    let k = SignedAction.mismatch(page: request.options, request: it.openOptions.anyObject)
    return k.isEmpty ? nil : k
  }
  private func load() async {
    do { if let x = try await RouterClient.shared.inboxItem(inboxId) { item = x } else { gone = true } }
    catch { self.error = errText(error) }
  }
  private func deny() async {
    denying = true
    do { try await RouterClient.shared.inboxDeny(inboxId); model.secureCompleted(true) }
    catch { denying = false; self.error = errText(error) }
  }
}
