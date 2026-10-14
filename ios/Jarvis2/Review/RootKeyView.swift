// The root key's own screen (docs/DESIGN.md "Target design": a separate warning screen for the root key). The root key
// is a third Secure Enclave key (PhoneKeys.rootPublic), and the kernel's table accepts ANY succession cert it signs, so
// nothing else in the app ever uses it. What it signs here is fixed, byte for byte: root's ⊤ on the sink
// (Kernel.rootGrantPayload), which the router keeps (PUT api/kernel/root-grant) and the grant mover moves along every
// phone-made source. It is made once after each Reset or Recover (the setup page opens this screen), or again from
// Settings when the router has none. Its Face ID is its own, never shared with a batch.
import SwiftUI

struct RootKeyView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  /// pushed from the setup page: told once the grant is kept, and the screen pops; nil = the review sheet (Settings)
  var onDone: (() -> Void)? = nil
  @State private var understood = false
  @State private var busy: String?
  @State private var failure: String?

  var body: some View {
    Form {
      Section {
        Label("Root key", systemImage: "exclamationmark.octagon.fill")
          .font(.title2.weight(.bold)).foregroundStyle(.red)
          .accessibilityIdentifier("root-warning")
        Text("The root key can sign anything the kernel accepts. This signature gives the sink every right with no conditions; each new session's rights are cut from it by what you approve there.")
          .font(.callout)
        Toggle("I am signing the root grant", isOn: $understood).tint(.red).accessibilityIdentifier("root-understood")
      } footer: {
        Text("Signed only here, never as part of a batch.")
      }
      SignedFactsSection(facts: SignedAction.rootGrant())
      Section {
        if let failure { ErrorRow(text: failure, id: "root-error") }
        Button(busy ?? "Sign with the root key", role: .destructive) { Task { await sign() } }
          .disabled(!understood || busy != nil)
          .accessibilityIdentifier("root-sign")
        Label(PhoneKeys.shared.usesEnclave ? "The root key is in this iPhone's Secure Enclave, behind Face ID." : "A software root key (simulator).",
              systemImage: "lock.shield")
          .font(.footnote).foregroundStyle(.secondary)
      }
    }
    .navigationTitle("Root key")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("root-cancel") }
    }
    .interactiveDismissDisabled(busy != nil)
  }

  private func sign() async {
    failure = nil
    do {
      busy = "Signing…"
      let sig = try await offMain { try PhoneKeys.shared.rootSign(Kernel.rootGrantPayload, reason: "Sign the root grant with the root key") }
      busy = "Sending…"
      try await RouterClient.shared.putRootGrant(sig: sig)
      if let onDone { onDone(); dismiss(); Task { await model.refresh() } } else { model.secureCompleted(true) }
    } catch { busy = nil; failure = errText(error) }
  }
}
