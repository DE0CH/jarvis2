// A repo's deploy key: add (the core makes an SSH key, puts it on GitHub as a read/write deploy key, keeps the private
// half in the store github-<repo>) or remove. What the page shows comes from the core's signed begin document (asked
// for when the page opens, and again when "Sensitive store" changes); one Face ID signs it and opens
// github-deploy-keys for this one request. The core's refusals (e.g. a 409 when another repo already owns the store
// name) are shown as the core words them.
import SwiftUI

struct RepoKeyView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let action: String
  let repo: String
  let sensitiveAsked: Bool
  let inbox: String?
  let request: SecureRequest
  @State private var b: DeployKeyBegin?
  @State private var doc: SignedDoc?
  @State private var sensitive = false
  @State private var forced = false
  @State private var signed: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String { action == "add" ? "Add repo" : "Remove repo" }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      Section("Repo") { Text(repo).font(.headline).accessibilityIdentifier("secure-repo-name") }
      if let b {
        Section("What happens") {
          if action == "add" {
            Text("The core makes a new SSH key and adds it to \(b.repo) on GitHub as a deploy key that can read and push (titled “\(b.title)”). It keeps the private half in the store \(b.store). Sessions that include \(b.store) can clone, pull and push this repo, and no other.")
            if b.replaces {
              Label("\(b.store) exists: its contents are replaced by the new key, and the earlier key “\(b.title)” is deleted on GitHub.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("secure-repo-replaces")
            }
          } else {
            Text("The core deletes the deploy key “\(b.title)” on GitHub and the store \(b.store). Sessions that hold the store lose access to the repo.")
          }
        }
        Section {
          StoreLines(stores: [b.store], sensitive: b.sensitive ? [b.store] : [])
          if action == "add" {
            Toggle("Sensitive store", isOn: Binding(get: { b.sensitive }, set: { v in if !forced && busy == nil { Task { await begin(sensitive: v) } } }))
              .disabled(forced || busy != nil)
              .accessibilityIdentifier("secure-repo-sensitive")
          }
        } header: { Text("Store") } footer: {
          if action == "add" {
            Text(forced ? "Always: a push to this repo can change Jarvis 2 itself, or the store is sensitive already (which never goes back)."
                 : "One way: a sensitive store can't be made not sensitive later.")
          }
        }
      } else if failure == nil {
        Section { ProgressView() }
      }
      Section {
        if let failure { ErrorRow(text: failure, id: "secure-error") }
        if let b { Text("Face ID lets the core use the GitHub token in \(b.tokenStore) for this one request; no other store is opened.").font(.footnote).foregroundStyle(.secondary) }
        SigningFooter()
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? (action == "add" ? "Add" : "Remove"), role: action == "add" ? nil : .destructive) { Task { await go() } }
          .disabled(b == nil || busy != nil).accessibilityIdentifier("secure-repo-go")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task {
      // Jarvis 2's own repo is always asked for as sensitive (Checks.deployKeyBegin refuses it otherwise)
      let want = sensitiveAsked || repo.lowercased() == "de0ch/jarvis2"
      sensitive = want
      await begin(sensitive: want)
    }
  }

  private func begin(sensitive want: Bool) async {
    failure = nil
    if b != nil { busy = "Checking…" }
    defer { busy = nil }
    do {
      let r = try await RouterClient.shared.deployKeyBegin(action: action, repo: repo, sensitive: want)
      doc = r.doc; b = r.begin; sensitive = want
      signed = SignedAction.deployKey(r.begin)
      forced = r.begin.sensitive && !want
    } catch { failure = errText(error) }
  }

  private func go() async {
    guard let b, let doc else { return }
    failure = nil
    do {
      busy = action == "add" ? "Adding…" : "Removing…"
      let payload = doc.payload, e = b.e, reason = "\(title): \(b.repo)"
      let r = try await offMain { try PhoneKeys.shared.signAndShare(payload, e: e, reason: reason) }
      _ = try await RouterClient.shared.deployKeyFinish(b, signature: r.signature, share: r.share)
      busy = nil
      model.say(action == "add" ? "\(repo): deploy key added." : "\(repo): deploy key and store removed.")
      model.secureCompleted(true)
    } catch {
      busy = nil
      let keep = errText(error)
      // the pending request is spent either way: ask the core again so the button works on the next tap
      await begin(sensitive: sensitive)
      failure = keep
    }
  }
}
