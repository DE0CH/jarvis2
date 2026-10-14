// The Inbox: everything waiting for this iPhone's Face ID that was asked for elsewhere (a session, the web page, Claude's
// setup session), and the router's approvals. Each row: the action (a fixed name per kind), what it is about (repo,
// feature, session: the router's record; the review page renders the exact facts from the signed content), who asked,
// when, the call, and the caller's reason in its own words.
// Review opens the page for it; Deny (a swipe or the page's button) drops it. An API call a session's actions asked
// for (router/apicalls.go) has no secure page: tapping it asks to run it, as Deyao, with no Face ID.
import SwiftUI

struct InboxView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    NavigationStack {
      List {
        if !model.inboxBatches.isEmpty {
          Section {
            ForEach(model.inboxBatches) { b in BatchRow(b: b) }
          } header: {
            Text("Batches")
          } footer: {
            Text("One Face ID allows every item of a batch.")
          }
        }
        if !model.inboxLoose.isEmpty {
          Section {
            ForEach(model.inboxLoose) { it in InboxRow(it: it) }
          } header: {
            Text("Requests")
          } footer: {
            Text("Nothing happens until you allow it with Face ID.")
          }
        }
      }
      .overlay {
        if model.inboxCount == 0 {
          ContentUnavailableView("Nothing waiting for you", systemImage: "tray", description: Text("Requests from sessions, the web page and Claude show up here."))
            .accessibilityIdentifier("inbox-empty")
        }
      }
      .navigationTitle("Inbox")
      .refreshable { await model.refresh() }
    }
  }
}

private struct InboxRow: View {
  @Environment(AppModel.self) private var model
  let it: InboxItem
  @State private var confirmCall = false

  var body: some View {
    Button(action: { if it.kind == "api-call" { confirmCall = true } else { review() } }) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text(action).font(.headline).foregroundStyle(Color.primary).accessibilityIdentifier("request-title-\(it.id)")
          Spacer()
          if let p = model.pending["q:" + it.id] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: kindName, color: .blue) }
        }
        if !details.isEmpty { Text(details.joined(separator: " · ")).font(.subheadline).foregroundStyle(Color.primary) }
        HStack(spacing: 12) {
          Label(it.callerText, systemImage: "person")
          if let c = it.created { Label(Fmt.ago(c), systemImage: "clock") }
          if let e = it.expires { Label(Fmt.when(e), systemImage: "hourglass") }
          if it.params["sensitive"].bool == true { StatusPill(text: "Sensitive", color: .red) }
        }
        .font(.footnote).foregroundStyle(Color.secondary).labelStyle(.titleAndIcon)
        Text(it.callLine).font(.caption.monospaced()).foregroundStyle(Color.secondary).lineLimit(2)
        if !it.explanation.isEmpty {
          Text("“\(it.explanation)”").font(.subheadline).italic().foregroundStyle(Color.secondary).lineLimit(2)
            .accessibilityIdentifier("request-reason-\(it.id)")
        }
      }
    }
    .accessibilityIdentifier("request-review-\(it.id)")
    .confirmationDialog("Run \(callTarget) as you?", isPresented: $confirmCall, titleVisibility: .visible) {
      Button("Approve") { Task { await model.approveCall(it) } }.accessibilityIdentifier("request-approve-\(it.id)")
      Button("Deny", role: .destructive) { Task { await model.deny(it) } }
    } message: {
      Text("Asked by \(it.callerText).")
    }
    .swipeActions {
      Button("Deny", role: .destructive) { Task { await model.deny(it) } }
    }
    .contextMenu {
      if it.kind == "api-call" {
        Button("Approve", systemImage: "checkmark") { Task { await model.approveCall(it) } }
      } else {
        Button("Review", systemImage: "faceid", action: review)
      }
      Button("Deny", systemImage: "xmark", role: .destructive) { Task { await model.deny(it) } }
    }
  }

  private var callTarget: String { "\(it.params["method"].string ?? "") \(it.params["path"].string ?? "")" }

  private func review() {
    guard let r = SecureRequest.fromInbox(it) else { model.say("This request can't be opened here."); return }
    model.present(r) { [model] ok in if ok { model.settle(60) } }
  }

  private var kindName: String {
    ["repo-key": "Repo key", "unlock": "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "terminal": "Terminal", "command": "Command",
     "add-store": "Add a store", "api-call": "API call", "restore": "Restore store"][it.kind] ?? it.kind
  }
  /// the list's title: the action the entry leads to, a fixed name per kind
  private var action: String { it.actionTitle }
  /// what it is about, as values (repo, store, session, length): the router's record, unverified
  private var details: [String] {
    let p = it.params, who = it.sessionName ?? it.session
    switch it.kind {
    case "repo-key":
      let repo = p["repo"].string ?? ""
      return [repo, Checks.repoStore(repo)]
    case "terminal": return [who, it.j["options"]["minutes"].string.map { "\($0) min" }].compactMap { $0 }
    case "add-store": return [it.j["options"]["store"].string, who].compactMap { $0 }
    case "api-call": return [callTarget, p["body"].string].compactMap { $0 }
    case "restore": return [p["store"].string, p["seq"].int.map { "Version \($0)" }].compactMap { $0 }
    default:
      if let r = it.j["options"]["restore"].text { return [r] }
      return [who].compactMap { $0 }
    }
  }
}

/// a batch: one entry, its summary (the caller's words), its items' actions; Review opens the batch page
private struct BatchRow: View {
  @Environment(AppModel.self) private var model
  let b: InboxBatch

  var body: some View {
    Button(action: review) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text("\(b.items.count) requests").font(.headline).foregroundStyle(Color.primary).accessibilityIdentifier("batch-title-\(b.id)")
          Spacer()
          if let p = model.pending["b:" + b.id] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: "Batch", color: .blue) }
        }
        let names = model.batchItems(b).map(\.actionTitle)
        if !names.isEmpty { Text(names.joined(separator: " · ")).font(.subheadline).foregroundStyle(Color.primary).lineLimit(3) }
        HStack(spacing: 12) {
          Label(b.callerText, systemImage: "person")
          if let c = b.created { Label(Fmt.ago(c), systemImage: "clock") }
          if let e = b.expires { Label(Fmt.when(e), systemImage: "hourglass") }
        }
        .font(.footnote).foregroundStyle(Color.secondary).labelStyle(.titleAndIcon)
        if !b.summary.isEmpty {
          Text("“\(b.summary)”").font(.subheadline).italic().foregroundStyle(Color.secondary).lineLimit(3)
            .accessibilityIdentifier("batch-summary-\(b.id)")
        }
      }
    }
    .accessibilityIdentifier("batch-review-\(b.id)")
    .swipeActions {
      Button("Deny all", role: .destructive) { Task { await model.denyBatch(b) } }
    }
    .contextMenu {
      Button("Review", systemImage: "faceid", action: review)
      Button("Deny all", systemImage: "xmark", role: .destructive) { Task { await model.denyBatch(b) } }
    }
  }

  private func review() { model.present(.batch(id: b.id)) { [model] ok in if ok { model.settle(60) } } }
}
