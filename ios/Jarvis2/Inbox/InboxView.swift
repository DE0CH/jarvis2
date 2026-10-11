// The Inbox: everything waiting for this iPhone's Face ID that was asked for elsewhere (a session, the web page, Claude's
// setup session), and the router's approvals. Each row: the action (what would be signed, in short, from the request's
// kind and arguments; the review page renders the exact text from the signed content), who asked, and their reason.
// Review opens the page for it; Deny (a swipe or the page's button) drops it.
import SwiftUI

struct InboxView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    NavigationStack {
      List {
        if !model.inbox.isEmpty {
          Section {
            ForEach(model.inbox) { it in InboxRow(it: it) }
          } header: {
            Text(model.inbox.count == 1 ? "1 request" : "\(model.inbox.count) requests")
          } footer: {
            Text("Asked for by sessions, the web page or Claude. Review shows exactly what you would sign; nothing happens until you allow it with Face ID.")
          }
        }
      }
      .overlay {
        if model.inbox.isEmpty {
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

  var body: some View {
    Button(action: review) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text(action).font(.headline).foregroundStyle(Color.primary).accessibilityIdentifier("request-title-\(it.id)")
          Spacer()
          if let p = model.pending["q:" + it.id] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: kindName, color: .blue) }
        }
        Text("From \(it.callerText)\(it.created.map { " · " + Fmt.ago($0) } ?? "")").font(.subheadline).foregroundStyle(Color.secondary)
        Text(it.callLine).font(.caption.monospaced()).foregroundStyle(Color.secondary).lineLimit(2)
        if !it.explanation.isEmpty {
          Text("“\(it.explanation)”").font(.subheadline).italic().foregroundStyle(Color.secondary).lineLimit(2)
            .accessibilityIdentifier("request-reason-\(it.id)")
        }
        if let e = it.expires { Text("Goes away \(Fmt.when(e)) if not answered").font(.footnote).foregroundStyle(Color.secondary) }
      }
    }
    .accessibilityIdentifier("request-review-\(it.id)")
    .swipeActions {
      Button("Deny", role: .destructive) { Task { await model.deny(it) } }
    }
    .contextMenu {
      Button("Review", systemImage: "faceid", action: review)
      Button("Deny", systemImage: "xmark", role: .destructive) { Task { await model.deny(it) } }
    }
  }

  private func review() {
    guard let r = SecureRequest.fromInbox(it) else { model.say("This request can't be opened here."); return }
    model.present(r) { [model] ok in if ok { model.settle(60) } }
  }

  private var kindName: String {
    ["repo-key": "Repo key", "grant": "Grant", "unlock": "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "add-store": "Add a store"][it.kind] ?? it.kind
  }
  /// the list's title: the core action (or the phone grant) the entry leads to
  private var action: String {
    let p = it.params, who = it.sessionName.map { "“\($0)”" } ?? it.session ?? "?"
    switch it.kind {
    case "repo-key":
      let repo = p["repo"].string ?? ""
      return p["action"].string == "remove" ? "Delete the deploy key and store \(Checks.repoStore(repo)) of \(repo)"
        : "Make a deploy key for \(repo) (read + push), kept in store \(Checks.repoStore(repo))\(p["sensitive"].bool == true ? " (sensitive)" : "")"
    case "grant":
      let h = Holder.title(p["holder"].string ?? "")
      if let d = p["days"].int, d > 0 { return "Standing rule: \(h) in \(who) for \(d) days" }
      return "Allow \(h) in \(who) for \(p["minutes"].int ?? 10) minutes"
    case "unlock":
      return "Unlock the stores \(who) is waiting on"
    case "add-store":
      return "Add store \(it.j["options"]["store"].string ?? "?") to \(who)"
    case "resume-upgrade":
      return "Resume \(who) on the latest image"
    default:
      if let r = it.j["options"]["restore"].text { return "Restore \(r)" }
      return "New session \(who)"
    }
  }
}
