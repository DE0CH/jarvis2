// Sessions: the list (grouped Running / Scheduled / Paused / Failed, newest first) beside the selected session's
// detail on iPad, a stack on iPhone. + starts a new session on the New session sheet; Previous lists the destroyed.
import SwiftUI

struct SessionsView: View {
  @Environment(AppModel.self) private var model
  @State private var selected: String?
  @State private var showPrevious = false

  private var list: [Session] {
    model.sessions.filter { !$0.isTaskLine }
      .sorted { ($0.created ?? .distantPast, $0.id) > ($1.created ?? .distantPast, $1.id) }
  }

  var body: some View {
    NavigationSplitView {
      SessionList(sessions: list, selected: $selected)
        .navigationTitle("Sessions")
        .toolbar {
          ToolbarItem(placement: .primaryAction) {
            Button("New session", systemImage: "plus", action: newSession).accessibilityIdentifier("newBtn")
          }
          ToolbarItem(placement: .topBarLeading) {
            Button("Previous", systemImage: "archivebox") { showPrevious = true }.accessibilityIdentifier("previousBtn")
          }
        }
        .navigationDestination(isPresented: $showPrevious) { PreviousView() }
    } detail: {
      NavigationStack {
        if let id = selected, model.session(id) != nil {
          SessionDetailView(id: id)
        } else {
          ContentUnavailableView("No session selected", systemImage: "rectangle.stack", description: Text("Pick a session, or start a new one with +."))
        }
      }
    }
    .onChange(of: model.sessions) { _, s in if let id = selected, !s.contains(where: { $0.id == id }) { selected = nil } }
  }

  private func newSession() {
    model.present(.newSession) { [model] ok in if ok { model.settle(120) } }
  }
}

private struct SessionList: View {
  @Environment(AppModel.self) private var model
  let sessions: [Session]
  @Binding var selected: String?

  var body: some View {
    List(selection: $selected) {
      Banners()
      if !model.inbox.isEmpty {
        Section {
          Button { model.tab = .inbox } label: {
            Label(model.inbox.count == 1 ? "1 request waiting in the Inbox" : "\(model.inbox.count) requests waiting in the Inbox", systemImage: "tray.full")
          }
          .accessibilityIdentifier("inbox-note")
        }
      }
      ForEach(["Running", "Scheduled", "Paused", "Failed"], id: \.self) { g in
        let inGroup = sessions.filter { $0.group == g }
        if !inGroup.isEmpty {
          Section(g) {
            ForEach(inGroup) { m in
              SessionRow(m: m).tag(m.id)
            }
          }
        }
      }
      FlyAccountSection()
    }
    .overlay {
      if model.loaded && sessions.isEmpty {
        ContentUnavailableView {
          Label("No sessions", systemImage: "rectangle.stack")
        } description: {
          Text("Start one with +.")
        }
      } else if !model.loaded && model.loadError == nil {
        ProgressView("Loading…")
      }
    }
    .refreshable { await model.refresh() }
  }
}

/// what is wrong right now, above the list
private struct Banners: View {
  @Environment(AppModel.self) private var model
  var body: some View {
    let dead = model.sessions.filter(\.authFailed)
    let b = model.budget
    if model.loadError != nil || (model.loaded && !model.coreUp) || !dead.isEmpty || b["capped"].bool == true || b["warned"].bool == true || model.fly["error"].text.map({ $0 != "FLY_READ_TOKEN not set" }) == true {
      Section {
        if let e = model.loadError { ErrorRow(text: "Can't reach the router: \(e)", id: "banner-router") }
        if model.loaded && !model.coreUp {
          Label("The core is not answering: sessions can't be created, resumed or approved until it is back.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
        }
        if !dead.isEmpty {
          ErrorRow(text: "Claude's login failed in \(dead.count == 1 ? "“\(dead[0].title)”" : "\(dead.count) sessions"). The router writes Jarvis 1's credentials into a session whose login expired; if this stays, re-login in Jarvis 1's Settings.", id: "banner-creds")
        }
        if b["capped"].bool == true {
          ErrorRow(text: "Fly spend reached the \(Fmt.usd(b["capUsd"].double ?? 0)) cap for \(b["month"].string ?? "this month") (\(Fmt.usd(b["spentUsd"].double ?? 0))): the router paused every running session.", id: "banner-budget")
        } else if b["warned"].bool == true {
          Label("Fly spend this month: \(Fmt.usd(b["spentUsd"].double ?? 0)) of the \(Fmt.usd(b["capUsd"].double ?? 0)) cap. At the cap every running session is paused.", systemImage: "dollarsign.circle").foregroundStyle(.orange)
            .accessibilityIdentifier("banner-budget")
        }
        if let e = model.fly["error"].text, e != "FLY_READ_TOKEN not set" { ErrorRow(text: "Fly: \(e)") }
      }
    }
  }
}

struct SessionRow: View {
  @Environment(AppModel.self) private var model
  let m: Session

  var body: some View {
    let busy = model.pending["s:" + m.id] ?? m.serverBusy
    let p = m.pill
    VStack(alignment: .leading, spacing: 4) {
      HStack(alignment: .firstTextBaseline) {
        Text(m.title).font(.headline).lineLimit(2)
        Spacer(minLength: 8)
        if let busy { StatusPill(text: busy.lowercased(), color: .orange, spinning: true) } else { StatusPill(text: p.text, color: p.color, spinning: p.spin) }
      }
      Text(line1).font(.subheadline).foregroundStyle(.secondary).lineLimit(2)
      if let lock = m.lockedStore {
        Label("Waiting for store \(lock) to be unlocked", systemImage: "lock").font(.footnote).foregroundStyle(.orange)
      } else if let g = m.needsGrant {
        Label("Turned away \(Holder.title(g).lowercased())", systemImage: "hand.raised").font(.footnote).foregroundStyle(.orange)
      }
    }
    .padding(.vertical, 2)
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("srow-\(m.id)")
    .swipeActions(edge: .leading) {
      if busy == nil {
        if m.state == "started" || m.state == "initialising" {
          Button("Pause", systemImage: "pause") { Task { await model.pause(m.id) } }.tint(.orange)
        } else if m.state == "paused" {
          Button("Resume", systemImage: "play") { Task { await model.resume(m.id) } }.tint(.green)
        }
      }
    }
    .swipeActions(edge: .trailing) {
      if busy == nil, m.state != "destroying" {
        Button("Destroy", systemImage: "trash", role: .destructive) { Task { await model.destroy(m.id) } }
      }
    }
    .contextMenu { SessionMenu(m: m) }
  }

  private var line1: String {
    let own = m.stores(policy: model.policy)
    let modelName = model.models.first { $0.id == m.model }?.label ?? m.model
    var parts = [own.isEmpty ? "no stores" : "stores: " + own.joined(separator: ", "), Fmt.harness(m.harness)]
    if let modelName { parts.append(modelName) }
    if m.permissionMode == "bypass" { parts.append("skip perms") }
    if m.oneShot { parts.append("one-shot") }
    return parts.joined(separator: " · ")
  }
}

/// More: the same actions in a row's context menu and the detail's toolbar menu
struct SessionMenu: View {
  @Environment(AppModel.self) private var model
  let m: Session
  var body: some View {
    let live = !["approval", "destroying"].contains(m.state)
    if !m.oneShot && live {
      Button { Task { await model.toggle(m, "auto-pause", on: !m.autoPause) } } label: {
        Label("Auto-pause when idle", systemImage: m.autoPause ? "checkmark" : "pause.circle")
      }
    }
    if live {
      Button { Task { await model.toggle(m, "notify-idle", on: !m.notifyIdle) } } label: {
        Label("Idle notifications", systemImage: m.notifyIdle ? "checkmark" : "bell")
      }
    }
    if m.state == "started" || m.state == "paused" {
      if m.permissionMode == "bypass" {
        Button("Switch to auto mode", systemImage: "shield") { Task { await model.switchMode(m, to: "auto") } }
      } else {
        Button("Switch to bypass mode", systemImage: "shield.slash") { Task { await model.switchMode(m, to: "bypass") } }
      }
    }
    if m.state == "paused" {
      Button("Resume with latest image", systemImage: "arrow.up.circle") { Task { await model.resumeLatest(m.id) } }
    }
    Button("Copy session id", systemImage: "doc.on.doc") { model.copy(m.id, "Session id") }
    Divider()
    Button("Destroy", systemImage: "trash", role: .destructive) { Task { await model.destroy(m.id) } }
  }
}

/// Everything on the Fly app that is not one of the sessions above (view only), and a summary line that SAYS when
/// nothing else is there
private struct FlyAccountSection: View {
  @Environment(AppModel.self) private var model
  var body: some View {
    let fly = model.fly
    if !fly.isNull {
      let other = fly["other"].array
      Section {
        ForEach(Array(other.enumerated()), id: \.offset) { _, o in
          VStack(alignment: .leading, spacing: 2) {
            HStack {
              Text(o["name"].text ?? o["id"].string ?? "").font(.headline)
              Spacer()
              StatusPill(text: o["state"].text ?? o["kind"].string ?? "", color: o["state"].string == "started" || o["kind"].string == "volume" ? .orange : .secondary)
            }
            Text([o["kind"].string ?? "", "app " + (o["app"].string ?? ""), o["detail"].text, o["region"].text.map { Fmt.region[$0] ?? $0 }].compactMap { $0 }.joined(separator: " · "))
              .font(.footnote).foregroundStyle(.secondary)
          }
        }
      } header: {
        if !other.isEmpty { Text("Also on Fly") }
      } footer: {
        Text(fly["error"].text.map { "Could not check the Fly app: \($0)" }
             ?? "Fly: \(Fmt.plural(fly["machines"].int ?? 0, "machine")) · \(Fmt.plural(fly["volumes"].int ?? 0, "volume")) — \(other.isEmpty ? "nothing outside the sessions" : "\(Fmt.plural(other.count, "item")) outside the sessions").")
          .accessibilityIdentifier("fly-summary")
      }
    }
  }
}
