// One session: its status, what waits on it (a grant, a locked store, a queued prompt, schedules), its details, and
// every action Jarvis 1's card had (Terminal or Remote, Pause / Resume, Transcript, Grants, Schedules, the switches,
// the permission mode, Resume with the latest image, Destroy).
import SwiftUI

enum SessionRoute: Hashable { case terminal, remote, transcript, grants, schedules }

struct SessionDetailView: View {
  @Environment(AppModel.self) private var model
  let id: String

  var body: some View {
    if let m = model.session(id) {
      SessionDetailList(m: m)
        .navigationTitle(m.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
          ToolbarItem(placement: .primaryAction) {
            if m.state == "started" && m.hasRemote {
              NavigationLink(value: SessionRoute.remote) { Label("Remote", systemImage: "link") }.accessibilityIdentifier("remote-\(m.id)")
            } else if m.state == "started" || m.state == "initialising" {
              NavigationLink(value: SessionRoute.terminal) { Label("Terminal", systemImage: "terminal") }.accessibilityIdentifier("term-\(m.id)")
            }
          }
          ToolbarItem(placement: .topBarTrailing) {
            Menu("More", systemImage: "ellipsis.circle") { SessionMenu(m: m) }.accessibilityIdentifier("more-\(m.id)")
          }
        }
        .navigationDestination(for: SessionRoute.self) { r in
          switch r {
          case .terminal: TerminalView(sessionId: m.id, title: m.title)
          case .remote: RemoteView(sessionId: m.id, title: m.title)
          case .transcript: TranscriptView(title: m.title, note: "Paused \(m.pausedAt.map(Fmt.ago) ?? "")", path: "api/sessions/\(m.id)/tail",
                                           actionTitle: "Resume", onAction: { Task { await model.resume(m.id) } })
          case .grants: GrantsView(sessionId: m.id)
          case .schedules: SchedulesView(sessionId: m.id)
          }
        }
      .task(id: id) {
        // remember which line this session id is (LinePins), so a later review page can't be handed another's cert
        if CoreTrust.pinned != nil, let c = try? await RouterClient.shared.sessionCert(id) { try? LinePins.check(session: id, line: c.line) }
      }
    } else {
      ContentUnavailableView("Session gone", systemImage: "rectangle.stack.badge.minus", description: Text("It was destroyed or isn't listed any more."))
    }
  }
}

private struct SessionDetailList: View {
  @Environment(AppModel.self) private var model
  let m: Session

  var body: some View {
    let busy = model.pending["s:" + m.id] ?? m.serverBusy
    let p = m.pill
    List {
      Section {
        HStack {
          if let busy { StatusPill(text: busy.lowercased(), color: .orange, spinning: true) } else { StatusPill(text: p.text, color: p.color, spinning: p.spin) }
          if m.permissionMode == "bypass" { StatusPill(text: "skip perms", color: .red) }
          if m.oneShot { StatusPill(text: "one-shot") }
          if m.state != "paused" && m.hasSchedule { StatusPill(text: "scheduled", color: .blue) }
        }
        .accessibilityIdentifier("status-\(m.id)")
        if let info = autoPauseInfo { Text(info).font(.subheadline).foregroundStyle(.secondary) }
        if m.authFailed { ErrorRow(text: "Claude's login failed in this session: the router writes fresh credentials from Jarvis 1 when it can.") }
        if let e = m.error { ErrorRow(text: e, id: "session-error") }
        if let rp = m.resumePrompt {
          Label((m.state == "paused" ? "Prompt queued for the next resume: " : "Prompt queued, delivered once it is up: ") + "“\(Fmt.clip(rp))”", systemImage: "text.bubble")
            .font(.subheadline)
        }
      }

      if let h = m.needsGrant {
        Section {
          Text("The machine turned away \(Holder.title(h).lowercased()) (\(Holder.sub(h).lowercased())).")
          Button("Allow \(Holder.title(h).lowercased()) for 10 minutes", systemImage: "checkmark.shield") { model.requestGrant(m.id, m.title, holder: h) }
            .accessibilityIdentifier("grant-\(m.id)")
          Button("Make a standing rule", systemImage: "calendar.badge.clock") { model.requestGrant(m.id, m.title, holder: h, rule: true) }
            .accessibilityIdentifier("rule-\(m.id)")
        } header: { Label("Needs a grant", systemImage: "hand.raised") }
      }
      if let lock = m.lockedStore {
        Section {
          Text("Waiting for store \(lock) to be unlocked.")
          Button("Unlock…", systemImage: "lock.open") { model.present(.unlock(session: m.id, label: m.title)) }
            .accessibilityIdentifier("unlock-\(m.id)")
        } header: { Label("Locked store", systemImage: "lock") }
      }
      if m.hasSchedule {
        Section("Wakes by itself") {
          ForEach(m.wakeups) { w in
            LabeledContent { Text("“\(Fmt.clip(w.prompt))”") } label: {
              Text("Wakes\(w.name == "default" ? "" : " “\(w.name)”") \(w.at.map(Fmt.when) ?? "")")
            }
          }
          ForEach(m.crons) { c in
            LabeledContent { Text("“\(Fmt.clip(c.prompt))”") } label: {
              Text("Repeats \(Fmt.every(c.everySeconds)), next \(c.nextAt.map(Fmt.when) ?? "")")
            }
          }
        }
      }

      Section {
        if busy == nil {
          if m.state == "started" || m.state == "initialising" {
            Button("Pause", systemImage: "pause.circle") { Task { await model.pause(m.id) } }.accessibilityIdentifier("pause-\(m.id)")
          }
          if m.state == "paused" {
            Button("Resume", systemImage: "play.circle") { Task { await model.resume(m.id) } }.accessibilityIdentifier("resume-\(m.id)")
            NavigationLink(value: SessionRoute.transcript) { Label("Transcript", systemImage: "text.alignleft") }.accessibilityIdentifier("tail-\(m.id)")
          }
        }
        if !["approval", "destroying"].contains(m.state) {
          NavigationLink(value: SessionRoute.grants) { Label("Grants", systemImage: "checkmark.shield") }.accessibilityIdentifier("grants-\(m.id)")
          NavigationLink(value: SessionRoute.schedules) { Label("Schedules", systemImage: "alarm") }.accessibilityIdentifier("schedules-\(m.id)")
        }
        if let ch = m.discordChannel, let u = URL(string: "https://discord.com/channels/1482150592414486748/\(ch)") {
          Link(destination: u) { Label("Discord channel", systemImage: "bubble.left.and.bubble.right") }
        }
      }

      Section("Details") {
        let own = m.stores(policy: model.policy)
        LabeledContent("Stores", value: own.isEmpty ? "none" : own.joined(separator: ", "))
        LabeledContent("Harness", value: Fmt.harness(m.harness))
        if let mo = m.model { LabeledContent("Model", value: model.models.first { $0.id == mo }?.label ?? mo) }
        LabeledContent("Permission mode", value: m.permissionMode == "bypass" ? "bypass (no prompts)" : "auto")
        if let r = m.region { LabeledContent("Region", value: Fmt.region[r] ?? r) }
        let machine = [m.size, m.guest].compactMap { $0 }.joined(separator: " · ")
        if !machine.isEmpty { LabeledContent("Machine", value: machine) }
        if let c = m.created { LabeledContent("Created", value: Fmt.ago(c)) }
        if m.state == "paused", let pa = m.pausedAt { LabeledContent("Paused", value: Fmt.ago(pa)) }
        LabeledContent("Session id") { Text(m.id).font(.footnote.monospaced()).textSelection(.enabled) }
      }

      Section {
        Button("Destroy", systemImage: "trash", role: .destructive) { Task { await model.destroy(m.id) } }
          .disabled(busy != nil || m.state == "destroying")
          .accessibilityIdentifier("destroy-\(m.id)")
      }
    }
    .refreshable { await model.refresh() }
  }

  /// the auto-pause line: off / counting down / generic; a paused session explains Resume
  private var autoPauseInfo: String? {
    if m.state == "paused" { return m.hasSchedule ? "Paused: the router resumes it on schedule; Resume brings it back now." : "Paused: Resume continues the same conversation." }
    if m.oneShot { return m.state == "started" ? "One-shot: archived and destroyed by itself once its prompt is done." : nil }
    guard m.state == "started" else { return nil }
    if !m.autoPause { return "Auto-pause off: stays running while idle." }
    if let ms = m.pauseInMs { return "Pauses in \(max(1, Int((ms / 60000).rounded()))) min if still idle." }
    return "Auto-pauses after 1 h idle."
  }
}
