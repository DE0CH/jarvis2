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
          case .transcript: TranscriptView(title: m.title, noteLabel: "Paused", noteValue: m.pausedAt.map(Fmt.ago) ?? "", path: "api/sessions/\(m.id)/tail",
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
        if let info = autoPauseInfo { LabeledContent(info.label, value: info.value).accessibilityIdentifier("autopause-\(m.id)") }
        if m.authFailed { ErrorRow(text: "Claude login failed") }
        if let e = m.error { ErrorRow(text: e, id: "session-error") }
        if let rp = m.resumePrompt {
          VStack(alignment: .leading, spacing: 2) {
            Label(m.state == "paused" ? "Queued for the next resume" : "Queued until it is up", systemImage: "text.bubble").font(.footnote).foregroundStyle(.secondary)
            Text(Fmt.clip(rp, 200)).font(.subheadline)
          }
          .accessibilityElement(children: .combine)
        }
      }

      if let a = m.memAlert { MemAlertSection(m: m, a: a, busy: busy) }
      if let a = m.diskAlert { DiskAlertSection(m: m, a: a, busy: busy) }
      if m.snapshotFailed != nil || m.noSnapshot != nil { SnapshotProblemSection(m: m, busy: busy) }

      if let h = m.needsGrant {
        Section {
          LabeledContent("Feature", value: Holder.title(h)).accessibilityIdentifier("turned-away-\(m.id)")
          LabeledContent("Allows", value: Holder.sub(h))
          LabeledContent("Why", value: "The session holds a sensitive store, so Jarvis can't do this without your approval.")
          Button("Allow for 10 minutes", systemImage: "checkmark.shield") { model.requestGrant(m.id, m.title, holder: h) }
            .accessibilityIdentifier("grant-\(m.id)")
          Button("Make a standing rule", systemImage: "calendar.badge.clock") { model.requestGrant(m.id, m.title, holder: h, rule: true) }
            .accessibilityIdentifier("rule-\(m.id)")
        } header: { Label("Needs your approval", systemImage: "hand.raised") }
      }
      if let lock = m.lockedStore {
        Section {
          LabeledContent("Store") { Text(lock).font(.body.monospaced()) }
          Button("Unlock…", systemImage: "lock.open") { model.present(.unlock(session: m.id, label: m.title)) }
            .accessibilityIdentifier("unlock-\(m.id)")
        } header: { Label("Waiting on a locked store", systemImage: "lock") }
      }
      if m.hasSchedule {
        Section("Wakes by itself") {
          ForEach(m.wakeups) { w in
            WakeRow(symbol: "alarm", when: w.at.map(Fmt.when) ?? "", name: w.name == "default" ? nil : w.name, prompt: w.prompt)
          }
          ForEach(m.crons) { c in
            WakeRow(symbol: "repeat", when: Fmt.every(c.everySeconds), name: c.name, prompt: c.prompt, next: c.nextAt.map(Fmt.when))
          }
        }
      }

      Section {
        if busy == nil {
          if m.state == "started" || m.state == "initialising" {
            Button("Pause", systemImage: "pause.circle") { Task { await model.pause(m.id) } }.accessibilityIdentifier("pause-\(m.id)")
          }
          if m.resumable {
            Button("Resume", systemImage: "play.circle") { Task { await model.resume(m.id) } }.accessibilityIdentifier("resume-\(m.id)")
          }
          if m.state == "paused" {
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
        if m.state == "started", let mem = m.memory {
          LabeledContent("Memory", value: "\(Fmt.bytes(mem.availMb * 1_048_576)) free of \(Fmt.bytes(mem.totalMb * 1_048_576))")
            .accessibilityIdentifier("memory-\(m.id)")
        }
        if m.state == "started", let d = m.disk {
          LabeledContent(d.volume ? "Disk (volume)" : "Disk", value: "\(Fmt.bytes(d.availMb * 1_048_576)) free of \(Fmt.bytes(d.totalMb * 1_048_576))")
            .accessibilityIdentifier("disk-\(m.id)")
        }
        if m.diskGB > 0 { LabeledContent("Next machine's disk", value: "\(m.diskGB) GB") }
        if let c = m.created { LabeledContent("Created", value: Fmt.ago(c)) }
        if m.state == "paused", let pa = m.pausedAt { LabeledContent("Paused", value: Fmt.ago(pa)) }
        LabeledContent("Session id") { Text(m.id).font(.footnote.monospaced()).textSelection(.enabled) }
      }

      if !m.backups.isEmpty { BackupsSection(m: m) }

      Section {
        Button("Destroy", systemImage: "trash", role: .destructive) { Task { await model.destroy(m.id) } }
          .disabled(busy != nil || m.state == "destroying")
          .accessibilityIdentifier("destroy-\(m.id)")
      }
    }
    .refreshable { await model.refresh() }
  }

  /// the auto-pause line: off / counting down / generic; a paused session explains Resume
  /// what happens to it when idle, as one labelled row
  private var autoPauseInfo: (label: String, value: String)? {
    if m.oneShot { return m.state == "started" ? ("When done", "Archived and destroyed") : nil }
    guard m.state == "started" else { return nil }
    if !m.autoPause { return ("Auto-pause", "Off") }
    if let ms = m.pauseInMs { return ("Auto-pause", "In \(max(1, Int((ms / 60000).rounded()))) min") }
    return ("Auto-pause", "After 1 h idle")
  }
}

/// a memory-starvation episode: why, the memory now, and Upgrade (the next size up, same conversation)
private struct MemAlertSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let a: MemAlert
  let busy: String?

  var body: some View {
    Section {
      Label("Running out of memory", systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.red).font(.subheadline.weight(.semibold))
        .accessibilityIdentifier("memalert-\(m.id)")
      LabeledContent("Why", value: a.reason)
      if let d = a.detail { LabeledContent("Now", value: d) }
      if let since = a.since { LabeledContent("Since", value: Fmt.ago(since)) }
      if busy == nil, m.wakeKind == "upgrade", m.wakePhase == "failed" {
        ErrorRow(text: "Upgrade failed" + (m.wakeError.map { ": \($0)" } ?? ""), id: "upgrade-error-\(m.id)")
      }
      if a.nextSize != nil, busy == nil {
        Button(Fmt.upgradeTitle(a), systemImage: "arrow.up.circle") { Task { await model.upgrade(m.id) } }
          .tint(.red)
          .accessibilityIdentifier("upgrade-\(m.id)")
      }
    } header: {
      Label("Memory", systemImage: "memorychip")
    } footer: {
      if a.nextSize != nil { Text("Upgrade stops Claude and everything it runs, then brings the same conversation back on the bigger machine" + (a.nextGuest.map { " (\($0))" } ?? "") + ".") }
    }
  }
}

/// a low-disk episode: the disk now, and More disk (the volume twice as big, same conversation)
private struct DiskAlertSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let a: DiskAlert
  let busy: String?

  var body: some View {
    Section {
      Label("Running out of disk", systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.red).font(.subheadline.weight(.semibold))
        .accessibilityIdentifier("diskalert-\(m.id)")
      LabeledContent("Why", value: a.reason)
      if let d = a.detail { LabeledContent("Now", value: d) }
      if let since = a.since { LabeledContent("Since", value: Fmt.ago(since)) }
      if busy == nil, m.wakeKind == "disk", m.wakePhase == "failed" {
        ErrorRow(text: "More disk failed" + (m.wakeError.map { ": \($0)" } ?? ""), id: "disk-error-\(m.id)")
      }
      if a.canGrow, let gb = a.nextGB, busy == nil, m.state == "started" {
        Button("More disk (\(gb) GB)", systemImage: "externaldrive.badge.plus") { Task { await model.moreDisk(m.id) } }
          .tint(.red)
          .accessibilityIdentifier("moredisk-\(m.id)")
      } else if let why = a.why {
        LabeledContent("More disk", value: why)
      }
    } header: {
      Label("Disk", systemImage: "internaldrive")
    }
  }
}

/// the final snapshot failed (machine kept), or the line's last machine left none (Resume refused)
private struct SnapshotProblemSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let busy: String?

  var body: some View {
    Section {
      if let f = m.snapshotFailed {
        ErrorRow(text: f, id: "snapshot-failed-\(m.id)")
        LabeledContent("Machine", value: "Kept")
        if busy == nil, m.state == "failed" {
          Button("Pause again", systemImage: "pause.circle") { Task { await model.pause(m.id) } }
            .accessibilityIdentifier("pause-again-\(m.id)")
        }
      }
      if let n = m.noSnapshot {
        ErrorRow(text: n, id: "no-snapshot-\(m.id)")
        LabeledContent("Resume", value: "Refused")
        if let b = m.backups.first {
          LabeledContent("Volume backup") { Text(b.snapshot).font(.footnote.monospaced()).textSelection(.enabled) }
          if let e = b.expiresAt { LabeledContent("Kept until", value: e.formatted(date: .abbreviated, time: .omitted)) }
        } else {
          LabeledContent("Volume backup", value: "None")
        }
      }
    } header: {
      Label(m.snapshotFailed != nil ? "Final snapshot failed" : "No snapshot", systemImage: "externaldrive.badge.exclamationmark")
        .foregroundStyle(.red)
    }
  }
}

/// the core's Fly volume backups of this line's machines, newest first: for recovery by hand, nothing restores them
private struct BackupsSection: View {
  @Environment(AppModel.self) private var model
  let m: Session

  var body: some View {
    Section {
      ForEach(m.backups) { b in
        VStack(alignment: .leading, spacing: 4) {
          LabeledContent("Snapshot") { Text(b.snapshot).font(.footnote.monospaced()).textSelection(.enabled) }
          LabeledContent("Volume") { Text(b.volume).font(.footnote.monospaced()).textSelection(.enabled) }
          if let at = b.at { LabeledContent("Taken", value: Fmt.ago(at)) }
          if let e = b.expiresAt { LabeledContent("Kept until", value: e.formatted(date: .abbreviated, time: .omitted)) }
          LabeledContent("Machine's own snapshot", value: b.signed ? "Yes" : "No")
          if let n = b.sizeBytes, n > 0 { LabeledContent("Size", value: Fmt.bytes(n)) }
        }
        .contextMenu {
          Button("Copy snapshot id", systemImage: "doc.on.doc") { model.copy(b.snapshot, "Snapshot id") }
          Button("Copy volume id", systemImage: "doc.on.doc") { model.copy(b.volume, "Volume id") }
        }
        .accessibilityIdentifier("backup-\(b.snapshot)")
      }
    } header: {
      Label("Volume backups", systemImage: "externaldrive.badge.timemachine")
    } footer: {
      Text("Fly volume snapshots the core took at each pause, for recovery by hand.")
    }
  }
}
