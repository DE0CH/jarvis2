// What the app's buttons do, ported from the React Native app (lib/*, views/*): each runs under its session's (or
// record's, task's) key, asks first where Jarvis 1 asked, and keeps its pending label until the router confirms.
import Foundation
import UIKit

extension AppModel {
  // ---- sessions ----
  func pause(_ id: String) async {
    await pendUntil("s:" + id, "Pausing…", 120, action: { try await RouterClient.shared.call("POST", "api/sessions/\(id)/pause") },
                    until: { ["paused", "failed"].contains($0.session(id)?.state ?? "") })
  }

  /// Resume with an optional prompt (typed into the conversation once it is up). A resume with a prompt is a new source
  /// the phone signs (resume-upgrade): its approval opens by itself; one with no change needs no phone.
  func resume(_ id: String) async {
    await exclusive("s:" + id) {
      let t = session(id)?.title ?? id
      guard let prompt = await ask("Resume “\(t)”?", "Same conversation and files on a new machine.",
                                   action: "Resume", input: ("Prompt (optional)", nil)) else { return }
      pend("s:" + id, "Resuming…")
      defer { pend("s:" + id, nil) }
      do {
        var body: [String: Any] = ["upgrade": false]
        if !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { body["prompt"] = prompt.trimmingCharacters(in: .whitespacesAndNewlines) }
        try await RouterClient.shared.call("POST", "api/sessions/\(id)/resume", body)
        var found: Approval?
        await refreshUntil(120) { m in
          found = m.approvals.first { $0.kind == "resume-upgrade" && $0.session == id }
          return found != nil || ["started", "initialising", "failed"].contains(m.session(id)?.state ?? "")
        }
        if let a = found { present(.approval(id: a.id)) }
        settle(30)
      } catch { fail(error); await refresh() }
    }
  }

  /// resume on the newest image: the router asks for an approval first, which opens by itself
  func resumeLatest(_ id: String) async {
    await exclusive("s:" + id) {
      let t = session(id)?.title ?? id
      guard await confirm("Resume “\(t)” with the latest image?", "The old machine can never come back as it was.", action: "Resume with latest image") else { return }
      pend("s:" + id, "Resuming…")
      defer { pend("s:" + id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/sessions/\(id)/resume", ["upgrade": true])
        var found: Approval?
        await refreshUntil(90) { m in
          found = m.approvals.first { $0.kind == "resume-upgrade" && $0.session == id }
          return found != nil || m.session(id)?.state == "failed"
        }
        if let a = found { present(.approval(id: a.id)) } else { say("Approve it in the Inbox") }
      } catch { fail(error) }
    }
  }

  /// Upgrade out of a memory-starvation episode: the router stops Claude and what it started, snapshots, and brings the
  /// same conversation back on the next size up (POST …/upgrade). No question first: one tap, as Jarvis 1's card
  /// (Deyao, 2026-10-10); the notice says what it does. The pending label holds until the session is up on the new
  /// size or the job failed; after that the router's own busy label shows it on every device.
  func upgrade(_ id: String) async {
    guard let next = session(id)?.memAlert?.nextSize else { return }
    await exclusive("s:" + id) {
      pend("s:" + id, "Upgrading…")
      defer { pend("s:" + id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/sessions/\(id)/upgrade", [:])
        await refreshUntil(60) { m in
          guard let x = m.session(id) else { return true }
          return x.serverBusy == nil && ((x.state == "started" && x.size == next) || (x.wakeKind == "upgrade" && x.wakePhase == "failed"))
        }
        if let x = session(id), x.serverBusy == nil, x.wakeKind == "upgrade", x.wakePhase == "failed" {
          failure = "Upgrade failed" + (x.wakeError.map { ": \($0)" } ?? "")
        }
        settle(120)
      } catch { fail(error); await refresh() }
    }
  }

  /// what a destroy would lose (GET …/changes: uncommitted and unpushed work), in words
  /// what a destroy would lose, one line per fact: "Claude is working", "repo · 2 uncommitted · 1 unpushed"
  private func changesText(_ id: String) async -> String {
    var lines: [String] = []
    do {
      let c = try await RouterClient.shared.get("api/sessions/\(id)/changes")
      if c["checked"].bool == true {
        let dirty = c["repos"].array.filter { ($0["uncommitted"].int ?? 0) > 0 || ($0["unpushed"].int ?? 0) != 0 }
        if c["status"].string == "busy" { lines.append("Claude is working") }
        for r in dirty {
          var parts = [r["name"].string ?? "?"]
          if let u = r["uncommitted"].int, u > 0 { parts.append("\(u) uncommitted") }
          if let p = r["unpushed"].int, p > 0 { parts.append("\(p) unpushed") } else if r["unpushed"].int == -1 { parts.append("no upstream") }
          lines.append(parts.joined(separator: " · "))
        }
        if dirty.isEmpty && c["status"].string != "busy" { lines.append(c["paused"].bool == true ? "No unsaved changes (when paused)" : "No unsaved changes") }
      } else {
        lines.append("Changes not checked: " + (c["reason"].string ?? "unknown"))
      }
    } catch { lines.append("Changes not checked: " + errText(error)) }
    return lines.joined(separator: "\n")
  }

  /// Destroy: what would be lost first, then the router pauses (final snapshot), archives and burns the line; a
  /// failed archive asks whether to destroy anyway
  func destroy(_ id: String) async {
    await exclusive("s:" + id) {
      pend("s:" + id, "Checking…")
      let t = session(id)?.title ?? id
      let msg = await changesText(id) + "\n\nArchived first, then gone for good."
      pend("s:" + id, nil)
      guard await confirm("Destroy “\(t)”?", msg, action: "Destroy session", destructive: true) else { return }
      pend("s:" + id, "Destroying…")
      defer { pend("s:" + id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/sessions/\(id)/destroy")
        await refreshUntil(15 * 60) { m in
          guard let x = m.session(id) else { return true }
          return x.state != "destroying" && (x.error?.hasPrefix("archive:") ?? false)
        }
        if let x = session(id), let e = x.error, e.hasPrefix("archive:") {
          if await confirm("Archiving to the Storage Box failed", e, action: "Destroy anyway", destructive: true) {
            try await RouterClient.shared.call("POST", "api/sessions/\(id)/destroy?force=1")
            await refreshUntil(10 * 60) { $0.session(id) == nil }
          }
        }
      } catch { fail(error); await refresh() }
    }
  }

  // ---- add-ons (docs/DESIGN.md "Adding to a running machine"): each an approval of two certs, under one Face ID ----
  /// a terminal for 10 minutes (typing, resizing, the remote page, the changes check): filed, then its approval opens;
  /// `done` once it closes (true = signed)
  func requestTerminal(_ m: Session, done: ((Bool) -> Void)? = nil) async {
    await exclusive("t:" + m.id) {
      do {
        let id = try await RouterClient.shared.requestAddOn("terminal", ["session": m.id, "minutes": 10])
        present(.approval(id: id)) { [weak self] ok in
          if ok { self?.say("Terminal open for 10 minutes") }
          done?(ok)
        }
      } catch { fail(error); done?(false) }
    }
  }
  /// another store for a running session (merged onto its main grant, then unlocked under the same Face ID)
  func requestAddStore(_ m: Session, store: String) async {
    await exclusive("t:" + m.id) {
      do {
        let id = try await RouterClient.shared.requestAddOn("add-store", ["session": m.id, "store": store])
        present(.approval(id: id)) { [weak self] ok in if ok { self?.say("Store \(store) added") } }
      } catch { fail(error) }
    }
  }
  /// drop stores a running session no longer needs: its main grant moved along its identity edge (no Face ID: it only
  /// narrows)
  func narrow(_ m: Session, keep: [String], dropping: [String]) async {
    guard await confirm("Drop \(dropping.joined(separator: ", ")) from “\(m.title)”?", "The session keeps \(keep.isEmpty ? "no stores" : keep.joined(separator: ", ")).",
                        action: "Drop", destructive: true) else { return }
    await pendUntil("s:" + m.id, "Dropping…", 30, action: { _ = try await RouterClient.shared.narrow(m.id, keep: keep) },
                    until: { m2 in Set(m2.session(m.id)?.j["stores"].strings ?? []).isDisjoint(with: dropping) })
  }

  /// Auto-pause when idle / Idle notifications: two-phase, the menu shows the router's value
  func toggle(_ m: Session, _ what: String, on: Bool) async {
    await pendUntil("s:" + m.id, on ? "Turning on…" : "Turning off…", 20,
                    action: { try await RouterClient.shared.call("POST", "api/sessions/\(m.id)/\(what)", ["on": on]) },
                    until: { m2 in
                      guard let x = m2.session(m.id) else { return true }
                      return (what == "auto-pause" ? x.autoPause : x.notifyIdle) == on
                    })
  }

  func copy(_ text: String, _ what: String) {
    UIPasteboard.general.string = text
    say("Copied")
  }

  // ---- previous sessions ----
  /// a new line whose first machine restores the archived snapshot; the iPhone approves it like a new session
  func restore(_ r: Rec) async {
    await exclusive("r:" + r.id) {
      guard await confirm("Restore “\(r.title)”?", r.restoredCount > 0 ? "Restored before: this starts another copy." : "A new session from the archived snapshot.", action: "Restore") else { return }
      pend("r:" + r.id, "Restoring…")
      defer { pend("r:" + r.id, nil) }
      do {
        let j = try await RouterClient.shared.call("POST", "api/records/\(r.id)/restore", ["requestId": CoreCrypto.nonce()])
        let sid = j["id"].string ?? ""
        var found: Approval?
        await refreshUntil(60) { m in
          found = m.approvals.first { $0.session == sid }
          return found != nil || m.sessions.contains { $0.id == sid && $0.state != "approval" }
        }
        if let a = found { tab = .sessions; present(.approval(id: a.id)) } else { say("Approve it in the Inbox") }
        settle(120)
      } catch { fail(error) }
      await loadRecords()
    }
  }

  /// off the list (the archive stays), or for good (the archive too; the title is typed first)
  func removeRecord(_ r: Rec, purge: Bool) async {
    await exclusive("r:" + r.id) {
      if purge {
        let msg = "Its archive goes too. Type the title to confirm."
        guard await ask("Delete “\(r.title)” permanently?", msg, action: "Delete permanently", destructive: true, input: (r.title, r.title)) != nil else { return }
      } else {
        guard await confirm("Remove “\(r.title)” from the list?", "Its archive stays.", action: "Remove", destructive: true) else { return }
      }
      pend("r:" + r.id, purge ? "Deleting…" : "Removing…")
      defer { pend("r:" + r.id, nil) }
      do {
        let id = r.id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? r.id
        try await RouterClient.shared.call("DELETE", "api/records/\(id)\(purge ? "?purge=1" : "")")
        say(purge ? "Deleted" : "Removed")
      } catch { fail(error) }
      await loadRecords()
    }
  }

  // ---- the Inbox ----
  func deny(_ it: InboxItem) async {
    await pendUntil("q:" + it.id, "Denying…", 30, action: { try await RouterClient.shared.inboxDeny(it.id) },
                    until: { m in !m.inbox.contains { $0.id == it.id } })
  }

  /// an API call a session's actions asked for: run now as Deyao. No Face ID: Face ID signs only what the kernel
  /// verifies, and a call that needs that asks for it itself afterwards.
  func approveCall(_ it: InboxItem) async {
    var outcome: JSON?
    await pendUntil("q:" + it.id, "Running…", 30, action: { outcome = try await RouterClient.shared.inboxApproveCall(it.id) },
                    until: { m in !m.inbox.contains { $0.id == it.id } })
    guard let o = outcome else { return }
    let line = "\(it.params["method"].string ?? "") \(it.params["path"].string ?? "")"
    if o["ok"].bool == true { say("Ran \(line): HTTP \(o["status"].int ?? 0)") } else { say(o["error"].string ?? "The call didn't run") }
  }

  func denyBatch(_ b: InboxBatch) async {
    await pendUntil("b:" + b.id, "Denying…", 30, action: { try await RouterClient.shared.inboxDenyBatch(b.id) },
                    until: { m in !m.inboxBatches.contains { $0.id == b.id } })
  }

  // ---- tasks ----
  /// wait for the approval the router made for this line and open it
  func openApproval(for session: String?, kind: String? = nil) async {
    guard let session else { return }
    var found: Approval?
    await refreshUntil(60) { m in
      found = m.approvals.first { $0.session == session && (kind == nil || $0.kind == kind) }
      return found != nil
    }
    if let a = found { present(.approval(id: a.id)) } else { say("Approve it in the Inbox") }
  }
  /// reload tasks until `pred` holds (two-phase)
  func pendTasks(_ key: String, _ label: String, _ seconds: Double = 20, action: () async throws -> Void, until pred: (TasksOverview) -> Bool) async {
    await exclusive(key) {
      pend(key, label)
      defer { pend(key, nil) }
      do {
        try await action()
        let until = Date.now.addingTimeInterval(seconds)
        while Date.now < until {
          await loadTasks()
          if pred(tasks) { break }
          try? await Task.sleep(for: .seconds(1))
        }
      } catch { fail(error); await loadTasks() }
    }
  }
  /// Run now; on the latest image the phone approves the newer image first (it opens by itself)
  func runTask(_ id: String, upgrade: Bool = false) async {
    var name = ""
    await pendTasks("task:" + id, upgrade ? "Asking the phone…" : "Starting…", action: {
      name = try await RouterClient.shared.call("POST", "api/tasks/instances/\(id)/run", upgrade ? ["upgrade": true] : [:])["name"].string ?? ""
    }, until: { d in d.instances.contains { $0.id == id && ($0.queued > 0 || $0.activeRun?.name == name || $0.lastRun?.name == name) } })
    if upgrade { await openApproval(for: tasks.instances.first { $0.id == id }?.session, kind: "resume-upgrade") }
  }
  /// a new line for a task whose line is gone or failed (the phone approves it)
  func reapprove(_ inst: TaskInstance) async {
    await exclusive("task:" + inst.id) {
      pend("task:" + inst.id, "Asking the phone…")
      defer { pend("task:" + inst.id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/tasks/instances/\(inst.id)/approve")
        await loadTasks()
        await openApproval(for: tasks.instances.first { $0.id == inst.id }?.session, kind: "new-session")
      } catch { fail(error) }
    }
  }
  func setSchedule(_ s: TaskSchedule, enabled on: Bool) async {
    await pendTasks("sched:" + s.id, on ? "Turning on…" : "Turning off…", action: {
      try await RouterClient.shared.call("PUT", "api/tasks/schedules/\(s.id)", ["enabled": on])
    }, until: { $0.schedules.contains { $0.id == s.id && $0.enabled == on } })
  }
  func deleteSchedule(_ s: TaskSchedule, name: String) async -> Bool {
    guard await confirm("Delete the schedule of “\(name)”?", "The task and its runs stay.", action: "Delete", destructive: true) else { return false }
    await pendTasks("sched:" + s.id, "Deleting…", action: { try await RouterClient.shared.call("DELETE", "api/tasks/schedules/\(s.id)") },
                    until: { !$0.schedules.contains { $0.id == s.id } })
    return true
  }
}
