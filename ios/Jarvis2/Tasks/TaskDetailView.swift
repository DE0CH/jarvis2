// One task: its values and line, Run / Run on the latest image / Edit / Schedule / Delete, its daily schedules and its
// runs (newest first) — a run opens its output and log.
import SwiftUI

struct TaskDetailView: View {
  @Environment(AppModel.self) private var model
  let id: String
  @Binding var path: [TaskRoute]
  @State private var runs: [TaskRun]?
  @State private var error: String?

  private var inst: TaskInstance? { model.tasks.instances.first { $0.id == id } }

  var body: some View {
    if let inst {
      let tmpl = model.tasks.templates.first { $0.name == inst.template }
      let schedules = model.tasks.schedules.filter { $0.instance == id }
      List {
        Section {
          HStack {
            StatusPill(text: inst.pill.0, color: inst.pill.1, spinning: inst.state == "running" || inst.state == "busy")
            Text("\(tmpl?.title ?? "\(inst.template) (template missing)") · created \(inst.createdAt?.formatted(date: .abbreviated, time: .omitted) ?? "")").font(.footnote).foregroundStyle(.secondary)
          }
          if inst.state == "approval" { Label("The iPhone approves this task's line once (it waits in the Inbox). Runs need no approval after that.", systemImage: "faceid").foregroundStyle(.blue) }
          if let d = inst.detail, inst.state != "approval" { Text(d).font(.subheadline).foregroundStyle(.secondary) }
          if let w = inst.activeRun?.waiting { Label("Waiting: \(w)", systemImage: "hourglass").foregroundStyle(.orange) }
          let summary = inst.summary(tmpl)
          if !summary.isEmpty { Text(summary).textSelection(.enabled) }
          Text([inst.stores.isEmpty ? "no stores" : "stores: " + inst.stores.joined(separator: ", "), inst.size, inst.queued > 0 ? "\(inst.queued) queued" : nil].compactMap { $0 }.joined(separator: " · "))
            .font(.footnote).foregroundStyle(.secondary)
        }
        Section {
          primary(inst)
          if ["ready", "running", "busy"].contains(inst.state) {
            PendingButton(key: "task:" + id, title: "Run on latest image", systemImage: "arrow.up.circle") { await upgrade(inst) }.accessibilityIdentifier("td-upgrade")
          }
          Button("Edit", systemImage: "pencil") { path.append(.edit(template: nil, instance: id)) }.disabled(tmpl == nil).accessibilityIdentifier("td-edit")
          Button("Schedule daily…", systemImage: "calendar.badge.plus") { path.append(.schedule(id: nil, instance: id)) }.accessibilityIdentifier("td-schedule")
          PendingButton(key: "task-del:" + id, title: "Delete", systemImage: "trash", role: .destructive) { await delete(inst, schedules: schedules.count) }.accessibilityIdentifier("td-delete")
        }
        if !schedules.isEmpty {
          Section("Schedules") {
            ForEach(schedules) { s in
              NavigationLink(value: TaskRoute.schedule(id: s.id, instance: nil)) {
                VStack(alignment: .leading) { Text(s.text); Text(s.enabled ? (s.nextAt.map { "next \(Fmt.fromNow($0))" } ?? "on") : "off").font(.footnote).foregroundStyle(.secondary) }
              }
            }
          }
        }
        Section("Runs") {
          if let error { ErrorRow(text: error) }
          else if let runs {
            if runs.isEmpty { Text("Not run yet.").foregroundStyle(.secondary) }
            ForEach(runs) { r in
              NavigationLink(value: TaskRoute.run(name: r.name, title: inst.name)) {
                VStack(alignment: .leading, spacing: 2) {
                  HStack {
                    StatusPill(text: r.pill.0, color: r.pill.1, spinning: r.active)
                    Text((r.scheduled ? "Scheduled" : "Manual") + (r.upgrade ? " · latest image" : "")).font(.subheadline)
                  }
                  Text(r.when + (r.exitCode.map { r.phase != "succeeded" ? " · exit \($0)" : "" } ?? "")).font(.footnote).foregroundStyle(.secondary)
                  if let w = r.waiting { Text("waiting: \(w)").font(.footnote).foregroundStyle(.secondary) }
                }
              }
              .accessibilityIdentifier("td-run-\(r.name)")
            }
          } else { ProgressView() }
        }
      }
      .navigationTitle(inst.name)
      .navigationBarTitleDisplayMode(.inline)
      .refreshable { await loadRuns(); await model.loadTasks() }
      .task(id: (inst.activeRun?.name ?? "") + (inst.activeRun?.phase ?? "") + (inst.lastRun?.name ?? "") + "\(inst.queued)") { await loadRuns() }
      .task { while !Task.isCancelled { await model.loadTasks(); try? await Task.sleep(for: .seconds(5)) } }
    } else {
      ContentUnavailableView("This task no longer exists", systemImage: "checklist")
    }
  }

  @ViewBuilder private func primary(_ inst: TaskInstance) -> some View {
    if inst.state == "approval" { Label("Waiting for the phone", systemImage: "hourglass").foregroundStyle(.secondary) }
    else if inst.state == "gone" || inst.state == "failed" {
      PendingButton(key: "task:" + id, title: "New line…", systemImage: "arrow.triangle.branch") { await model.reapprove(inst) }.accessibilityIdentifier("td-run-approve")
    } else if inst.activeRun != nil { Label("Running…", systemImage: "play.circle").foregroundStyle(.secondary) }
    else { PendingButton(key: "task:" + id, title: "Run", systemImage: "play.fill") { await model.runTask(id) }.accessibilityIdentifier("td-run") }
  }

  private func loadRuns() async {
    do {
      let rs = try await RouterClient.shared.get("api/tasks/instances/\(id)/runs")["runs"].array.map(TaskRun.init)
      runs = rs; error = nil
      if rs.contains(where: \.active) { try? await Task.sleep(for: .seconds(2)); await loadRuns() }
    } catch { self.error = errText(error) }
  }
  private func upgrade(_ inst: TaskInstance) async {
    guard await model.confirm("Run “\(inst.name)” on the latest image?", "Resumes its line on the newest session image (how a changed template reaches a task). The iPhone approves the new image first.", action: "Run on latest image") else { return }
    await model.runTask(id, upgrade: true)
  }
  private func delete(_ inst: TaskInstance, schedules: Int) async {
    guard await model.confirm("Delete “\(inst.name)”?", "Its \(schedules > 0 ? "\(Fmt.plural(schedules, "schedule")) and " : "")run history go with it, and its session line is destroyed (archived like any session). The template stays.", action: "Delete", destructive: true) else { return }
    await model.pendTasks("task-del:" + id, "Deleting…", 60, action: { try await RouterClient.shared.call("DELETE", "api/tasks/instances/\(id)") },
                          until: { !$0.instances.contains { $0.id == id } })
    if !path.isEmpty { path.removeLast() }
  }
}
