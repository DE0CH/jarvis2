// A session's logs, read only, beside the terminal: the supervisor's log (what the machine's supervisor wrote: boot,
// commands it ran, prompts it delivered, the snapshot, with no secrets in it) and the lifecycle log (each boot, pause,
// resume, upgrade and destroy: what Fly did, what the router did, then the supervisor's lines, in order). Both are kept
// for the session's life, so they open for running, paused and failed sessions alike; while open they poll every 2 s
// and follow new lines. Plain native lists, wrapped text (no sideways scrolling on a phone).
import SwiftUI

/// "12:04:31" today, "Oct 15 12:04:31" on another day
private func clock(_ d: Date?) -> String {
  guard let d else { return "" }
  return Calendar.current.isDateInToday(d)
    ? d.formatted(.dateTime.hour().minute().second())
    : d.formatted(.dateTime.month(.abbreviated).day().hour().minute().second())
}

/// "4 s", "2 min 5 s", "1 h 3 min"
func lifecycleDuration(_ from: Date?, _ to: Date?) -> String {
  guard let from else { return "" }
  let s = max(0, Int((to ?? .now).timeIntervalSince(from)))
  if s < 60 { return "\(s) s" }
  if s < 3600 { return s % 60 == 0 ? "\(s / 60) min" : "\(s / 60) min \(s % 60) s" }
  return "\(s / 3600) h \((s % 3600) / 60) min"
}

private let pollEvery: Duration = .seconds(2)

struct SupervisorLogView: View {
  let sessionId: String
  let title: String
  @State private var lines: [SupervisorLine] = []
  @State private var next = 0
  @State private var loaded = false
  @State private var error: String?
  @State private var follow = true

  var body: some View {
    ScrollViewReader { proxy in
      List {
        if let error { ErrorRow(text: error, id: "suplog-error") }
        if loaded && lines.isEmpty {
          Text("The supervisor hasn't written anything yet.").foregroundStyle(.secondary).accessibilityIdentifier("suplog-empty")
        }
        ForEach(Array(lines.enumerated()), id: \.element.id) { i, l in
          VStack(alignment: .leading, spacing: 2) {
            if i == 0 || lines[i - 1].machine != l.machine, !l.machine.isEmpty {
              Label("machine \(l.machine)", systemImage: "server.rack").font(.caption.bold()).foregroundStyle(.secondary)
                .padding(.top, i == 0 ? 0 : 6)
            }
            HStack(alignment: .firstTextBaseline, spacing: 8) {
              Text(clock(l.at)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
              Text(l.text).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            }
          }
          .listRowInsets(EdgeInsets(top: 2, leading: 12, bottom: 2, trailing: 12))
          .listRowSeparator(.hidden)
          .id(l.id)
          .accessibilityIdentifier("suplog-line-\(l.seq)")
        }
      }
      .listStyle(.plain)
      .overlay { if !loaded && error == nil { ProgressView("Reading the supervisor's log…") } }
      .task(id: sessionId) {
        while !Task.isCancelled {
          await poll()
          if follow, let last = lines.last { withAnimation(nil) { proxy.scrollTo(last.id, anchor: .bottom) } }
          try? await Task.sleep(for: pollEvery)
        }
      }
    }
    .navigationTitle("Supervisor log")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Toggle(isOn: $follow) { Label("Follow", systemImage: "arrow.down.to.line") }.toggleStyle(.button).accessibilityIdentifier("suplog-follow")
      }
    }
    .accessibilityIdentifier("supervisor-log")
  }

  private func poll() async {
    do {
      let r = try await RouterClient.shared.get("api/sessions/\(RouterClient.escaped(sessionId))/supervisor-log?after=\(next)&limit=500")
      let new = r["lines"].array.map(SupervisorLine.init).filter { $0.seq > (lines.last?.seq ?? -1) || lines.isEmpty }
      if !new.isEmpty { lines.append(contentsOf: new); if lines.count > 5000 { lines.removeFirst(lines.count - 5000) } }
      if let n = r["next"].int { next = n } else if let s = lines.last?.seq { next = s }
      loaded = true
      error = nil
    } catch {
      self.error = errText(error)
      loaded = true
    }
  }
}

struct LifecycleListView: View {
  let sessionId: String
  let title: String
  @State private var ops: [LifecycleOp]?
  @State private var error: String?

  var body: some View {
    List {
      if let error { ErrorRow(text: error, id: "lifecycle-error") }
      if let ops {
        if ops.isEmpty { Text("No operations recorded yet.").foregroundStyle(.secondary).accessibilityIdentifier("lifecycle-empty") }
        ForEach(ops) { op in
          NavigationLink(value: SessionRoute.lifecycleOp(op.id)) {
            VStack(alignment: .leading, spacing: 4) {
              HStack {
                Text(op.kind.capitalized).font(.headline)
                Spacer()
                LifecycleBadge(state: op.state)
              }
              Text([op.started.map { $0.formatted(.dateTime.month(.abbreviated).day().hour().minute().second()) }, lifecycleDuration(op.started, op.ended).nilIfEmpty]
                .compactMap { $0 }.joined(separator: " · "))
                .font(.caption).foregroundStyle(.secondary)
              if let e = op.error { Text(e).font(.caption).foregroundStyle(.red).lineLimit(2) }
            }
          }
          .accessibilityIdentifier("lc-op-\(op.id)")
        }
      }
    }
    .overlay { if ops == nil && error == nil { ProgressView("Reading the lifecycle log…") } }
    .refreshable { await load() }
    .task(id: sessionId) {
      while !Task.isCancelled {
        await load()
        // poll only while something runs (a running op's duration and state change)
        try? await Task.sleep(for: (ops ?? []).contains(where: \.running) ? pollEvery : .seconds(10))
      }
    }
    .navigationTitle("Lifecycle")
    .navigationBarTitleDisplayMode(.inline)
    .accessibilityIdentifier("lifecycle")
  }

  private func load() async {
    do {
      ops = try await RouterClient.shared.get("api/sessions/\(RouterClient.escaped(sessionId))/lifecycle")["ops"].array.map(LifecycleOp.init)
      error = nil
    } catch { self.error = errText(error) }
  }
}

struct LifecycleOpView: View {
  let sessionId: String
  let opId: String
  @State private var op: LifecycleOp?
  @State private var error: String?

  var body: some View {
    ScrollViewReader { proxy in
      List {
        if let error { ErrorRow(text: error, id: "lc-error") }
        if let op {
          Section {
            HStack { Text(op.kind.capitalized).font(.headline); Spacer(); LifecycleBadge(state: op.state) }
            if let s = op.started { LabeledContent("Started", value: s.formatted(.dateTime.month(.abbreviated).day().hour().minute().second())) }
            LabeledContent(op.running ? "Running for" : "Took", value: lifecycleDuration(op.started, op.ended))
            if !op.machines.isEmpty { LabeledContent("Machines") { Text(op.machines.joined(separator: ", ")).font(.caption.monospaced()) } }
            if let e = op.error { ErrorRow(text: e, id: "lc-op-error") }
          }
          Section("Log") {
            if op.entries.isEmpty { Text(op.running ? "Waiting for the first step…" : "Nothing was recorded.").foregroundStyle(.secondary) }
            ForEach(op.entries) { e in
              VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                  Text(clock(e.at)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                  SourceTag(source: e.source)
                  if !e.machine.isEmpty { Text(e.machine).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1) }
                }
                Text(e.text).font(.caption.monospaced()).textSelection(.enabled)
              }
              .id(e.id)
              .accessibilityElement(children: .combine)
              .accessibilityIdentifier("lc-entry-\(e.n)")
            }
          }
        }
      }
      .overlay { if op == nil && error == nil { ProgressView("Reading the operation…") } }
      .task(id: opId) {
        var wasRunning = true
        while !Task.isCancelled && wasRunning {
          await load()
          if let last = op?.entries.last, op?.running == true { withAnimation(nil) { proxy.scrollTo(last.id, anchor: .bottom) } }
          wasRunning = op?.running ?? (error != nil)
          if wasRunning { try? await Task.sleep(for: pollEvery) }
        }
      }
    }
    .navigationTitle(op?.kind.capitalized ?? "Operation")
    .navigationBarTitleDisplayMode(.inline)
    .accessibilityIdentifier("lifecycle-op")
  }

  private func load() async {
    do {
      op = LifecycleOp(j: try await RouterClient.shared.get("api/sessions/\(RouterClient.escaped(sessionId))/lifecycle/\(RouterClient.escaped(opId))"))
      error = nil
    } catch { self.error = errText(error) }
  }
}

private struct LifecycleBadge: View {
  let state: String
  var body: some View {
    switch state {
    case "running": StatusPill(text: "running", color: .orange, spinning: true)
    case "failed": StatusPill(text: "failed", color: .red)
    default: StatusPill(text: "done", color: .green)
    }
  }
}

private struct SourceTag: View {
  let source: String
  var body: some View {
    let (t, c): (String, Color) = switch source {
    case "fly": ("Fly", .purple)
    case "router": ("Router", .blue)
    case "supervisor": ("Supervisor", .teal)
    default: (source.isEmpty ? "—" : source, .secondary)
    }
    Text(t).font(.caption2.weight(.semibold)).padding(.horizontal, 5).padding(.vertical, 1)
      .foregroundStyle(c).background(c.opacity(0.14), in: .capsule)
  }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
