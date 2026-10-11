// Machines: every Fly machine in jarvis2-sessions (api/machines), live from Fly, each with the session it belongs to or
// "No session", and "test" when it points at a test router. Destroy only for a machine with no session; the router
// re-checks that and destroys it through the core's kill.
import SwiftUI

struct MachinesView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    let ms = model.machines
    List {
      if let e = ms.error { ErrorRow(text: "Could not list machines: \(e)") }
      if ms.loaded {
        Section {
          ForEach(ms.items) { m in MachineRow(m: m) }
        } footer: {
          let orphans = ms.items.count { $0.sessionId == nil }
          Text("\(Fmt.plural(ms.items.count, "machine")) in the Fly app jarvis2-sessions, \(orphans > 0 ? "\(orphans) with no session" : "all belong to sessions"). A paused session has no machine.")
        }
      }
    }
    .overlay {
      if !ms.loaded && ms.error == nil { ProgressView("Loading…") }
      else if ms.loaded && ms.items.isEmpty { ContentUnavailableView("No machines", systemImage: "server.rack", description: Text("Nothing is running or stopped in the app.")) }
    }
    .navigationTitle("Machines")
    .refreshable { await model.loadMachines() }
    .task { while !Task.isCancelled { await model.loadMachines(); try? await Task.sleep(for: .seconds(15)) } }
  }
}

private struct MachineRow: View {
  @Environment(AppModel.self) private var model
  let m: Machine
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack {
        Text(m.id).font(.headline.monospaced())
        Spacer()
        if m.test { StatusPill(text: "test", color: .blue) }
        if let p = model.pending["machine:" + m.id] { StatusPill(text: p, color: .orange, spinning: true) }
        else { StatusPill(text: m.state.isEmpty ? "unknown" : m.state, color: m.state == "started" ? .green : ["starting", "created", "replacing"].contains(m.state) ? .orange : m.state == "failed" ? .red : .secondary) }
      }
      if let sid = m.sessionId {
        Text("\(m.current ? "Session" : "Earlier machine of"): \(model.session(sid)?.title ?? sid)").font(.subheadline)
          .accessibilityIdentifier("machine-session-\(m.id)")
      } else {
        Text("No session").font(.subheadline.weight(.medium)).foregroundStyle(.orange).accessibilityIdentifier("machine-orphan-\(m.id)")
      }
      Text([Fmt.region[m.region].map { "\($0) (\(m.region))" } ?? m.region, [m.size, m.guest].filter { !$0.isEmpty }.joined(separator: " · ")].filter { !$0.isEmpty }.joined(separator: " · "))
        .font(.footnote).foregroundStyle(.secondary)
      Text(m.created.map { "Created \(Fmt.ago($0))" } ?? "Created: unknown").font(.footnote).foregroundStyle(.secondary)
      Text(m.routerUrl.isEmpty ? "Router: none set" : "Router: \(URL(string: m.routerUrl)?.host() ?? m.routerUrl)\(m.test ? " (a test router)" : "")").font(.footnote).foregroundStyle(.secondary)
      Text(shortImage).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      if m.sessionId == nil, let why = m.noDestroy { Text("Destroy isn't offered: \(why).").font(.footnote).foregroundStyle(.secondary) }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("machine-\(m.id)")
    .swipeActions {
      if m.sessionId == nil && m.noDestroy == nil {
        Button("Destroy", systemImage: "trash", role: .destructive) { Task { await destroy() } }
      }
    }
  }
  private var shortImage: String {
    var s = m.image.replacing("ghcr.io/de0ch/", with: "")
    if let r = s.range(of: "@sha256:"), s.distance(from: r.upperBound, to: s.endIndex) > 12 { s = String(s[..<s.index(r.upperBound, offsetBy: 12)]) + "…" }
    return s.isEmpty ? "no image" : s
  }
  private func destroy() async {
    await model.exclusive("machine:" + m.id) {
      guard await model.confirm("Destroy machine \(m.id)?", "\(m.name.isEmpty ? m.id : m.name) belongs to no session\(m.test ? " (it points at a test router)" : ""). The core destroys it on Fly with its disk; nothing of it is archived. It can't be undone.", action: "Destroy machine", destructive: true) else { return }
      model.pend("machine:" + m.id, "Destroying…")
      defer { model.pend("machine:" + m.id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/machines/\(m.id)/destroy")
        for _ in 0..<20 { await model.loadMachines(); if !model.machines.items.contains(where: { $0.id == m.id }) { break }; try? await Task.sleep(for: .seconds(1.5)) }
      } catch { model.fail(error, "Could not destroy: ") }
    }
  }
}
