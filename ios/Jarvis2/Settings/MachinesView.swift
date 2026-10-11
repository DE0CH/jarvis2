// Machines: every Fly machine and volume in every Fly org Jarvis can see (api/machines, router/flyorgs.go): this
// Jarvis's own app (jarvis2-sessions) with each machine's session or "No session", and the other apps read-only (an org
// read through Jarvis 1 says so). Whatever stands out is flagged in amber. Destroy only for a machine of this Jarvis's
// own app that belongs to no session; the router re-checks that and destroys it through the core's kill.
import SwiftUI

struct MachinesView: View {
  @Environment(AppModel.self) private var model

  private static let orgOrder = ["jarvis2-370", "kamyee", "personal"]
  private var orgs: [JSON] {
    model.machinesDoc["orgs"].array.sorted { a, b in
      let ia = Self.orgOrder.firstIndex(of: a["org"].string ?? "") ?? 99, ib = Self.orgOrder.firstIndex(of: b["org"].string ?? "") ?? 99
      return ia < ib
    }
  }

  var body: some View {
    let doc = model.machinesDoc
    List {
      if let e = model.machines.error { ErrorRow(text: "Could not list machines: \(e)") }
      if model.machines.loaded {
        Section {
          let n = doc["attention"].int ?? 0
          if n > 0 {
            Label("\(Fmt.plural(n, "thing")) stand\(n == 1 ? "s" : "") out", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
              .accessibilityElement(children: .combine).accessibilityIdentifier("machines-attention")
          } else {
            Label("Nothing stands out.", systemImage: "checkmark.circle").foregroundStyle(.green)
              .accessibilityElement(children: .combine).accessibilityIdentifier("machines-attention")
          }
          if let e = doc["configError"].text { ErrorRow(text: e) }
        } footer: {
          let own = model.machines.items
          let orphans = own.count { $0.sessionId == nil }
          Text("\(Fmt.plural(own.count, "machine")) in \(doc["app"].string ?? "jarvis2-sessions"), \(orphans > 0 ? "\(orphans) with no session" : "all belong to sessions"). A paused session has no machine.")
        }
        ForEach(Array(orgs.enumerated()), id: \.offset) { _, org in OrgSections(org: org) }
      }
    }
    .overlay { if !model.machines.loaded && model.machines.error == nil { ProgressView("Loading…") } }
    .navigationTitle("Machines")
    .refreshable { await model.loadMachines() }
    .task { while !Task.isCancelled { await model.loadMachines(); try? await Task.sleep(for: .seconds(15)) } }
  }
}

/// one org: a section per app (or one saying it has none, or its error)
private struct OrgSections: View {
  let org: JSON
  var body: some View {
    let name = org["org"].string ?? ""
    let via = org["via"].string ?? "fly"
    let apps = org["apps"].array
    if org["error"].text != nil || apps.isEmpty {
      Section {
        if let e = org["error"].text { ErrorRow(text: e) }
        else { Text("No apps in this org.").foregroundStyle(.secondary) }
      } header: { Text("Org \(name)\(via == "fly" ? "" : " · via \(via)")") }
    }
    ForEach(Array(apps.enumerated()), id: \.offset) { _, app in
      let own = app["own"].bool == true
      let machines = app["machines"].array.map(Machine.init)
      let volumes = app["volumes"].array
      Section {
        if let e = app["error"].text { ErrorRow(text: e) }
        ForEach(machines) { m in MachineRow(m: m, own: own) }
        ForEach(Array(volumes.enumerated()), id: \.offset) { _, v in VolumeRow(v: v) }
        if machines.isEmpty && volumes.isEmpty && app["error"].text == nil { Text("No machines or volumes.").foregroundStyle(.secondary) }
      } header: {
        HStack {
          Text("Org \(name)\(via == "fly" ? "" : " · via \(via)") · \(app["app"].string ?? "")")
          Spacer()
          StatusPill(text: own ? "this Jarvis" : "read-only", color: own ? .blue : .secondary)
        }
      } footer: {
        Text([app["label"].text ?? "an app no Jarvis uses", Fmt.plural(machines.count, "machine"), Fmt.plural(volumes.count, "volume"), app["status"].text].compactMap { $0 }.joined(separator: " · "))
      }
      .accessibilityIdentifier("app-\(app["app"].string ?? "")")
    }
  }
}

private struct VolumeRow: View {
  let v: JSON
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack {
        Label(v["name"].text ?? v["id"].string ?? "", systemImage: "externaldrive").font(.headline)
        Spacer()
        StatusPill(text: v["state"].text ?? "volume", color: v["attachedTo"].text == nil ? .orange : .secondary)
      }
      Text([v["id"].string, v["sizeGb"].int.map { "\($0) GB" }, v["region"].text.map { Fmt.region[$0] ?? $0 }, v["attachedTo"].text.map { "attached to \($0)" } ?? "not attached", v["created"].string?.isoDate.map { "created " + Fmt.ago($0) }].compactMap { $0 }.joined(separator: " · "))
        .font(.footnote).foregroundStyle(.secondary)
      if let a = v["attention"].text { Label(a, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange) }
    }
  }
}

private struct MachineRow: View {
  @Environment(AppModel.self) private var model
  let m: Machine
  let own: Bool
  private var canDestroy: Bool { own && m.sessionId == nil && m.noDestroy == nil }

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
      } else if let other = m.otherSession {
        Text("Jarvis 1 session \(other)").font(.subheadline)
      } else if own {
        Text("No session").font(.subheadline.weight(.medium)).foregroundStyle(.orange).accessibilityIdentifier("machine-orphan-\(m.id)")
      }
      if let a = m.attention { Label(a, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange) }
      Text([Fmt.region[m.region].map { "\($0) (\(m.region))" } ?? m.region, [m.size, m.guest].filter { !$0.isEmpty }.joined(separator: " · ")].filter { !$0.isEmpty }.joined(separator: " · "))
        .font(.footnote).foregroundStyle(.secondary)
      Text(m.created.map { "Created \(Fmt.ago($0))" } ?? "Created: unknown").font(.footnote).foregroundStyle(.secondary)
      if own { Text(m.routerUrl.isEmpty ? "Router: none set" : "Router: \(URL(string: m.routerUrl)?.host() ?? m.routerUrl)\(m.test ? " (a test router)" : "")").font(.footnote).foregroundStyle(.secondary) }
      Text(shortImage).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      if own, m.sessionId == nil, let why = m.noDestroy { Text("Destroy isn't offered: \(why).").font(.footnote).foregroundStyle(.secondary) }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("machine-\(m.id)")
    .swipeActions {
      if canDestroy { Button("Destroy", systemImage: "trash", role: .destructive) { Task { await destroy() } } }
    }
    .contextMenu {
      if canDestroy { Button("Destroy", systemImage: "trash", role: .destructive) { Task { await destroy() } } }
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
