// A running session's stores: drop the ones it no longer needs (POST api/sessions/:id/narrow: its main grant moved along
// the machine's identity edge, no Face ID since it only narrows) or ask for another (an add-store approval: two certs
// and the store's unlock under one Face ID). The harness's own stores and the reserved ones are never offered. And the
// results of the commands Deyao approved for it (GET api/state `commands`).
import SwiftUI

struct SessionStoresView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  @State private var keep: Set<String> = []
  @State private var seeded = false

  var body: some View {
    if let m = model.session(sessionId) {
      let harness = Set(model.policy[m.harness] ?? [])
      let own = m.stores(policy: model.policy)
      let held = Set(m.j["stores"].strings)
      let others = model.stores.items.filter { !held.contains($0.name) && !harness.contains($0.name) && !$0.isCore && $0.name != Checks.deployKeyTokenStore }
      let busy = model.pending["s:" + m.id] ?? m.serverBusy
      Form {
        Section {
          if own.isEmpty { Text("No stores of its own.").foregroundStyle(.secondary) }
          ForEach(own, id: \.self) { n in
            CheckRow(on: keep.contains(n), id: "keep-store-\(n)", action: { if keep.contains(n) { keep.remove(n) } else { keep.insert(n) } }) {
              HStack(spacing: 6) {
                Text(n)
                if model.stores.items.first(where: { $0.name == n })?.sensitive == true { StatusPill(text: "Sensitive", color: .red) }
              }
            }
          }
          let dropping = own.filter { !keep.contains($0) }
          Button(busy ?? "Drop the unticked stores", systemImage: "minus.circle", role: .destructive) {
            Task { await model.narrow(m, keep: m.j["stores"].strings.filter { !dropping.contains($0) }, dropping: dropping) }
          }
          .disabled(dropping.isEmpty || busy != nil || m.state != "started")
          .accessibilityIdentifier("drop-stores")
        } header: { Text("Keep") } footer: {
          Text("Dropping needs no Face ID. Getting a store back is a new approval.")
        }
        if !harness.isEmpty {
          Section("The harness brings") { ForEach(harness.sorted(), id: \.self) { Label($0, systemImage: "shippingbox").foregroundStyle(.secondary) } }
        }
        Section {
          if others.isEmpty { Text("No other stores.").foregroundStyle(.secondary) }
          ForEach(others) { s in
            Button { Task { await model.requestAddStore(m, store: s.name) } } label: {
              HStack(spacing: 6) {
                Label(s.name, systemImage: "plus.circle")
                Spacer()
                if s.sensitive { StatusPill(text: "Sensitive", color: .red) }
                if !s.unlocked { StatusPill(text: "Locked") }
              }
            }
            .disabled(busy != nil || m.state != "started")
            .accessibilityIdentifier("add-store-\(s.name)")
          }
        } header: { Text("Add a store") } footer: {
          Text("Opens an approval: Face ID signs it and unlocks the store if it is locked.")
        }
      }
      .navigationTitle("Stores")
      .navigationBarTitleDisplayMode(.inline)
      .onAppear { if !seeded { keep = Set(own); seeded = true } }
      .task { await model.loadStores() }
    } else {
      ContentUnavailableView("Session gone", systemImage: "rectangle.stack.badge.minus")
    }
  }
}

struct CommandsView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  var body: some View {
    let runs = Array((model.session(sessionId)?.commands ?? []).reversed())
    List {
      if runs.isEmpty { Text("No commands yet.").foregroundStyle(.secondary) }
      ForEach(runs) { c in
        Section {
          Text(c.cmd).font(.footnote.monospaced()).textSelection(.enabled)
          LabeledContent("Exit code") { Text("\(c.code)").foregroundStyle(c.code == 0 ? Color.primary : Color.red) }
          if let e = c.error { ErrorRow(text: e) }
          if !c.stdout.isEmpty { Text(c.stdout).font(.caption.monospaced()).textSelection(.enabled) }
          if !c.stderr.isEmpty { Text(c.stderr).font(.caption.monospaced()).foregroundStyle(.orange).textSelection(.enabled) }
        } header: { Text(c.at.map(Fmt.ago) ?? "") }
      }
    }
    .navigationTitle("Command results")
    .navigationBarTitleDisplayMode(.inline)
  }
}
