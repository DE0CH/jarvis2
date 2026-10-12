// The core's secret stores, from its signed list (checked against the pinned core key): unlock (Face ID → this phone's
// share, sealed to the core's one-off key), lock, mark sensitive (one way), and a new empty store. The core's signed
// list of open unlocks, each with Lock. Key names per store come from the router (non-secret; never values).
import SwiftUI

struct StoresView: View {
  @Environment(AppModel.self) private var model
  @State private var keyNames: [String: [String]] = [:]
  @State private var creating = false
  @State private var newName = ""
  @State private var markAsk: String?

  var body: some View {
    List {
      if let e = model.stores.error { ErrorRow(text: e, id: "secure-error") }
      Section {
        ForEach(model.stores.items) { s in
          StoreRow(s: s, keys: keyNames[s.name], harness: model.harnessHidden.contains(s.name), mark: { markAsk = s.name })
        }
      } header: { Text("Stores") } footer: {
        Text("Unlocked: open to every session until locked.")
      }
      Section {
        if model.stores.loaded && model.openUnlocks.isEmpty { Text("None").foregroundStyle(.secondary).accessibilityIdentifier("unlocks-none") }
        ForEach(model.openUnlocks) { u in
          HStack {
            VStack(alignment: .leading, spacing: 3) {
              HStack(spacing: 6) {
                Text(u.store).font(.headline)
                StatusPill(text: (u.forNonce ?? "").isEmpty ? "Every session" : "One session", color: (u.forNonce ?? "").isEmpty ? .orange : .blue)
              }
              HStack(spacing: 12) {
                Label(u.since.isoDate.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? u.since, systemImage: "clock")
                Text(u.id.prefix(8)).monospaced()
              }
              .font(.footnote).foregroundStyle(.secondary)
            }
            Spacer()
            PendingButton(key: "store:" + u.store, title: "Lock", role: .destructive) { await lock(u) }
              .buttonStyle(.borderless).accessibilityIdentifier("lock-\(u.store)")
          }
        }
      } header: { Text("Open unlocks") } footer: {
        Text("From the core's signed list.")
      }
    }
    .overlay { if !model.stores.loaded && model.stores.error == nil { ProgressView("Loading stores…") } }
    .navigationTitle("Stores")
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button("New store", systemImage: "plus") { newName = ""; creating = true }.accessibilityIdentifier("store-new")
      }
    }
    .alert("New store", isPresented: $creating) {
      TextField("name (a–z, 0–9, -)", text: $newName).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("store-new-name")
      Button("Create") { Task { await create() } }.accessibilityIdentifier("store-create")
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("Empty and not sensitive.")
    }
    .confirmationDialog("Mark \(markAsk ?? "") sensitive?", isPresented: Binding(get: { markAsk != nil }, set: { if !$0 { markAsk = nil } }), titleVisibility: .visible) {
      Button("Mark sensitive", role: .destructive) { if let n = markAsk { Task { await mark(n) } } }.accessibilityIdentifier("mark-confirm")
    } message: { Text("The mark can never be removed.") }
    .refreshable { await reload() }
    .task { await reload() }
  }

  private func reload() async {
    await model.loadStores()
    if let j = try? await RouterClient.shared.get("api/stores") {
      var out: [String: [String]] = [:]
      for s in j["stores"].array { if let n = s["name"].string, !s["keys"].isNull { out[n] = s["keys"].strings } }
      keyNames = out
    }
  }
  private func run(_ key: String, _ label: String, _ fn: () async throws -> Void) async {
    await model.exclusive(key) {
      model.pend(key, label)
      defer { model.pend(key, nil) }
      do { try await fn() } catch { model.fail(error) }
      await model.loadStores()
    }
  }
  private func lock(_ u: UnlockRow) async { await run("store:" + u.store, "Locking…") { try await RouterClient.shared.lock(u.id) } }
  private func mark(_ n: String) async { markAsk = nil; await run("store:" + n, "Marking…") { try await RouterClient.shared.markSensitive(n) } }
  private func create() async {
    let n = newName.trimmingCharacters(in: .whitespaces).lowercased()
    guard !n.isEmpty else { return }
    await run("store:new", "Creating…") { try await RouterClient.shared.createStore(n) }
  }
}

private struct StoreRow: View {
  @Environment(AppModel.self) private var model
  let s: StoreView
  let keys: [String]?
  let harness: Bool
  let mark: () -> Void

  var body: some View {
    HStack {
      VStack(alignment: .leading, spacing: 3) {
        HStack(spacing: 6) {
          Text(s.name).font(.headline)
          if s.sensitive { StatusPill(text: "Sensitive", color: .red).accessibilityIdentifier("sensitive-\(s.name)") }
          StatusPill(text: s.unlocked ? "Unlocked" : "Locked", color: s.unlocked ? .blue : .secondary)
        }
        if s.empty || harness {
          HStack(spacing: 6) {
            if s.empty { StatusPill(text: "Empty") }
            if harness { StatusPill(text: "Harness", color: .blue) }
          }
        }
        if let keys, !keys.isEmpty {
          Text(keys.joined(separator: ", ")).font(.footnote.monospaced()).foregroundStyle(.secondary).lineLimit(3)
        }
      }
      Spacer()
      if let p = model.pending["store:" + s.name] {
        HStack { ProgressView(); Text(p).font(.footnote) }
      } else {
        Button(s.unlocked ? "Unlock again" : "Unlock") { Task { await unlock() } }
          .buttonStyle(.bordered).disabled(s.empty)
          .accessibilityIdentifier("unlock-\(s.name)")
      }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("store-\(s.name)")
    .swipeActions {
      if !s.sensitive { Button("Mark sensitive…", action: mark).tint(.red) }
    }
    .contextMenu {
      if !s.sensitive { Button("Mark sensitive…", systemImage: "exclamationmark.shield", action: mark) }
    }
  }

  private func unlock() async {
    let key = "store:" + s.name
    await model.exclusive(key) {
      model.pend(key, "Unlocking…")
      defer { model.pend(key, nil) }
      do {
        let b = try await RouterClient.shared.unlockBegin(s.name)
        let e = b.e, name = s.name
        let x = try await offMain { try PhoneKeys.shared.share(with: e, reason: "Unlock \(name)") }
        try await RouterClient.shared.unlockFinish(b, share: try CoreCrypto.sealShare(x, to: b.t))
      } catch { model.fail(error) }
      await model.loadStores()
    }
  }
}
