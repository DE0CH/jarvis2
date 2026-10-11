// Settings: the Claude account (Jarvis 1 holds it) and its usage, Stores, Repos and Machines, the Fly spend against the
// cap, and Jarvis 2 itself with Reset or recover.
import SwiftUI

enum SettingsRoute: Hashable { case stores, repos, addRepo, machines }

struct SettingsView: View {
  @Environment(AppModel.self) private var model
  @State private var path: [SettingsRoute] = []

  var body: some View {
    NavigationStack(path: $path) {
      List {
        Section {
          NavigationLink(value: SettingsRoute.stores) {
            LabeledContent { Text(model.stores.loaded ? "\(model.stores.items.count)" : "") } label: { Label("Stores", systemImage: "shippingbox") }
          }
          .accessibilityElement(children: .combine).accessibilityIdentifier("open-stores")
          NavigationLink(value: SettingsRoute.repos) {
            LabeledContent { Text("\(model.repos.count)") } label: { Label("Repos", systemImage: "chevron.left.forwardslash.chevron.right") }
          }
          .accessibilityElement(children: .combine).accessibilityIdentifier("open-repos")
          NavigationLink(value: SettingsRoute.machines) { Label("Machines", systemImage: "server.rack") }
            .accessibilityIdentifier("open-machines")
        }
        Section {
          Text("Jarvis 2 sessions use Jarvis 1's Claude login: the router fetches its credential pair and writes it into a session whose login expired. Re-login and the token live in Jarvis 1's Settings; the quota below is read through it.")
            .font(.subheadline).foregroundStyle(.secondary)
          if let u = URL(string: "https://jarvis.deyaochen.com/") { Link(destination: u) { Label("Jarvis 1", systemImage: "arrow.up.right.square") }.accessibilityIdentifier("open-jarvis1") }
        } header: { Text("Claude account") }
        UsageSection()
        FlySection()
        Section {
          LabeledContent("Core", value: model.coreUp ? "Running" : "Not answering")
          Button("Reset or recover…", systemImage: "key.horizontal") { model.showSetup = true }.accessibilityIdentifier("open-setup")
        } header: { Text("Jarvis 2") } footer: {
          Text("Start fresh with a new recovery kit, or bring everything back with yours. Either pairs this iPhone again.")
        }
      }
      .navigationTitle("Settings")
      .refreshable { await model.refresh(); await model.loadStores() }
      .navigationDestination(for: SettingsRoute.self) { r in
        switch r {
        case .stores: StoresView()
        case .repos: ReposView(path: $path)
        case .addRepo: AddRepoView(path: $path)
        case .machines: MachinesView()
        }
      }
    }
  }
}

/// the Claude quota (GET api/usage, forwarded to Jarvis 1, which holds the login)
private struct UsageSection: View {
  @State private var u: JSON?
  @State private var error: String?
  @State private var busy = false
  var body: some View {
    Section {
      if let u {
        let limits = u["limits"].array
        if limits.isEmpty { Text("No rate-limit windows reported.").foregroundStyle(.secondary) }
        ForEach(Array(limits.enumerated()), id: \.offset) { _, l in
          let used = max(0, min(100, l["percent"].int ?? 0))
          VStack(alignment: .leading, spacing: 4) {
            HStack { Text(label(l)); Spacer(); Text("\(used)% used").bold().foregroundStyle(used >= 90 ? .red : used >= 75 ? .orange : .green) }
            ProgressView(value: Double(used), total: 100).tint(used >= 90 ? .red : used >= 75 ? .orange : .green)
            Text("\(100 - used)% left\(l["resetsAt"].string?.isoDate.map { " · resets " + Fmt.fromNow($0) } ?? "")").font(.footnote).foregroundStyle(.secondary)
          }
        }
        let x = u["extraUsage"]
        if !x.isNull {
          Text(x["enabled"].bool == true ? "Extra usage: \(money(x["usedCredits"], x)) of \(money(x["monthlyLimit"], x)) this month\(x["spendLimitReached"].bool == true ? " · spend limit reached" : "")"
               : "Extra usage: off\(x["disabledReason"].text.map { " (\($0.replacing("_", with: " ")))" } ?? "")")
            .font(.footnote).foregroundStyle(.secondary)
        }
        if let at = u["fetchedAt"].string?.isoDate { Text("Fetched \(Fmt.fromNow(at))\(u["stale"].bool == true ? " · showing the last good reading, refresh failed: \(u["error"].string ?? "")" : "")").font(.footnote).foregroundStyle(.secondary) }
      } else if let error { ErrorRow(text: error) } else { ProgressView() }
      Button(busy ? "Refreshing…" : "Refresh") { Task { await load(force: true) } }.disabled(busy).accessibilityIdentifier("usage-refresh")
    } header: { Text("Usage") }
    .task { await load(force: false) }
  }
  private func load(force: Bool) async {
    busy = force
    defer { busy = false }
    do { u = try await RouterClient.shared.get("api/usage" + (force ? "?refresh=1" : "")); error = nil } catch { self.error = errText(error) }
  }
  private func label(_ l: JSON) -> String {
    let scope = l["model"].text ?? l["surface"].text
    switch l["group"].string {
    case "session": return "Session (5 h)"
    case "weekly": return scope.map { "Weekly · " + $0 } ?? "Weekly · all models"
    default: return (scope.map { $0 + " · " } ?? "") + (l["kind"].string ?? "").replacing("_", with: " ")
    }
  }
  private func money(_ v: JSON, _ x: JSON) -> String {
    let dp = x["decimalPlaces"].int ?? 2
    let amount = (v.double ?? 0) / pow(10, Double(dp))
    return amount.formatted(.currency(code: x["currency"].string ?? "USD"))
  }
}

/// the Fly spend against the cap (the router's own estimate from the machines' sizes and running time)
private struct FlySection: View {
  @Environment(AppModel.self) private var model
  var body: some View {
    let b = model.budget
    Section {
      if b.isNull {
        Text(model.fly["error"].text.map { "No reading: \($0)" } ?? "No reading yet (the router samples the Fly app every few minutes).").foregroundStyle(.secondary)
      } else {
        let cap = b["capUsd"].double ?? 0, spent = b["spentUsd"].double ?? 0
        let pct = cap > 0 ? min(100, Int((spent / cap * 100).rounded())) : 0
        let color: Color = b["capped"].bool == true ? .red : b["warned"].bool == true ? .orange : .green
        HStack { Text("\(Fmt.usd(spent)) of \(Fmt.usd(cap)) · \(b["month"].string ?? "")").accessibilityIdentifier("budget-spent"); Spacer(); Text("\(pct)%").bold().foregroundStyle(color) }
        ProgressView(value: Double(pct), total: 100).tint(color)
        Text("Now \(Fmt.usd(b["ratePerHour"].double ?? 0))/h (\(Fmt.usd(b["perMonth"].double ?? 0)) a month at this rate) · \(Fmt.plural(b["running"].int ?? 0, "running machine")) · \(Fmt.plural(b["volumes"].int ?? 0, "volume"))")
          .font(.footnote).foregroundStyle(.secondary)
        Text("A DM at \(Fmt.usd(b["warnUsd"].double ?? 0)); at \(Fmt.usd(cap)) the router pauses every running session.").font(.footnote).foregroundStyle(.secondary)
      }
    } header: { Text("Fly spend") } footer: {
      Text("Fly app \(model.flyApp ?? "jarvis2-sessions") (org jarvis2-370). An estimate, not Fly's invoice.")
    }
  }
}
