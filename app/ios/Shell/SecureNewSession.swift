// The secure New session page. Drawn only by the shell (the React Native UI's view is gone while it is
// up). What it shows comes from the core's signed answers; what it signs is checked against what was
// picked here. Normal mode may pre-select non-sensitive stores; a sensitive store is only ever added by
// a tap on this page.
import SwiftUI

struct SecureNewSession: View {
  let shell: Shell
  let options: [String: Any]
  @State private var stores: [StoreInfo] = []
  @State private var image: ImageInfo?
  @State private var picked: Set<String> = []
  @State private var harness = "claude"
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String { (options["title"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "New session" }
  private var pickedSensitive: [String] { stores.filter { $0.sensitive && picked.contains($0.name) }.map(\.name) }

  var body: some View {
    VStack(spacing: 0) {
      // the app's Page top bar (src/ui/page.tsx): ← Back · title · primary action
      HStack(spacing: 12) {
        KitButton(title: "← Back", variant: .soft, color: .gray, disabled: busy != nil, id: "secure-back") { shell.exitSecure("back") }
        Text("New session").font(.system(size: K.fontSize[4], weight: .bold)).foregroundStyle(Radix.gray.s[12]).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
        KitButton(title: busy ?? "Create", disabled: picked.isEmpty || image == nil, busy: busy != nil, id: "secure-create") { Task { await create() } }
      }
      .padding(.horizontal, 20).padding(.vertical, 16)
      .overlay(alignment: .bottom) { Rectangle().fill(Radix.gray.a[5]).frame(height: 1) }

      ScrollView {
        VStack(alignment: .leading, spacing: 0) {
          HStack(spacing: 6) {
            Image(systemName: "lock.fill").font(.system(size: 11, weight: .semibold)).foregroundStyle(Radix.blue.a[11])
            Text("Secure — drawn by the Jarvis 2 shell, signed with \(PhoneKey.shared.usesEnclave ? "Face ID" : "a software key (simulator)")")
              .font(.system(size: K.fontSize[1], weight: .medium)).foregroundStyle(Radix.blue.a[11])
          }
          .padding(.horizontal, 8).padding(.vertical, 6)
          .background(RoundedRectangle(cornerRadius: K.radius[2]).fill(Radix.blue.a[3]))
          .padding(.top, 12)
          .accessibilityIdentifier("secure-banner")

          Lbl(text: "Session")
          Muted(text: title)

          Lbl(text: "Secret stores")
          if let loadError { Callout(text: loadError, color: .red) }
          else if stores.isEmpty { ProgressView().frame(maxWidth: .infinity) }
          VStack(spacing: 8) {
            ForEach(stores) { s in
              ChoiceCard(on: picked.contains(s.name), check: true, id: "secure-store-\(s.name)", action: { toggle(s.name) }) {
                HStack(spacing: 6) {
                  Text(s.name).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
                  if s.sensitive { Badge(text: "Sensitive", color: .red) }
                }
                Text("\(s.keys) key\(s.keys == 1 ? "" : "s")").font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11])
              }
            }
          }
          if !pickedSensitive.isEmpty {
            Callout(text: "This session will hold sensitive secrets: \(pickedSensitive.joined(separator: ", ")). Only pick them for a session you'll treat with care.", amber: true)
              .padding(.top, 12).accessibilityIdentifier("secure-sensitive-warning")
          }

          Lbl(text: "Harness")
          VStack(spacing: 8) {
            ChoiceCard(on: harness == "claude", id: "secure-harness-claude", action: { harness = "claude" }) { ChoiceText(title: "Claude Code", sub: "Claude subscription · Claude app") }
            ChoiceCard(on: harness == "opencode", id: "secure-harness-opencode", action: { harness = "opencode" }) { ChoiceText(title: "OpenCode · OpenRouter", sub: "Paseo app + web UI") }
          }

          Lbl(text: "Session image")
          if let image {
            ChoiceCard(on: true, id: "secure-image", action: {}) { ChoiceText(title: "Latest CI build", sub: "Built \(Self.date(image.builtAt)) · verified by the core") }
              .allowsHitTesting(false)
          }

          if let failure { Callout(text: failure, color: .red).padding(.top, 16).accessibilityIdentifier("secure-error") }
          Spacer(minLength: 48)
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: 720)
        .frame(maxWidth: .infinity)
      }
    }
    .background(Radix.background.ignoresSafeArea())
    .task { await load() }
  }

  private func toggle(_ n: String) { if picked.contains(n) { picked.remove(n) } else { picked.insert(n) } }

  private func apply(_ p: Core.StoresPayload) {
    stores = p.stores; image = p.image
    // pre-selection from normal mode: known, non-sensitive stores only
    let pre = (options["environments"] as? [String]) ?? []
    if picked.isEmpty { picked = Set(pre.filter { n in p.stores.contains { $0.name == n && !$0.sensitive } }) }
  }

  private func load() async {
    if let p = shell.prefetched { apply(p) }
    if let h = options["harness"] as? String, h == "opencode" { harness = "opencode" }
    let t = Date()
    do {
      let p = try await Core.shared.stores()
      shell.log(String(format: "core stores fetched in %.2fs", Date().timeIntervalSince(t)))
      shell.prefetched = p
      let keep = picked
      apply(p)
      picked = keep.isEmpty ? picked : keep.intersection(p.stores.map(\.name))
    } catch { if stores.isEmpty { loadError = error.localizedDescription } }
  }

  private func create() async {
    failure = nil
    do {
      busy = "Starting…"
      let t0 = Date()
      let machine = try await Core.shared.start()
      shell.log(String(format: "core start %.2fs", Date().timeIntervalSince(t0)))
      busy = "Asking…"
      let want = picked.sorted()
      let (doc, c) = try await Core.shared.succession(machine: machine, stores: want, harness: harness)
      // sign only what was chosen here
      guard c.request.machine == machine else { throw CoreError.mismatch("machine") }
      guard c.request.stores == want else { throw CoreError.mismatch("stores") }
      guard c.request.options.harness == harness else { throw CoreError.mismatch("harness") }
      guard c.request.image == image else { throw CoreError.mismatch("image") }
      busy = "Signing…"
      let (sig, pub) = try await PhoneKey.shared.sign(doc.payload, reason: "Create \"\(title)\" with \(want.joined(separator: ", "))")
      busy = "Creating…"
      var session = options
      session["kind"] = nil
      let id = try await Core.shared.respond(challenge: doc, signature: sig, phoneKey: pub, session: session)
      shell.log("created \(id)")
      busy = nil
      shell.exitSecure("created \(id)", created: id)
    } catch {
      busy = nil
      failure = error.localizedDescription
    }
  }

  static func date(_ iso: String) -> String {
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let d = f.date(from: iso) else { return iso }
    return d.formatted(date: .abbreviated, time: .shortened)
  }
}
