// "What you sign (exact)": the first of the three fields a request's review page shows (docs/DESIGN.md
// "Requests"). It is rendered here, in the app, from the very content the phone signs — secrets' signed begin
// documents and the exact payloads of the succession certs it signs — never from the router's words, so a lying router
// can't make it say something other than what gets signed. Known strings readably, unknown JSON pretty-printed,
// anything else exactly as it is (docs/DESIGN.md "The iPhone app"). It is a list of
// labelled facts (no sentences assembled from fields: docs/DESIGN.md "No prose assembled by code"); the page shows
// each as a row with the accessibility id `signed-<id>`. Foundation only: the interop and golden tests (ios/interop)
// render it too.
import Foundation

/// one signed fact: a labelled value, shown as a row
struct SignedFact: Equatable, Identifiable {
  enum Style: Equatable {
    case plain
    /// an id, a digest, a key title: monospaced
    case code
    /// worth a second look (a sensitive store, bypass mode, a replaced key): drawn as a warning
    case warning
  }
  let id: String
  let label: String
  /// one value per line (a list of stores, repos, images)
  let value: String
  var style: Style = .plain
}

enum SignedAction {
  static func list(_ xs: [String]) -> String { xs.isEmpty ? "None" : xs.joined(separator: "\n") }
  static func yes(_ b: Bool) -> String { b ? "Yes" : "No" }
  /// the value of a fact by id (interop and tests)
  static func value(_ facts: [SignedFact], _ id: String) -> String? { facts.first { $0.id == id }?.value }

  /// a deploy key, from secrets' signed deploy-key-begin document
  static func deployKey(_ b: DeployKeyBegin) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Secrets request"),
      .init(id: "action", label: "Action", value: b.action == "remove" ? "Remove deploy key" : "Add deploy key"),
      .init(id: "repo", label: "Repo", value: b.repo, style: .code),
      .init(id: "key-title", label: "Key on GitHub", value: b.title, style: .code),
    ]
    if b.action != "remove" { f.append(.init(id: "access", label: "Access", value: "Read and push")) }
    f.append(.init(id: "store", label: b.action == "remove" ? "Deletes store" : "Store", value: b.store, style: .code))
    f.append(.init(id: "sensitive", label: "Sensitive", value: yes(b.sensitive), style: b.sensitive ? .warning : .plain))
    if b.action != "remove" && b.replaces {
      f.append(.init(id: "replaces", label: "Replaces earlier key", value: "Yes", style: .warning))
    }
    f.append(.init(id: "token-store", label: "GitHub token from", value: b.tokenStore, style: .code))
    f.append(.init(id: "token-use", label: "Token use", value: "This request only"))
    return f
  }

  /// a string of a grant or cert, readably when it is one the app knows (store:, shell, session:, until:, cmd:, once:),
  /// pretty-printed when it is JSON, otherwise exactly as it is. `cmd`: the command text an approval names (shown when
  /// its sha256 is the one in the cert)
  static func element(_ s: String, cmd: String? = nil) -> (label: String, value: String, style: SignedFact.Style) {
    func after(_ p: String) -> String? { s.hasPrefix(p) && s.count > p.count ? String(s.dropFirst(p.count)) : nil }
    if s == "shell" { return ("Shell", "Run commands as the session's user", .warning) }
    if let x = after("store:") { return ("Store", x, .code) }
    if let x = after("session:") { return ("Session", x, .code) }
    if let x = after("until:"), let d = Kernel.untilDate(x) { return ("Until", d.formatted(date: .abbreviated, time: .shortened), .plain) }
    if let x = after("cmd:"), Kernel.matches(x, "^[0-9a-f]{64}$") {
      if let cmd, CoreCrypto.sha256hex(Data(cmd.utf8)) == x { return ("Command", cmd, .code) }
      return ("Command sha256", x, .code)
    }
    if let x = after("once:") { return ("Once", x, .code) }
    if let p = Kernel.prettyJSON(s) { return ("JSON", p, .code) }
    return ("String", s, .code)
  }

  /// an object of a cert: the sink, a source with its contents (image, snapshot, start settings), a machine with its keys
  static func object(_ o: KObject, id: String, label: String) -> [SignedFact] {
    switch o.kind {
    case .sink: return [.init(id: id, label: label, value: "Sink")]
    case .source:
      var f: [SignedFact] = [.init(id: id, label: label, value: o.id, style: .code)]
      if !o.image.isEmpty { f.append(.init(id: id + "-image", label: "Image", value: o.image, style: .code)) }
      if !o.snapshot.isEmpty { f.append(.init(id: id + "-snapshot", label: "Starts from snapshot", value: o.snapshot, style: .code)) }
      if !o.settings.isEmpty { f += settings(o.settings, id: id + "-settings") }
      return f
    case .machine:
      return [.init(id: id, label: label, value: "Machine " + o.id, style: .code),
              .init(id: id + "-signing", label: "Its signing key", value: o.signingKey, style: .code),
              .init(id: id + "-encryption", label: "Its encryption key", value: o.encryptionKey, style: .code)]
    }
  }

  /// a source's start settings: the fields the app knows as rows, any other field pretty-printed, and settings that
  /// aren't a JSON object exactly as they are
  static func settings(_ text: String, id: String) -> [SignedFact] {
    guard let c = Kernel.settings(text) else { return [.init(id: id, label: "Settings", value: text, style: .warning)] }
    var f: [SignedFact] = []
    let s = { (k: String) -> String in (c[k] as? String) ?? "" }
    if !s("session").isEmpty { f.append(.init(id: id + "-session", label: "Session", value: s("session"), style: .code)) }
    if !s("title").isEmpty { f.append(.init(id: id + "-title", label: "Title", value: s("title"))) }
    if !s("prompt").isEmpty { f.append(.init(id: id + "-prompt", label: "First prompt", value: s("prompt"))) }
    if !s("harness").isEmpty { f.append(.init(id: id + "-harness", label: "Harness", value: s("harness"))) }
    let mode = s("permissionMode")
    f.append(.init(id: id + "-mode", label: "Permission mode", value: mode.isEmpty ? "None" : mode, style: mode == "auto" ? .plain : .warning))
    if !s("model").isEmpty { f.append(.init(id: id + "-model", label: "Model", value: s("model"))) }
    if let repos = c["repos"] as? [String], !repos.isEmpty { f.append(.init(id: id + "-repos", label: "Repos", value: list(repos), style: .code)) }
    if let cs = Checks.content(c), !cs.isEmpty { f.append(.init(id: id + "-content", label: "Content stores", value: list(cs), style: .code)) }
    if (c["oneShot"] as? Bool) == true { f.append(.init(id: id + "-one-shot", label: "One-shot", value: "Yes")) }
    if (c["apiProxy"] as? Bool) == true { f.append(.init(id: id + "-api-proxy", label: "API proxy log", value: "Yes")) }
    if let atts = Checks.attachments(c), !atts.isEmpty {
      f.append(.init(id: id + "-images", label: "Images", value: list(atts.map { "\($0.name) · \($0.size) B · sha256 \($0.sha256.prefix(12))…" }), style: .code))
    }
    if !s("rollback").isEmpty { f.append(.init(id: id + "-rollback", label: "Roll back from", value: s("rollback"), style: .warning)) }
    if let t = c["task"] as? [String: Any] {
      f.append(.init(id: id + "-task", label: "Task", value: (t["name"] as? String) ?? ""))
      f.append(.init(id: id + "-task-params", label: "Task parameters", value: Checks.compact(t["params"]), style: .code))
    }
    // what the app has no row for, as it is: a field it doesn't know, or a known one of another type
    var rest: [String: Any] = [:]
    for (k, v) in c where !Kernel.settingsKeys.contains(k) { rest[k] = v }
    if Checks.attachments(c) == nil { rest["attachments"] = c["attachments"] }
    if Checks.content(c) == nil { rest["content"] = c["content"] }
    if !rest.isEmpty { f.append(.init(id: id + "-other", label: "Other settings", value: Kernel.pretty(rest), style: .warning)) }
    return f
  }

  /// one succession cert the phone signs, every field rendered from its payload
  static func cert(_ c: KSuccession, id: String, cmd: String? = nil) -> [SignedFact] {
    var f: [SignedFact] = [.init(id: id + "-signer", label: "Signed by", value: c.signer == "phone" ? "This iPhone" : c.signer)]
    f += object(c.predecessor, id: id + "-from", label: "From")
    f += object(c.successor, id: id + "-to", label: "To")
    let a = c.pair.allowed
    if a.isEverything {
      f.append(.init(id: id + "-allowed", label: "Allows", value: "Everything the source holds", style: c.predecessor.kind == .source ? .plain : .warning))
    } else {
      if a.cofinite { f.append(.init(id: id + "-allowed", label: "Allows", value: "Everything except", style: .warning)) }
      else if a.elems.isEmpty { f.append(.init(id: id + "-allowed", label: "Allows", value: "Nothing")) }
      for (i, x) in a.elems.enumerated() {
        let r = element(x, cmd: cmd)
        f.append(.init(id: "\(id)-allowed-\(i)", label: (a.cofinite ? "Except " : "Allows ") + r.label.lowercased(), value: r.value, style: r.style))
      }
    }
    if c.pair.conditions.isEmpty { f.append(.init(id: id + "-conditions", label: "Conditions", value: "None")) }
    for (i, x) in c.pair.conditions.enumerated() {
      let r = element(x, cmd: cmd)
      f.append(.init(id: "\(id)-condition-\(i)", label: "If " + r.label.lowercased(), value: r.value, style: r.style))
    }
    return f
  }

  /// an approval: its kind, then each draft as signed
  static func approval(_ r: ReviewedApproval, cmd: String? = nil) -> [SignedFact] {
    let action: String = switch r.kind {
    case "new-session": "New session"
    case "resume-upgrade": "Continue from a snapshot"
    case "terminal": "Open a terminal"
    case "command": "Run a command"
    case "add-store": "Add a store"
    default: r.kind
    }
    var f: [SignedFact] = [.init(id: "kind", label: "Kind", value: "Succession certs"), .init(id: "action", label: "Action", value: action)]
    if r.drafts.count > 1 { f.append(.init(id: "certs", label: "Certs", value: "\(r.drafts.count)")) }
    for (i, d) in r.drafts.enumerated() { f += cert(d.cert, id: "d\(i + 1)", cmd: cmd) }
    return f
  }

  /// unlocks: per store, open to every grant that names it until locked
  static func unlock(stores: [String], session: String?) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Secrets request"),
      .init(id: "action", label: "Action", value: stores.isEmpty ? "Nothing to unlock" : "Unlock stores"),
    ]
    if let session { f.append(.init(id: "session", label: "For session", value: session, style: .code)) }
    if !stores.isEmpty { f += scope(stores, id: "stores", label: "Stores") }
    return f
  }

  /// the stores an approval also unlocks under its Face ID
  static func alsoUnlocks(_ stores: [String]) -> [SignedFact] { stores.isEmpty ? [] : scope(stores, id: "unlocks", label: "Also unlocks") }

  private static func scope(_ stores: [String], id: String, label: String) -> [SignedFact] {
    [.init(id: id, label: label, value: list(stores), style: .code),
     .init(id: "unlock-scope", label: "Open to", value: "Every session whose grant names it"),
     .init(id: "relock", label: "Locked again", value: "When you lock it")]
  }

  /// root's ⊤ on the sink: signed with the root key, behind its own warning screen
  static func rootGrant() -> [SignedFact] {
    [.init(id: "kind", label: "Kind", value: "Root grant"),
     .init(id: "key", label: "Signed by", value: "The root key", style: .warning),
     .init(id: "machine", label: "On", value: "Sink"),
     .init(id: "allowed", label: "Allows", value: "Everything", style: .warning),
     .init(id: "conditions", label: "Conditions", value: "None", style: .warning),
     .init(id: "payload", label: "Exact text", value: Kernel.rootGrantPayload, style: .code)]
  }

  /// the request's call as one line: `POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}`
  static func call(method: String, path: String, args: [String: Any]?) -> String {
    var s = "\(method) \(path)"
    if let args, !args.isEmpty, let d = try? JSONSerialization.data(withJSONObject: args, options: [.sortedKeys, .withoutEscapingSlashes]) {
      s += " " + String(decoding: d, as: UTF8.self)
    }
    return s
  }

  /// the keys of the page's own options that must equal the request's (so the request shown is the one this page
  /// acts on); "" = they match
  static func mismatch(page: [String: Any], request: [String: Any]) -> String {
    for k in ["approvalId", "action", "repo", "sessionId", "store", "seq"] {
      let a = page[k].map { "\($0)" } ?? "", b = request[k].map { "\($0)" } ?? ""
      if k == "repo" ? a.lowercased() != b.lowercased() : a != b { return k }
    }
    return ""
  }
}
