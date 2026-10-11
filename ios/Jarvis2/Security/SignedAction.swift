// "What you sign (exact)": the first of the three fields a request's review page shows (docs/DESIGN.md
// "Requests"). It is rendered here, in the app, from the very content the phone signs — the core's signed begin
// document, the core-signed challenge, the session's core-signed cert and the checked grant — never from the
// router's words, so a lying router can't make it say something other than what gets signed. Foundation only:
// the interop test (app/ios/interop) renders it from the real core's documents too.
import Foundation

enum SignedAction {
  static func list(_ xs: [String]) -> String { xs.isEmpty ? "none" : xs.joined(separator: ", ") }

  /// a deploy key, from the core's signed deploy-key-begin document
  static func deployKey(_ b: DeployKeyBegin) -> String {
    if b.action == "remove" {
      return "Core: delete the deploy key “\(b.title)” on \(b.repo) on GitHub and delete the store \(b.store)\(b.sensitive ? " (sensitive)" : ""), "
        + "using the GitHub token in store \(b.tokenStore) for this one call."
    }
    var s = "Core: make an SSH deploy key for \(b.repo) (read + push) and add it on GitHub as “\(b.title)”, using the GitHub token in store "
      + "\(b.tokenStore) for this one call; keep the private key in store \(b.store) (\(b.sensitive ? "sensitive" : "not sensitive"))."
    if b.replaces { s += " \(b.store) exists: its contents are replaced and the earlier key “\(b.title)” is deleted on GitHub." }
    return s
  }

  /// the signed settings and one-time inputs, word for word (what the machine takes: docs/DESIGN.md "Inputs")
  static func inputs(_ r: Checks.Reviewed) -> String {
    var s = ""
    if let c = r.challenge.request.options.config, !c.isEmpty { s += " Settings it takes: \(Checks.compact(r.config))." }
    else if r.kind == .newSession || r.kind == .resumeUpgrade { s += " No settings travel in the cert (this core doesn't carry them): no prompt, title, model or repos beyond the stores' own." }
    if let o = r.challenge.request.options.once, !o.isEmpty { s += " One-time inputs for this machine: \(Checks.compact(r.once))." }
    return s
  }

  /// a succession, from the core-signed challenge (Checks.review)
  /// `of`: the session the challenge continues, from its predecessor's core-signed cert (Checks.continues)
  static func approval(_ r: Checks.Reviewed, of id: LineIdentity? = nil) -> String {
    let sens = r.sensitive.isEmpty ? "" : " (sensitive: \(list(r.sensitive)))"
    switch r.kind {
    case .newSession:
      return "Core: approve a new session machine on image \(r.image) with stores \(list(r.stores))\(sens), harness \(r.harness), permission mode \(r.permissionMode)." + inputs(r)
    case .resumeUpgrade:
      return "Core: continue the paused session \(id?.words ?? "") on a new machine on image \(r.image) with stores \(list(r.stores))\(sens), harness \(r.harness), permission mode \(r.permissionMode)." + inputs(r)
    case .addStore:
      let added = r.addedStore ?? ""
      return "Core: add store \(added)\(r.sensitive.contains(added) ? " (sensitive)" : "") to the running machine \(r.challenge.request.machine?.id ?? "") of \(id?.words ?? "its session"), which keeps its keys; it then holds \(list(r.stores))."
    case .other:
      return "Core: sign a challenge of kind \(r.challenge.request.kind) with stores \(list(r.stores))\(sens)."
    }
  }

  /// unlocks: the stores the session's core-signed cert names that the core's signed list shows locked. scoped =
  /// the core's signed store list says it takes unlocks for one session (then only this session's cert reads them
  /// and its pull locks them again); a core that predates that keeps them open until locked.
  static func unlock(stores: [String], session: String, scoped: Bool) -> String {
    if stores.isEmpty { return "Nothing: every store of “\(session)” is open already." }
    let what = "Core: unlock store\(stores.count == 1 ? "" : "s") \(list(stores)) for session “\(session)”"
    return scoped ? what + " only. The core locks \(stores.count == 1 ? "it" : "them") again as soon as the session's machine has its secrets."
      : what + ". Unlocked stores stay open (any session holding them can read them) until you lock them on the Stores page."
  }

  /// the stores an approval also unlocks under its Face ID (for that one session; scoped as above)
  static func alsoUnlocks(_ stores: [String], scoped: Bool) -> String {
    stores.isEmpty ? "" : " With the same Face ID: unlock \(list(stores)) " + (scoped ? "for this session only (locked again once its machine has its secrets)." : "(open until you lock them on the Stores page).")
  }

  /// a grant: signed by this iPhone (not the core) for the line in the session's core-signed cert; the router's draft
  /// is checked field for field against it before signing (Checks.reviewGrant)
  static func grant(meaning: String, line: String, of id: LineIdentity? = nil) -> String {
    "Phone grant for \(id?.words ?? "session line \(line)") (the session's machine checks it, not the core)\(id?.sensitive == true ? ", a session holding a sensitive store" : ""): \(meaning)"
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
    for k in ["approvalId", "action", "repo", "sessionId", "holder", "grantKind", "minutes"] {
      let a = page[k].map { "\($0)" } ?? "", b = request[k].map { "\($0)" } ?? ""
      if k == "repo" ? a.lowercased() != b.lowercased() : a != b { return k }
    }
    return ""
  }
}
