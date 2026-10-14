// What an approval asks the phone to sign (docs/API.md "Approvals"): one or two succession certs, drafted by the router,
// each with the log notary's challenge over its payload. The page signs exactly each draft's payload, so everything it
// shows is read from those payloads (never from the router's label or options), and what it refuses is decided here:
//   new-session     (sink, source-x, P): a source with an image and settings, P = the session's stores on session:<id>
//   resume-upgrade  (sink, source-z, P): the same, starting from a snapshot
//   terminal        (sink, source-a, ({shell}, {session:S, until:T})) and (source-a, M, ⊤)
//   command         (sink, source-a, ({shell}, {cmd:<sha256>, once:<id>, session:S, until:T})) and (source-a, M, ⊤)
//   add-store       (sink, source-a, ({store:X}, {session:S})) and (source-a, M, ⊤)
// M, the machine an add-on reaches, must be the session's running machine: the spawner's notarized spawn cert names it,
// coming out of a source whose settings name session S (Checks.machineOf). No UI, network or Keychain here.
import Foundation

/// one draft, read: the cert the phone will sign and its exact payload
struct ReviewedDraft: Equatable {
  let payload: String
  let cert: KSuccession
}

/// an approval as the router serves it (GET api/state `approvals`)
struct ApprovalDTO: Decodable, Equatable {
  struct Draft: Decodable, Equatable { let payload: String; let challenge: SignedDoc }
  let id: String
  let kind: String
  var session: String? = nil
  var machine: String? = nil
  var label: String? = nil
  let drafts: [Draft]
  var imageSig: String? = nil
  var cmd: String? = nil
  var store: String? = nil
  var options: [String: String]? = nil
  var explanation: String? = nil
}

/// an approval whose drafts were read and checked for its kind
struct ReviewedApproval {
  let kind: String
  let session: String
  let drafts: [ReviewedDraft]
  /// the source the first draft makes
  var source: KObject { drafts[0].cert.successor }
  /// its start settings (new-session, resume-upgrade)
  var settings: [String: Any]? { Kernel.settings(source.settings) }
  /// the stores the first draft allows (its finite `store:` strings)
  var stores: [String] { drafts[0].cert.pair.allowed.cofinite ? [] : drafts[0].cert.pair.allowed.elems.compactMap { $0.hasPrefix("store:") ? String($0.dropFirst(6)) : nil } }
  /// the machine an add-on's second draft reaches
  var machine: KObject? { drafts.count == 2 ? drafts[1].cert.successor : nil }
  /// an add-on's `until` condition
  var until: Date? { drafts[0].cert.pair.conditions.first { $0.hasPrefix("until:") }.flatMap { Kernel.untilDate(String($0.dropFirst(6))) } }
  var harness: String { (settings?["harness"] as? String) ?? "" }
  var permissionMode: String { (settings?["permissionMode"] as? String) == "bypass" ? "bypass" : "auto" }
  var title: String? { (settings?["title"] as? String).flatMap { $0.isEmpty ? nil : $0 } }
  var isAddOn: Bool { ["terminal", "command", "add-store"].contains(kind) }
}

extension Checks {
  static let approvalKinds: Set<String> = ["new-session", "resume-upgrade", "terminal", "command", "add-store"]
  /// the longest add-on a page signs (terminal: 10 minutes; a command: 10 minutes to run once), with a minute of slack
  static let addOnMax: TimeInterval = 11 * 60

  /// every draft read strictly, signed by the phone, its challenge the notary's over exactly this payload (`notaryKey`:
  /// the vouched notary key, checked when known), and the shape the approval's kind has
  static func review(_ a: ApprovalDTO, notaryKey: String?, now: Date = Date()) throws -> ReviewedApproval {
    guard approvalKinds.contains(a.kind) else { throw TrustError.mismatch("an approval this app doesn't know (\(a.kind))") }
    guard let sid = a.session, !sid.isEmpty else { throw TrustError.mismatch("an approval for no session") }
    var drafts: [ReviewedDraft] = []
    for d in a.drafts {
      let c = try KSuccession.parse(d.payload)
      guard c.signer == "phone" else { throw TrustError.mismatch("a draft for the \(c.signer) to sign, not this iPhone") }
      let ch = try KChallenge.parse(d.challenge.payload)
      guard ch.subject == CoreCrypto.sha256hex(Data(d.payload.utf8)), ch.about == "succession" else { throw TrustError.stale("a challenge for another draft") }
      if let k = notaryKey, !CoreCrypto.valid(Data(d.challenge.payload.utf8), sig: d.challenge.sig, by: k) { throw TrustError.badSignature("the log notary's challenge") }
      drafts.append(ReviewedDraft(payload: d.payload, cert: c))
    }
    let r = ReviewedApproval(kind: a.kind, session: sid, drafts: drafts)
    let session = "session:" + sid
    func storesOnly(_ c: KSuccession) throws {
      guard !c.pair.allowed.cofinite, c.pair.allowed.elems.allSatisfy({ $0.hasPrefix("store:") && $0.count > 6 }) else {
        throw TrustError.mismatch("rights other than stores")
      }
    }
    switch a.kind {
    case "new-session", "resume-upgrade":
      guard drafts.count == 1 else { throw TrustError.mismatch("\(drafts.count) drafts for a \(a.kind)") }
      let c = drafts[0].cert
      guard c.predecessor == .sink, c.successor.kind == .source else { throw TrustError.mismatch("not a new source out of the sink") }
      guard !c.successor.image.isEmpty else { throw TrustError.mismatch("a source with no image") }
      guard let st = r.settings else { throw TrustError.mismatch("start settings that aren't a JSON object") }
      guard st["session"] as? String == sid else { throw TrustError.mismatch("settings for another session") }
      guard c.pair.conditions == [session] else { throw TrustError.mismatch("conditions other than this session") }
      try storesOnly(c)
      if a.kind == "resume-upgrade" { guard !c.successor.snapshot.isEmpty else { throw TrustError.mismatch("a resume with no snapshot") } }
    default:
      guard drafts.count == 2 else { throw TrustError.mismatch("\(drafts.count) drafts for a \(a.kind)") }
      let (c1, c2) = (drafts[0].cert, drafts[1].cert)
      guard c1.predecessor == .sink, c1.successor.kind == .source, c1.successor.image.isEmpty, c1.successor.settings.isEmpty,
            c1.successor.snapshot.isEmpty else { throw TrustError.mismatch("an add-on that isn't a bare source out of the sink") }
      guard c2.predecessor == c1.successor, c2.successor.kind == .machine, c2.pair.isTop else {
        throw TrustError.mismatch("an add-on's second cert isn't (that source, a machine, ⊤)")
      }
      let conds = Set(c1.pair.conditions)
      switch a.kind {
      case "terminal", "command":
        guard c1.pair.allowed == .only(["shell"]) else { throw TrustError.mismatch("rights other than a shell") }
        guard let t = r.until, t > now.addingTimeInterval(-60), t <= now.addingTimeInterval(addOnMax) else { throw TrustError.mismatch("until (at most 10 minutes)") }
        if a.kind == "terminal" {
          guard c1.pair.conditions.count == 2, conds.contains(session) else { throw TrustError.mismatch("a terminal's conditions") }
        } else {
          guard let cmd = a.cmd, !cmd.isEmpty else { throw TrustError.mismatch("a command with no text") }
          let once = c1.pair.conditions.filter { $0.hasPrefix("once:") }
          guard c1.pair.conditions.count == 4, conds.contains(session), conds.contains("cmd:" + CoreCrypto.sha256hex(Data(cmd.utf8))), once.count == 1 else {
            throw TrustError.mismatch("a command's conditions (not this command, once, this session)")
          }
        }
      default: // add-store
        guard let st = a.store, c1.pair.allowed == .only(["store:" + st]), c1.pair.conditions == [session] else {
          throw TrustError.mismatch("an added store's rights or conditions")
        }
      }
    }
    return r
  }

  /// The machine an add-on reaches is the session's running machine: the spawner's notarized spawn cert (source, M, ⊤)
  /// names M exactly, out of a source whose settings name this session. Returns that source's settings (its title).
  static func machineOf(_ r: ReviewedApproval, spawn: KNotarized, roster: KRoster) throws -> [String: Any] {
    let s = try Kernel.openNotarized(spawn, roster: roster)
    guard s.signer == "spawner", s.pair.isTop, s.predecessor.kind == .source else { throw TrustError.mismatch("not the spawner's spawn cert") }
    guard let m = r.machine, s.successor == m else { throw TrustError.mismatch("the machine isn't the one the session runs on") }
    guard let st = Kernel.settings(s.predecessor.settings), st["session"] as? String == r.session else {
      throw TrustError.mismatch("the machine runs another session")
    }
    return st
  }

  /// what the New session page chose: the signed source must carry exactly these settings
  struct Settings {
    var label: String; var prompt: String; var model: String; var repos: [String]; var oneShot: Bool; var apiProxy: Bool
    var attachments: [Attachment] = []
    var content: [String] = []
  }
  /// an attached file as the signed settings name it: the sha256 and size are of the bytes this phone uploaded
  struct Attachment: Equatable { var name: String; var sha256: String; var size: Int }

  /// the settings' attachments, as signed (nil: not a list of {name, sha256, size})
  static func attachments(_ c: [String: Any]) -> [Attachment]? {
    guard let v = c["attachments"] else { return [] }
    guard let list = v as? [[String: Any]] else { return nil }
    var out: [Attachment] = []
    for a in list {
      guard Set(a.keys) == ["name", "sha256", "size"], let n = a["name"] as? String, let h = a["sha256"] as? String,
            let z = a["size"] as? Int else { return nil }
      out.append(Attachment(name: n, sha256: h, size: z))
    }
    return out
  }
  /// the settings' content stores (nil: not a list of store names)
  static func content(_ c: [String: Any]) -> [String]? {
    guard let v = c["content"] else { return [] }
    guard let list = v as? [String] else { return nil }
    for n in list where !Kernel.matches(n, "^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$") { return nil }
    return list
  }

  /// New session: the draft carries exactly the stores picked on the page plus the harness's own (`harnessStores`: the
  /// router's list; Checks.onlyHarnessExtras then holds the extras to the pinned policy), the harness, the permission
  /// mode and these settings; no snapshot, task or rollback
  static func matchesPicked(_ r: ReviewedApproval, stores picked: [String], harnessStores: [String], harness: String, permissionMode: String, settings s: Settings) throws {
    guard r.kind == "new-session" else { throw TrustError.mismatch("not a new session") }
    guard r.stores == Array(Set(picked + harnessStores)).sorted() else { throw TrustError.mismatch("stores") }
    guard r.source.snapshot.isEmpty else { throw TrustError.mismatch("a snapshot") }
    guard let c = r.settings else { throw TrustError.mismatch("settings") }
    func str(_ k: String) -> String { (c[k] as? String) ?? "" }
    guard Set(c.keys).isSubset(of: Kernel.settingsKeys) else { throw TrustError.mismatch("settings this page didn't choose") }
    guard r.harness == harness else { throw TrustError.mismatch("harness") }
    guard str("permissionMode") == (permissionMode == "bypass" ? "bypass" : "auto") else { throw TrustError.mismatch("permission mode") }
    guard str("title") == s.label else { throw TrustError.mismatch("title") }
    guard str("prompt") == s.prompt else { throw TrustError.mismatch("first prompt") }
    if !s.model.isEmpty { guard str("model") == s.model else { throw TrustError.mismatch("model") } }
    guard ((c["repos"] as? [String]) ?? []) == s.repos else { throw TrustError.mismatch("repos") }
    guard ((c["oneShot"] as? Bool) ?? false) == s.oneShot else { throw TrustError.mismatch("one-shot") }
    guard ((c["apiProxy"] as? Bool) ?? false) == s.apiProxy else { throw TrustError.mismatch("API proxy") }
    guard attachments(c) == s.attachments else { throw TrustError.mismatch("attachments") }
    guard content(c) == s.content.sorted() else { throw TrustError.mismatch("content stores") }
    for k in ["task", "rollback"] where c[k] != nil { throw TrustError.mismatch(k) }
  }

  /// every store a new session's draft carries beyond those picked must be one the harness brings by the app's own pinned
  /// policy; returns those extras (the page marks any that is sensitive)
  static func onlyHarnessExtras(_ r: ReviewedApproval, picked: [String], pinnedHarness: [String], sensitive: [String] = []) throws -> [String] {
    let extra = r.stores.filter { !picked.contains($0) }
    for n in extra where !pinnedHarness.contains(n) {
      throw TrustError.mismatch("store \(n) wasn't picked and isn't the harness's\(sensitive.contains(n) ? " (and it is sensitive)" : "")")
    }
    return extra
  }
}
