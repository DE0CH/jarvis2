// The kernel's formats on the phone (core/kernel/README.md, docs/DESIGN.md "Target design"), with no UI, network or
// Keychain in it, so the interop and golden-vector tests (ios/interop) compile the same file:
//   - a set: {"only":[…]} (finite) or {"except":[…]} (everything but those); strings sorted by byte order, each once,
//     1–1024 bytes of UTF-8. Conditions: a sorted array of such strings. A pair is (allowed, conditions); ⊤ = everything, ∅.
//   - an object: {"id":"sink"} | {"id":"source-<32 hex>","image","settings","snapshot"} (each optional) |
//     {"id":"<fly id>","signingKey","encryptionKey"}; compared whole.
//   - a succession cert {kind "succession", signer, predecessor, successor, allowed, conditions}; a challenge of the log
//     notary; a notarization; a grant {kind "grant", by, machine, allowed, conditions, from}.
// Payloads are read strictly, as the kernel reads them: an unknown field refuses the document.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

// ---- sets and conditions ---------------------------------------------------------------------------------------------
struct KSet: Equatable {
  /// true: every string but `elems`
  let cofinite: Bool
  /// sorted by byte order, each once
  let elems: [String]

  static let everything = KSet(cofinite: true, elems: [])
  static func only(_ xs: [String]) -> KSet { KSet(cofinite: false, elems: Array(Set(xs)).sorted(by: Kernel.byteLess)) }
  var isEverything: Bool { cofinite && elems.isEmpty }
  func contains(_ x: String) -> Bool { cofinite != elems.contains(x) }

  /// strictly: one key, "only" or "except", with a valid sorted list
  static func parse(_ v: Any?) throws -> KSet {
    guard let d = v as? [String: Any], d.count == 1, let first = d.first, first.key == "only" || first.key == "except" else {
      throw TrustError.mismatch(#"a set that isn't {"only":[…]} or {"except":[…]}"#)
    }
    return KSet(cofinite: first.key == "except", elems: try Kernel.strings(first.value))
  }
  var json: [String: Any] { [cofinite ? "except" : "only": elems] }

  // the set algebra (golden vectors; the kernel's own, never needed to decide what to sign)
  func subset(of b: KSet) -> Bool {
    switch (cofinite, b.cofinite) {
    case (false, false): return Set(elems).isSubset(of: b.elems)
    case (false, true): return Set(elems).isDisjoint(with: b.elems)
    case (true, false): return false
    case (true, true): return Set(b.elems).isSubset(of: elems)
    }
  }
  func intersect(_ b: KSet) -> KSet {
    switch (cofinite, b.cofinite) {
    case (false, false): return KSet(cofinite: false, elems: elems.filter { b.elems.contains($0) })
    case (false, true): return KSet(cofinite: false, elems: elems.filter { !b.elems.contains($0) })
    case (true, false): return b.intersect(self)
    case (true, true): return KSet(cofinite: true, elems: Array(Set(elems).union(b.elems)).sorted(by: Kernel.byteLess))
    }
  }
  func union(_ b: KSet) -> KSet {
    switch (cofinite, b.cofinite) {
    case (false, false): return KSet(cofinite: false, elems: Array(Set(elems).union(b.elems)).sorted(by: Kernel.byteLess))
    case (false, true): return KSet(cofinite: true, elems: b.elems.filter { !elems.contains($0) })
    case (true, false): return b.union(self)
    case (true, true): return KSet(cofinite: true, elems: elems.filter { b.elems.contains($0) })
    }
  }
}

/// a permission pair (allowed covariant, conditions contravariant)
struct KPair: Equatable {
  let allowed: KSet
  let conditions: [String]
  static let top = KPair(allowed: .everything, conditions: [])
  var isTop: Bool { allowed.isEverything && conditions.isEmpty }
  func leq(_ q: KPair) -> Bool { allowed.subset(of: q.allowed) && Set(q.conditions).isSubset(of: conditions) }
  func meet(_ q: KPair) -> KPair {
    KPair(allowed: allowed.intersect(q.allowed), conditions: Array(Set(conditions).union(q.conditions)).sorted(by: Kernel.byteLess))
  }
}

// ---- objects ----------------------------------------------------------------------------------------------------------
struct KObject: Equatable {
  enum Kind: String { case sink, source, machine }
  let id: String
  var image = "", settings = "", snapshot = ""
  var signingKey = "", encryptionKey = ""

  var kind: Kind {
    if id == "sink" { return .sink }
    if Kernel.matches(id, "^source-[0-9a-f]{32}$") { return .source }
    return .machine
  }
  static let sink = KObject(id: "sink")

  /// strictly, with the kernel's rules for each shape (core/kernel/docs.go Object.Valid)
  static func parse(_ v: Any?) throws -> KObject {
    guard let d = v as? [String: Any] else { throw TrustError.mismatch("an object that isn't a JSON object") }
    let known: Set<String> = ["id", "image", "settings", "snapshot", "signingKey", "encryptionKey"]
    guard Set(d.keys).isSubset(of: known) else { throw TrustError.mismatch("an object with fields this app doesn't know") }
    func str(_ k: String) throws -> String {
      guard let x = d[k] else { return "" }
      guard let s = x as? String else { throw TrustError.mismatch("an object's \(k) that isn't text") }
      return s
    }
    let o = KObject(id: try str("id"), image: try str("image"), settings: try str("settings"), snapshot: try str("snapshot"),
                    signingKey: try str("signingKey"), encryptionKey: try str("encryptionKey"))
    try o.valid()
    return o
  }

  func valid() throws {
    let src = !image.isEmpty || !settings.isEmpty || !snapshot.isEmpty
    let keys = !signingKey.isEmpty || !encryptionKey.isEmpty
    switch kind {
    case .sink:
      guard !src && !keys else { throw TrustError.mismatch("a sink with contents or keys") }
    case .source:
      guard !keys else { throw TrustError.mismatch("a source with keys of its own") }
      guard image.utf8.count <= 512, Kernel.matches(image, "^[\\x21-\\x7e]*$"), settings.utf8.count <= 64 << 10 else {
        throw TrustError.mismatch("a source's image or settings out of bounds")
      }
      guard snapshot.isEmpty || Kernel.matches(snapshot, "^[0-9a-f]{64}$") else { throw TrustError.mismatch("a source's snapshot that isn't a sha256") }
    case .machine:
      guard Kernel.matches(id, "^[0-9a-z]{1,32}$") else { throw TrustError.mismatch("\(id) isn't sink, a source or a Fly machine") }
      guard !src else { throw TrustError.mismatch("a machine with a source's contents") }
      guard Kernel.point(signingKey), Kernel.point(encryptionKey) else { throw TrustError.mismatch("machine \(id)'s keys") }
    }
  }
}

// ---- documents --------------------------------------------------------------------------------------------------------
/// a succession cert (predecessor, successor, P)
struct KSuccession: Equatable {
  let signer: String
  let predecessor: KObject
  let successor: KObject
  let pair: KPair

  static let signers: Set<String> = ["phone", "root", "spawner", "identity", "gullible"]
  static func parse(_ payload: String) throws -> KSuccession {
    let d = try Kernel.object(payload, keys: ["kind", "signer", "predecessor", "successor", "allowed", "conditions"], what: "succession cert")
    guard d["kind"] as? String == "succession" else { throw TrustError.mismatch("not a succession cert") }
    guard let s = d["signer"] as? String, signers.contains(s) else { throw TrustError.mismatch("a cert's signer") }
    return KSuccession(signer: s, predecessor: try KObject.parse(d["predecessor"]), successor: try KObject.parse(d["successor"]),
                       pair: KPair(allowed: try KSet.parse(d["allowed"]), conditions: try Kernel.strings(d["conditions"])))
  }
}

/// the log notary's challenge
struct KChallenge: Equatable {
  let seq: Int, prev: String, at: String, subject: String, about: String, nonce: String
  static func parse(_ payload: String) throws -> KChallenge {
    let d = try Kernel.object(payload, keys: ["kind", "seq", "prev", "at", "subject", "about", "nonce"], what: "challenge")
    guard d["kind"] as? String == "challenge", let seq = d["seq"] as? Int, let prev = d["prev"] as? String, let at = d["at"] as? String,
          let subject = d["subject"] as? String, let about = d["about"] as? String, let nonce = d["nonce"] as? String else {
      throw TrustError.mismatch("not a challenge")
    }
    guard Kernel.matches(subject, "^[0-9a-f]{64}$"), Kernel.matches(about, "^[a-z][a-z0-9-]{0,63}$") else { throw TrustError.mismatch("a challenge's subject or about") }
    return KChallenge(seq: seq, prev: prev, at: at, subject: subject, about: about, nonce: nonce)
  }
}

/// a grant (by the mover, the merger, or ⊤ on the sink by the root key)
struct KGrant: Equatable {
  let by: String
  let machine: KObject
  let pair: KPair
  let from: [String]
  static func parse(_ payload: String) throws -> KGrant {
    let d = try Kernel.object(payload, keys: ["kind", "by", "machine", "allowed", "conditions", "from"], what: "grant")
    guard d["kind"] as? String == "grant", let by = d["by"] as? String, ["mover", "merger", "root"].contains(by),
          let from = d["from"] as? [String] else { throw TrustError.mismatch("not a grant") }
    return KGrant(by: by, machine: try KObject.parse(d["machine"]),
                  pair: KPair(allowed: try KSet.parse(d["allowed"]), conditions: try Kernel.strings(d["conditions"])), from: from)
  }
}

/// a cert with its challenge and the notarizer's notarization
struct KNotarized: Codable, Equatable { let cert: SignedDoc; let challenge: SignedDoc; let notarization: SignedDoc }

/// the public keys of the kernel's parts, each vouched for by the box key (keys/box.pub)
struct KRoster: Equatable {
  var keys: [String: String] = [:]
  /// the parts the app checks documents of
  static let parts = ["notary", "notarizer", "mover", "merger", "identity", "gullible", "spawner", "secrets"]
  func key(_ role: String) throws -> String {
    guard let k = keys[role], !k.isEmpty else { throw TrustError.mismatch("no key for the \(role) that the box key vouches for") }
    return k
  }
}

enum Kernel {
  /// ⊤ on the sink, the one grant the root key makes: exactly these bytes are signed (testdata/grants.json "root")
  static let rootGrantPayload = #"{"kind":"grant","by":"root","machine":{"id":"sink"},"allowed":{"except":[]},"conditions":[],"from":[]}"#

  static func id(_ d: SignedDoc) -> String { CoreCrypto.sha256hex(Data(d.payload.utf8)) }
  static func byteLess(_ a: String, _ b: String) -> Bool { Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8)) }
  static func matches(_ s: String, _ re: String) -> Bool { s.range(of: re, options: .regularExpression) != nil }
  /// a 65-byte uncompressed P-256 point, base64
  static func point(_ s: String) -> Bool {
    guard let d = Data(base64Encoded: s), d.count == 65 else { return false }
    return (try? P256.Signing.PublicKey(x963Representation: d)) != nil
  }

  /// a JSON object with no field outside `keys` (and every one of them present)
  static func object(_ payload: String, keys: Set<String>, what: String) throws -> [String: Any] {
    guard let d = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else { throw TrustError.mismatch("a \(what) that isn't JSON") }
    guard Set(d.keys) == keys else { throw TrustError.mismatch("a \(what) with fields this app doesn't know") }
    return d
  }
  /// a sorted list of distinct strings, each 1–1024 bytes
  static func strings(_ v: Any?) throws -> [String] {
    guard let xs = v as? [String] else { throw TrustError.mismatch("a list of strings") }
    for (i, x) in xs.enumerated() {
      guard !x.isEmpty, x.utf8.count <= 1024 else { throw TrustError.mismatch("a string of 1 to 1024 bytes") }
      if i > 0 && !byteLess(xs[i - 1], x) { throw TrustError.mismatch("strings sorted by byte order, each once") }
    }
    return xs
  }

  /// what the box key signs for a part: "jarvis2-<role>-identity <signingKey> <agreementKey>"
  static func identityText(role: String, signingKey: String, agreementKey: String) -> String {
    "jarvis2-\(role)-identity \(signingKey) \(agreementKey)"
  }
  struct Identity: Codable, Equatable {
    let role: String; let signingKey: String; var agreementKey: String? = nil; var boxSig: String? = nil
  }
  /// a part's identity, if the box key vouches for it
  static func vouched(_ id: Identity, role: String, boxKey: String) -> Bool {
    guard id.role == role, point(id.signingKey), let sig = id.boxSig else { return false }
    return CoreCrypto.valid(Data(identityText(role: role, signingKey: id.signingKey, agreementKey: id.agreementKey ?? "").utf8), sig: sig, by: boxKey)
  }
  /// the roster from GET /api/kernel/identities: only the parts the box key vouches for
  static func roster(_ ids: [String: Identity?], boxKey: String) -> KRoster {
    var r = KRoster()
    for role in KRoster.parts { if let x = ids[role] ?? nil, vouched(x, role: role, boxKey: boxKey) { r.keys[role] = x.signingKey } }
    return r
  }

  /// a cert signed by `key` (its payload read strictly)
  static func openSuccession(_ d: SignedDoc, key: String) throws -> KSuccession {
    let s = try KSuccession.parse(d.payload)
    guard CoreCrypto.valid(Data(d.payload.utf8), sig: d.sig, by: key) else { throw TrustError.badSignature("the \(s.signer)'s cert") }
    return s
  }
  /// a notarized cert: the cert by its signer's key, the challenge by the notary's and for this cert, the notarization by
  /// the notarizer's and for both. `signerKey`: the key the cert's signer has (the roster's for a part)
  static func openNotarized(_ nc: KNotarized, roster: KRoster, signerKey: String? = nil) throws -> KSuccession {
    let s = try KSuccession.parse(nc.cert.payload)
    let k = try signerKey ?? roster.key(s.signer)
    guard CoreCrypto.valid(Data(nc.cert.payload.utf8), sig: nc.cert.sig, by: k) else { throw TrustError.badSignature("the \(s.signer)'s cert") }
    let ch = try KChallenge.parse(nc.challenge.payload)
    guard CoreCrypto.valid(Data(nc.challenge.payload.utf8), sig: nc.challenge.sig, by: try roster.key("notary")) else { throw TrustError.badSignature("the log notary's challenge") }
    guard ch.subject == id(nc.cert), ch.about == "succession" else { throw TrustError.mismatch("a challenge for another cert") }
    let n = try object(nc.notarization.payload, keys: ["kind", "cert", "challenge"], what: "notarization")
    guard CoreCrypto.valid(Data(nc.notarization.payload.utf8), sig: nc.notarization.sig, by: try roster.key("notarizer")) else { throw TrustError.badSignature("the notarization") }
    guard n["kind"] as? String == "notarization", n["cert"] as? String == id(nc.cert), n["challenge"] as? String == id(nc.challenge) else {
      throw TrustError.mismatch("a notarization of another cert")
    }
    return s
  }
  /// a grant by the mover or the merger, signed by that part's vouched key
  static func openGrant(_ d: SignedDoc, roster: KRoster) throws -> KGrant {
    let g = try KGrant.parse(d.payload)
    guard g.by == "mover" || g.by == "merger" else { throw TrustError.mismatch("a grant by \(g.by)") }
    guard CoreCrypto.valid(Data(d.payload.utf8), sig: d.sig, by: try roster.key(g.by)) else { throw TrustError.badSignature("the \(g.by)'s grant") }
    return g
  }

  /// the start settings a source carries (docs/API-grants.md "Start settings"): a JSON object, or nil when they aren't one
  static func settings(_ s: String) -> [String: Any]? {
    guard !s.isEmpty else { return nil }
    return (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any]
  }
  /// the fields of the start settings the app knows (machine/settings.go Settings); others are shown pretty-printed
  static let settingsKeys: Set<String> = ["v", "session", "harness", "permissionMode", "title", "model", "repos", "content", "oneShot",
                                          "apiProxy", "prompt", "attachments", "rollback", "task"]
  /// a JSON value pretty-printed, keys sorted (what the page shows of a value it has no row for)
  static func pretty(_ v: Any) -> String {
    guard JSONSerialization.isValidJSONObject(v),
          let d = try? JSONSerialization.data(withJSONObject: v, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { return "\(v)" }
    return String(decoding: d, as: UTF8.self)
  }
  /// a string that is a JSON object or array, pretty-printed; nil for anything else
  static func prettyJSON(_ s: String) -> String? {
    guard let f = s.first, f == "{" || f == "[", let v = try? JSONSerialization.jsonObject(with: Data(s.utf8)) else { return nil }
    return pretty(v)
  }
  /// "until:<RFC 3339>" as the guard reads it (2026-10-14T12:10Z and full RFC 3339)
  static func untilDate(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    for o: ISO8601DateFormatter.Options in [[.withInternetDateTime], [.withInternetDateTime, .withFractionalSeconds],
                                            [.withFullDate, .withTime, .withDashSeparatorInDate, .withColonSeparatorInTime, .withTimeZone]] {
      f.formatOptions = o
      if let d = f.date(from: s) { return d }
    }
    return nil
  }
}
