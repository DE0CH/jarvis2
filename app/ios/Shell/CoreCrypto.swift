// The shell's side of the core's formats (core/crypto.go, core/core.go), with no UI, network or Keychain in
// it, so the same file is compiled into the interop test (ios/interop) that runs it against the real core.
//   - a signed document is {payload, sig}: sig = base64 DER ECDSA-P256-SHA256 over the payload's bytes;
//   - public keys are base64 of the 65-byte uncompressed X9.63 point;
//   - Sealed {e, data}: ephemeral P-256 e, x(e·R) → HKDF-SHA256(salt empty, info, 32 bytes) → AES-256-GCM
//     combined (nonce‖ct‖tag). Infos: "jarvis2/unlock-share" (the phone's share x(p·E) to the core's one-off
//     key T), "jarvis2/claim" (the claim's bundle to the core), "jarvis2/backup" (a store backup to the
//     master key, the store's name as associated data).
// The core's identity: "jarvis2-core-identity <signingKey> <agreementKey>", signed by the box key (keys/box.pub),
// which the app checks itself before it trusts a core.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct SignedDoc: Codable, Equatable { let payload: String; let sig: String }

enum TrustError: LocalizedError, Equatable {
  case notSetUp, badKit(String), badSignature(String), mismatch(String), stale(String), backup(String)
  var errorDescription: String? {
    switch self {
    case .notSetUp: return "Jarvis 2 isn't set up on this iPhone yet — open Settings → Reset or recover."
    case .badKit(let s): return s
    case .badSignature(let s): return "The signature on \(s) didn't check out — refusing to continue."
    case .mismatch(let s): return "The core's answer doesn't match what you chose (\(s)) — refusing to sign."
    case .stale(let s): return "The core's answer isn't for this request (\(s)) — refusing to continue."
    case .backup(let s): return s
    }
  }
}

/// a P-256 key pair's public halves (the core's, the phone's)
struct PublicKeys: Codable, Equatable {
  let signingKey: String, agreementKey: String
  static func valid(_ k: PublicKeys) -> Bool {
    guard let s = Data(base64Encoded: k.signingKey), (try? P256.Signing.PublicKey(x963Representation: s)) != nil,
          let a = Data(base64Encoded: k.agreementKey), (try? P256.KeyAgreement.PublicKey(x963Representation: a)) != nil else { return false }
    return true
  }
}

enum CoreCrypto {
  static func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }
  static func sha256hex(_ d: Data) -> String { hex(SHA256.hash(data: d)) }

  /// a DER signature by `key` (base64 X9.63) over exactly `payload`
  static func valid(_ payload: Data, sig: String, by key: String) -> Bool {
    guard let k = Data(base64Encoded: key.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap({ try? P256.Signing.PublicKey(x963Representation: $0) }),
          let s = Data(base64Encoded: sig).flatMap({ try? P256.Signing.ECDSASignature(derRepresentation: $0) }) else { return false }
    return k.isValidSignature(s, for: payload)
  }
  /// the payload's bytes, only if `key` (base64 X9.63) signed them
  static func verified(_ doc: SignedDoc, by key: String, what: String) throws -> Data {
    let p = Data(doc.payload.utf8)
    guard valid(p, sig: doc.sig, by: key) else { throw TrustError.badSignature(what) }
    return p
  }
  static func decode<T: Decodable>(_ doc: SignedDoc, by key: String, as: T.Type, what: String) throws -> T {
    try JSONDecoder().decode(T.self, from: verified(doc, by: key, what: what))
  }

  // ---- sealing ----
  static let shareInfo = "jarvis2/unlock-share", claimInfo = "jarvis2/claim", backupInfo = "jarvis2/backup"
  static func seal(_ plain: Data, to recipient: String, info: String, aad: Data? = nil) throws -> [String: String] {
    guard let rb = Data(base64Encoded: recipient) else { throw TrustError.badSignature("the recipient key") }
    let rk = try P256.KeyAgreement.PublicKey(x963Representation: rb)
    let e = P256.KeyAgreement.PrivateKey()
    let key = try e.sharedSecretFromKeyAgreement(with: rk)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(info.utf8), outputByteCount: 32)
    let box: AES.GCM.SealedBox
    if let aad { box = try AES.GCM.seal(plain, using: key, authenticating: aad) } else { box = try AES.GCM.seal(plain, using: key) }
    guard let combined = box.combined else { throw TrustError.badSignature("sealing") }
    return ["e": e.publicKey.x963Representation.base64EncodedString(), "data": combined.base64EncodedString()]
  }
  static func open(_ sealed: [String: String], with priv: P256.KeyAgreement.PrivateKey, info: String, aad: Data? = nil) throws -> Data {
    guard let eb = Data(base64Encoded: sealed["e"] ?? ""), let e = try? P256.KeyAgreement.PublicKey(x963Representation: eb),
          let d = Data(base64Encoded: sealed["data"] ?? "") else { throw TrustError.backup("a sealed value is malformed") }
    let key = try priv.sharedSecretFromKeyAgreement(with: e)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(info.utf8), outputByteCount: 32)
    let box = try AES.GCM.SealedBox(combined: d)
    if let aad { return try AES.GCM.open(box, using: key, authenticating: aad) }
    return try AES.GCM.open(box, using: key)
  }
  /// seal the phone's 32-byte share x(p·E) to the core's one-off key T → {e, data}
  static func sealShare(_ x: Data, to t: String) throws -> [String: String] { try seal(x, to: t, info: shareInfo) }

  static func nonce() -> String {
    var g = SystemRandomNumberGenerator()
    return hex((0..<16).map { _ in UInt8.random(in: 0...255, using: &g) })
  }

  // ---- the core's identity ----
  static func identityText(_ k: PublicKeys) -> String { "jarvis2-core-identity \(k.signingKey) \(k.agreementKey)" }
  /// the box key (keys/box.pub, from GitHub) vouches for this core's keys
  static func identityVouched(_ k: PublicKeys, boxSig: String, boxKey: String) -> Bool {
    PublicKeys.valid(k) && valid(Data(identityText(k).utf8), sig: boxSig, by: boxKey)
  }
}

// ---- the recovery kit: what Deyao keeps in his password manager --------------------------------------
/// The master private key. It exists only inside the recovery kit: Reset makes it and shows the kit, Recover
/// reads it from the pasted kit; either way the app keeps it in memory just long enough to set the core up.
struct MasterKey {
  let signing: P256.Signing.PrivateKey
  var agreement: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation) }
  var publicKey: String { signing.publicKey.x963Representation.base64EncodedString() }
  /// a fresh pair, made in software so the private half can go into the recovery kit
  static func generate() -> MasterKey { MasterKey(signing: P256.Signing.PrivateKey()) }
  /// the kit's master part: base64 PKCS#8 DER (the body of a PEM "PRIVATE KEY" block)
  var pkcs8: String { signing.pemRepresentation.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined() }
  init(signing: P256.Signing.PrivateKey) { self.signing = signing }
  init(pkcs8 b64: String) throws {
    guard let d = Data(base64Encoded: b64.filter { !$0.isWhitespace }), let k = try? P256.Signing.PrivateKey(derRepresentation: d) else {
      throw TrustError.badKit("That isn't a recovery kit.")
    }
    signing = k
  }
  func sign(_ text: String) throws -> String { try signing.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString() }
  /// the public half is `pub` (base64 X9.63)
  func matches(_ pub: String) -> Bool { MasterKey.same(publicKey, pub) }
  static func same(_ a: String, _ b: String) -> Bool {
    guard let x = Data(base64Encoded: a.trimmingCharacters(in: .whitespacesAndNewlines)), !x.isEmpty else { return false }
    return x == Data(base64Encoded: b.trimmingCharacters(in: .whitespacesAndNewlines))
  }
}

/// The recovery kit: the ONE string Deyao keeps in his password manager — `jarvis2-kit:2:<master private key,
/// base64 PKCS#8 DER>`. Reset shows it; Recover takes it. Version 1 (which carried the backup bucket's read keys)
/// is refused: the router reads the backups now, and no core trusts a version-1 key.
struct RecoveryKit {
  let master: MasterKey
  static let prefix = "jarvis2-kit:2:"
  var string: String { RecoveryKit.prefix + master.pkcs8 }
  static func parse(_ raw: String) throws -> RecoveryKit {
    let s = raw.filter { !$0.isWhitespace }
    if s.hasPrefix("jarvis2-kit:1:") { throw TrustError.badKit("This recovery kit is from an older Jarvis 2 and doesn't work any more.") }
    guard s.hasPrefix(prefix), let m = try? MasterKey(pkcs8: String(s.dropFirst(prefix.count))) else { throw TrustError.badKit("That isn't a recovery kit.") }
    return RecoveryKit(master: m)
  }
}

// ---- the core's documents (core/core.go) ----
struct StartedMachine: Codable, Equatable { let id: String; let requested: String?; let image: String; let encryptionKey: String; let signingKey: String }
/// the core's signed options: the harness and the permission mode ("auto" | "bypass")
struct Options: Codable, Equatable { let harness: String?; var permissionMode: String? = nil }
struct SuccessionRequest: Codable {
  let kind: String
  let predecessor: SignedDoc?
  let predecessorId: String?
  let machine: StartedMachine?
  let image: String?
  let stores: [String]?
  let sensitive: [String]?
  let options: Options
  let addedStore: String?
  let downgrade: Bool?
}
struct Challenge: Codable { let kind: String; let nonce: String; let request: SuccessionRequest }
/// the core's answer to an approved challenge: an "approval" (a new line, bound to a machine later) or a
/// "succession-cert" (a running machine with one more store)
struct Answer: Codable { let kind: String; let nonce: String; let machine: StartedMachine? }
struct StoreView: Codable, Identifiable, Equatable {
  let name: String; let sensitive: Bool; let empty: Bool; let unlocked: Bool; var id: String { name }
  /// the store named `core` holds the core's own Fly token: it never shows for sessions
  static let coreStore = "core"
  var isCore: Bool { name == StoreView.coreStore }
}
struct StoresDoc: Codable { let kind: String; let nonce: String; let stores: [StoreView] }
struct UnlockRow: Codable, Identifiable, Equatable { let id: String; let store: String; let since: String }
struct UnlockedDoc: Codable { let kind: String; let nonce: String; let unlocked: [UnlockRow] }
struct UnlockBegin: Codable { let kind: String; let pending: String; let store: String; let e: String; let t: String }
struct KindDoc: Codable { let kind: String; let id: String?; let store: String?; let name: String?; let stores: Int?; let core: String? }

/// What a secure page shows for a challenge — read from the core-signed challenge itself, never from the
/// router's label — and the checks that what comes back answers it.
enum Checks {
  enum Kind: String { case newSession = "new-session", resumeUpgrade = "resume-upgrade", addStore = "add-store", other }
  struct Reviewed {
    let kind: Kind; let challenge: Challenge; let stores: [String]; let sensitive: [String]; let harness: String; let image: String; let addedStore: String?
    /// from the signed challenge itself: "bypass" or "auto" (an absent mode is auto, as the core normalises it)
    var permissionMode: String { challenge.request.options.permissionMode == "bypass" ? "bypass" : "auto" }
  }

  /// the challenge is core-signed; what it asks for comes from its own fields
  static func review(challenge doc: SignedDoc, coreKey: String) throws -> Reviewed {
    let ch = try CoreCrypto.decode(doc, by: coreKey, as: Challenge.self, what: "the challenge")
    guard ch.kind == "challenge" else { throw TrustError.mismatch("not a challenge") }
    let r = ch.request, pred = r.predecessorId ?? ""
    let kind: Kind
    if let added = r.addedStore, !added.isEmpty, r.machine != nil { kind = .addStore }
    else if r.downgrade == true || r.machine != nil || (r.image ?? "").isEmpty || r.image == "null" { kind = .other }
    else if !pred.isEmpty { kind = .resumeUpgrade }
    else { kind = .newSession }
    let image = r.machine?.image ?? r.image ?? ""
    return Reviewed(kind: kind, challenge: ch, stores: r.stores ?? [], sensitive: r.sensitive ?? [], harness: r.options.harness ?? "", image: image, addedStore: r.addedStore)
  }

  /// the secure New session page: the challenge carries exactly the stores picked there (plus the harness's
  /// own, which the router adds), the harness and the permission mode picked there
  static func matchesPicked(_ r: Reviewed, stores picked: [String], harnessStores: [String], harness: String, permissionMode: String) throws {
    guard r.kind == .newSession else { throw TrustError.mismatch("not a new session") }
    guard r.stores == Array(Set(picked + harnessStores)).sorted() else { throw TrustError.mismatch("stores") }
    guard r.harness == harness else { throw TrustError.mismatch("harness") }
    guard r.permissionMode == (permissionMode == "bypass" ? "bypass" : "auto") else { throw TrustError.mismatch("permission mode") }
  }

  /// the answer that came back is the core's, for this challenge
  static func answerFor(_ r: Reviewed, answer doc: SignedDoc, coreKey: String) throws {
    let a = try CoreCrypto.decode(doc, by: coreKey, as: Answer.self, what: "the core's answer")
    guard a.nonce == r.challenge.nonce else { throw TrustError.stale("answer") }
    if r.kind == .addStore {
      guard a.kind == "succession-cert", a.machine == r.challenge.request.machine else { throw TrustError.stale("cert") }
    } else {
      guard a.kind == "approval" || a.kind == "succession-cert" else { throw TrustError.stale("answer kind \(a.kind)") }
    }
  }
}

// ---- deploy keys (core/deploykeys.go): adding or removing a repo's key, approved by the phone ------------
/// the core's signed begin document: exactly what will happen, with the token store's E and a one-off T
struct DeployKeyBegin: Codable, Equatable {
  let kind: String, pending: String, action: String, repo: String, store: String
  let sensitive: Bool, replaces: Bool, title: String, tokenStore: String, e: String, t: String
}
/// the core's answer once it is done: "deploy-key-added" (with the key's fingerprint) or "deploy-key-removed"
struct DeployKeyAnswer: Codable {
  let kind: String, pending: String, repo: String, store: String
  let sensitive: Bool?, fingerprint: String?, deleted: Int?
}

extension Checks {
  /// the only store this flow opens: its GitHub token may manage deploy keys, nothing else
  static let deployKeyTokenStore = "github-deploy-keys"

  /// the store a repo's key lives in (the core's RepoStore): github-<name> for DE0CH's repos, else
  /// github-<owner>-<name>; lower case, anything outside [a-z0-9-] as "-"
  static func repoStore(_ repo: String) -> String {
    let parts = repo.lowercased().split(separator: "/", maxSplits: 1).map(String.init)
    guard parts.count == 2 else { return "" }
    let slug = parts[0] == "de0ch" ? parts[1] : parts[0] + "-" + parts[1]
    let mapped = String(slug.unicodeScalars.map { s -> Character in
      (s >= "a" && s <= "z") || (s >= "0" && s <= "9") ? Character(s) : "-"
    })
    return "github-" + mapped.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
  }

  /// the begin document is the core's, for exactly this action on this repo: its store, its title on GitHub,
  /// the one token store it opens; asked-for sensitivity is kept (the core may only add it)
  static func deployKeyBegin(_ doc: SignedDoc, coreKey: String, action: String, repo: String, sensitive: Bool) throws -> DeployKeyBegin {
    let b = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyBegin.self, what: "the deploy-key request")
    guard b.kind == "deploy-key-begin", b.action == action else { throw TrustError.mismatch("action") }
    guard b.repo.lowercased() == repo.lowercased() else { throw TrustError.mismatch("repo") }
    guard b.store == repoStore(repo), b.title == "jarvis2 " + b.store else { throw TrustError.mismatch("store") }
    guard b.tokenStore == deployKeyTokenStore else { throw TrustError.mismatch("the store it opens") }
    if action == "add", sensitive, !b.sensitive { throw TrustError.mismatch("sensitive") }
    return b
  }

  /// the core's answer is for this request and says it was done
  static func deployKeyAnswer(_ doc: SignedDoc, coreKey: String, begin b: DeployKeyBegin) throws -> DeployKeyAnswer {
    let a = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyAnswer.self, what: "the core's answer")
    guard a.pending == b.pending, a.repo == b.repo, a.store == b.store else { throw TrustError.stale("deploy key") }
    guard a.kind == (b.action == "add" ? "deploy-key-added" : "deploy-key-removed") else { throw TrustError.stale("answer kind \(a.kind)") }
    if b.action == "add", a.sensitive != b.sensitive { throw TrustError.mismatch("sensitive") }
    return a
  }
}

// ---- grants (docs/DESIGN.md "Grants"): what the phone signs to let a router feature into a session --------
/// a line's succession cert (core/core.go Cert): the line grants name, the phone key the machine checks them
/// against, and the stores the session holds
struct SessionCert: Codable {
  let kind: String
  let stores: [String]?
  let options: Options?
  let phone: String?
  let sensitive: Bool?
  let line: String
  let issuedAt: String?
}
/// the grant text (router/grants.go grantText) — exactly the router's draft, field for field
struct GrantText: Codable, Equatable {
  let kind: String, holder: String, session: String, scope: String, issued: String
  let expires: String?, until: String?
}

extension Checks {
  static let grantFields: Set<String> = ["kind", "holder", "session", "scope", "issued", "expires", "until"]
  static func isoDate(_ s: String?) -> Date? {
    guard let s else { return nil }
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
    return f.date(from: s)
  }

  /// the session's cert, core-signed; it must name a line
  static func cert(_ doc: SignedDoc, coreKey: String) throws -> SessionCert {
    let c = try CoreCrypto.decode(doc, by: coreKey, as: SessionCert.self, what: "the session's cert")
    guard c.kind == "succession-cert", !c.line.isEmpty else { throw TrustError.mismatch("not a session cert") }
    return c
  }

  /// The router's draft must say exactly what was chosen on the grant page: this kind, this holder's key, the
  /// cert's line, scope "shell", issued now, and `minutes` (1–10) for a grant or `until` for a standing rule.
  /// The cert must name this phone (the machine checks the signature against it). Nothing else may be in it.
  static func reviewGrant(text: String, cert: SessionCert, phoneKey: String, holderKey: String, kind: String,
                          minutes: Int, until: Date?, now: Date = Date()) throws -> GrantText {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
          Set(obj.keys).isSubset(of: grantFields),
          let g = try? JSONDecoder().decode(GrantText.self, from: Data(text.utf8)) else { throw TrustError.mismatch("the grant text") }
    guard cert.phone == phoneKey else { throw TrustError.mismatch("this session's cert names another phone") }
    guard g.kind == kind else { throw TrustError.mismatch("kind") }
    guard g.holder == holderKey else { throw TrustError.mismatch("feature") }
    guard g.session == cert.line else { throw TrustError.mismatch("session") }
    guard g.scope == "shell" else { throw TrustError.mismatch("scope") }
    guard let issued = isoDate(g.issued), abs(issued.timeIntervalSince(now)) < 300 else { throw TrustError.mismatch("issued time") }
    switch kind {
    case "grant":
      guard (1...10).contains(minutes), g.until == nil, let end = isoDate(g.expires),
            abs(end.timeIntervalSince(issued) - Double(minutes * 60)) < 1 else { throw TrustError.mismatch("duration") }
    case "rule":
      guard cert.sensitive != true else { throw TrustError.mismatch("a sensitive session takes only a phone grant") }
      guard g.expires == nil, let end = isoDate(g.until), let until, abs(end.timeIntervalSince(until)) < 2, end > now else { throw TrustError.mismatch("end date") }
    default: throw TrustError.mismatch("kind")
    }
    return g
  }
}
