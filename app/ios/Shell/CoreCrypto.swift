// The shell's side of the core's formats (core/crypto.go, core/core.go), with no UI, network or Keychain in
// it, so the same file is compiled into the interop test (ios/interop) that runs it against the real core.
//   - a signed document is {payload, sig}: sig = base64 DER ECDSA-P256-SHA256 over the payload's bytes;
//   - public keys are base64 of the 65-byte uncompressed X9.63 point;
//   - Sealed {e, data}: ephemeral P-256 e, x(e·R) → HKDF-SHA256(salt empty, info, 32 bytes) → AES-256-GCM
//     combined (nonce‖ct‖tag). Infos: "jarvis2/unlock-share" (the phone's share x(p·E) to the core's one-off
//     key T), "jarvis2/recover" (the recovery bundle to the core), "jarvis2/backup" (a store backup to the
//     master key, the store's name as associated data).
// The core's identity: "jarvis2-core-identity <signingKey> <agreementKey>", signed by the box key, shown as
// 8 words (BIP39 English, the first 88 bits of its SHA-256, 11 bits per word — core/identity.go).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct SignedDoc: Codable, Equatable { let payload: String; let sig: String }

enum TrustError: LocalizedError, Equatable {
  case notRecovered, badKit(String), badSignature(String), mismatch(String), stale(String), backup(String)
  var errorDescription: String? {
    switch self {
    case .notRecovered: return "This iPhone hasn't recovered a core yet — open Recovery."
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
  static let shareInfo = "jarvis2/unlock-share", recoverInfo = "jarvis2/recover", backupInfo = "jarvis2/backup"
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
  /// 8 words from `words` (the BIP39 English list, core/words.txt)
  static func identityWords(_ k: PublicKeys, words: [String]) -> String {
    guard words.count == 2048 else { return "(no word list)" }
    let h = Array(SHA256.hash(data: Data(identityText(k).utf8)))
    return (0..<8).map { i -> String in
      var idx = 0
      for b in 0..<11 { let bit = i * 11 + b; idx = idx << 1 | Int(h[bit / 8] >> (7 - UInt8(bit % 8)) & 1) }
      return words[idx]
    }.joined(separator: " ")
  }
  /// the box key (keys/box.pub, from GitHub) vouches for this core's keys
  static func identityVouched(_ k: PublicKeys, boxSig: String, boxKey: String) -> Bool {
    PublicKeys.valid(k) && valid(Data(identityText(k).utf8), sig: boxSig, by: boxKey)
  }
}

// ---- the recovery kit: what Deyao keeps in his password manager --------------------------------------
/// `jarvis2-master:<base64 PKCS#8 DER>` — the master private key (a PEM "PRIVATE KEY" block is accepted too)
struct MasterKey {
  let signing: P256.Signing.PrivateKey
  var agreement: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation) }
  var publicKey: String { signing.publicKey.x963Representation.base64EncodedString() }
  static let prefix = "jarvis2-master:"
  static func parse(_ raw: String) throws -> MasterKey {
    let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    var der: Data?
    if s.hasPrefix(prefix) {
      der = Data(base64Encoded: String(s.dropFirst(prefix.count)).filter { !$0.isWhitespace })
    } else if s.hasPrefix("-----BEGIN PRIVATE KEY-----") {
      der = Data(base64Encoded: s.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined().filter { !$0.isWhitespace })
    }
    guard let d = der, let k = try? P256.Signing.PrivateKey(derRepresentation: d) else {
      throw TrustError.badKit("That isn't a master key (jarvis2-master:… with a base64 PKCS#8 P-256 private key).")
    }
    return MasterKey(signing: k)
  }
  /// a fresh pair, made in software so the private half can be written down (it is never stored)
  static func generate() -> MasterKey { MasterKey(signing: P256.Signing.PrivateKey()) }
  /// the kit string: PKCS#8 DER, the body of the PEM "PRIVATE KEY" block
  var kit: String { MasterKey.prefix + signing.pemRepresentation.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined() }
  func sign(_ text: String) throws -> String { try signing.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString() }
}

/// `jarvis2-s3:<access key>:<secret key>` — read credentials for the backup bucket
struct S3Credentials {
  let accessKey: String, secretKey: String
  static func parse(_ raw: String) throws -> S3Credentials {
    let p = raw.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
    guard p.count == 3, p[0] == "jarvis2-s3", !p[1].isEmpty, !p[2].isEmpty else {
      throw TrustError.badKit("That isn't the backup bucket's credentials (jarvis2-s3:<access key>:<secret key>).")
    }
    return S3Credentials(accessKey: p[1], secretKey: p[2])
  }
}

// ---- the core's documents (core/core.go) ----
struct StartedMachine: Codable, Equatable { let id: String; let requested: String?; let image: String; let encryptionKey: String; let signingKey: String }
struct Options: Codable, Equatable { let harness: String? }
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
struct KindDoc: Codable { let kind: String; let id: String?; let store: String?; let name: String?; let stores: Int? }

/// What a secure page shows for a challenge — read from the core-signed challenge itself, never from the
/// router's label — and the checks that what comes back answers it.
enum Checks {
  enum Kind: String { case newSession = "new-session", resumeUpgrade = "resume-upgrade", addStore = "add-store", other }
  struct Reviewed { let kind: Kind; let challenge: Challenge; let stores: [String]; let sensitive: [String]; let harness: String; let image: String; let addedStore: String? }

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
  /// own, which the router adds) and the harness picked there
  static func matchesPicked(_ r: Reviewed, stores picked: [String], harnessStores: [String], harness: String) throws {
    guard r.kind == .newSession else { throw TrustError.mismatch("not a new session") }
    guard r.stores == Array(Set(picked + harnessStores)).sorted() else { throw TrustError.mismatch("stores") }
    guard r.harness == harness else { throw TrustError.mismatch("harness") }
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
