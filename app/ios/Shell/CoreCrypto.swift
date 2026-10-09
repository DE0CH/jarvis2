// The shell's side of the core's formats (core/crypto.go, docs/API.md), with no UI, network or Keychain in
// it, so the same file is compiled into the interop test (ios/interop) that runs it against the real core.
//   - a signed document is {payload, sig}: sig = base64 DER ECDSA-P256-SHA256 over the payload's bytes;
//   - public keys are base64 of the 65-byte uncompressed X9.63 point;
//   - an unlock share is the phone's x(p·E), sealed to the core's one-off key T: ephemeral r, x(r·T) →
//     HKDF-SHA256(salt empty, info "jarvis2/unlock-share", 32 bytes) → AES-256-GCM combined (nonce‖ct‖tag).
// Every check that decides whether the phone signs lives here (Checks), so it is tested in one place.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct SignedDoc: Codable, Equatable { let payload: String; let sig: String }

enum TrustError: LocalizedError, Equatable {
  case notPaired, badPairing(String), badSignature(String), mismatch(String), stale(String)
  var errorDescription: String? {
    switch self {
    case .notPaired: return "This iPhone isn't paired with a core yet — open Pairing and paste the core's key."
    case .badPairing(let s): return s
    case .badSignature(let s): return "The core's signature on \(s) didn't check out — refusing to continue."
    case .mismatch(let s): return "The core's answer doesn't match what you chose (\(s)) — refusing to sign."
    case .stale(let s): return "The core's answer isn't for this request (\(s)) — refusing to continue."
    }
  }
}

/// the two pairing strings: `jarvis2-phone:<signingKey>:<agreementKey>` and `jarvis2-core:<signingKey>:<agreementKey>`
struct KeyPairString: Equatable {
  let role: String, signingKey: String, agreementKey: String
  var text: String { "jarvis2-\(role):\(signingKey):\(agreementKey)" }
  static func parse(_ raw: String, role: String) throws -> KeyPairString {
    let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 3, parts[0] == "jarvis2-\(role)" else { throw TrustError.badPairing("That isn't a jarvis2-\(role):… string.") }
    guard let sk = Data(base64Encoded: parts[1]), (try? P256.Signing.PublicKey(x963Representation: sk)) != nil else { throw TrustError.badPairing("The signing key in it isn't a P-256 public key.") }
    guard let ak = Data(base64Encoded: parts[2]), (try? P256.KeyAgreement.PublicKey(x963Representation: ak)) != nil else { throw TrustError.badPairing("The agreement key in it isn't a P-256 public key.") }
    return KeyPairString(role: role, signingKey: parts[1], agreementKey: parts[2])
  }
}

enum CoreCrypto {
  /// the payload's bytes, only if `key` (base64 X9.63) signed them
  static func verified(_ doc: SignedDoc, by key: String, what: String) throws -> Data {
    guard let k = Data(base64Encoded: key).flatMap({ try? P256.Signing.PublicKey(x963Representation: $0) }),
          let sig = Data(base64Encoded: doc.sig), let s = try? P256.Signing.ECDSASignature(derRepresentation: sig),
          k.isValidSignature(s, for: Data(doc.payload.utf8)) else { throw TrustError.badSignature(what) }
    return Data(doc.payload.utf8)
  }
  static func decode<T: Decodable>(_ doc: SignedDoc, by key: String, as: T.Type, what: String) throws -> T {
    try JSONDecoder().decode(T.self, from: verified(doc, by: key, what: what))
  }

  static let shareInfo = "jarvis2/unlock-share"
  /// seal the phone's 32-byte share x(p·E) to the core's one-off key T → {e, data}
  static func sealShare(_ x: Data, to t: String) throws -> [String: String] {
    guard let tb = Data(base64Encoded: t) else { throw TrustError.badSignature("the unlock key") }
    let tk = try P256.KeyAgreement.PublicKey(x963Representation: tb)
    let r = P256.KeyAgreement.PrivateKey()
    let secret = try r.sharedSecretFromKeyAgreement(with: tk)
    let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(shareInfo.utf8), outputByteCount: 32)
    let box = try AES.GCM.seal(x, using: key)
    guard let combined = box.combined else { throw TrustError.badSignature("sealing") }
    return ["e": r.publicKey.x963Representation.base64EncodedString(), "data": combined.base64EncodedString()]
  }

  static func nonce() -> String {
    var g = SystemRandomNumberGenerator()
    return (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &g)) }.joined()
  }
}

// ---- the core's documents (core/core.go) ----
struct StartedMachine: Codable, Equatable { let id: String; let image: String; let encryptionKey: String; let signingKey: String }
struct Options: Codable, Equatable { let harness: String }
struct SuccessionRequest: Codable {
  let kind: String
  let predecessor: SignedDoc?
  let predecessorId: String?
  let machine: StartedMachine?
  let stores: [String]?
  let sensitive: [String]?
  let options: Options
  let addedStore: String?
}
struct Challenge: Codable { let kind: String; let nonce: String; let request: SuccessionRequest }
struct Cert: Codable {
  let kind: String; let predecessorId: String?; let machine: StartedMachine?; let stores: [String]?; let options: Options; let nonce: String; let issuedAt: String
}
struct StoreView: Codable, Identifiable, Equatable {
  let name: String; let keys: [String]; let sensitive: Bool; let unlocked: Bool; var id: String { name }
  /// the store named `core` holds the core's own Fly token: unlocked and locked on the Stores page, never
  /// offered to a session (the core refuses it in succession)
  static let coreStore = "core"
  var isCore: Bool { name == StoreView.coreStore }
  var title: String { isCore ? "core — the core's own Fly token" : name }
}
struct StoresDoc: Codable { let kind: String; let nonce: String; let stores: [StoreView] }
struct UnlockRow: Codable, Identifiable, Equatable { let id: String; let store: String; let since: String }
struct UnlockedDoc: Codable { let kind: String; let nonce: String; let unlocked: [UnlockRow] }
struct UnlockBegin: Codable { let kind: String; let pending: String; let store: String; let e: String; let t: String }
struct KindDoc: Codable { let kind: String; let id: String?; let store: String?; let name: String? }

/// What a secure page shows for a challenge, and the exact checks before the phone signs it.
enum Checks {
  enum Kind: String { case newSession = "new-session", resumeUpgrade = "resume-upgrade", addStore = "add-store" }
  struct Reviewed { let kind: Kind; let challenge: Challenge; let stores: [String]; let sensitive: [String]; let harness: String; let image: String; let addedStore: String? }

  /// the challenge is core-signed and well formed; what kind it really is comes from its own fields
  static func review(challenge doc: SignedDoc, routerKind: String, burnCert: SignedDoc?, coreKey: String) throws -> Reviewed {
    let ch = try CoreCrypto.decode(doc, by: coreKey, as: Challenge.self, what: "the challenge")
    guard ch.kind == "challenge", ch.request.kind == "succession" else { throw TrustError.mismatch("not a succession challenge") }
    guard let m = ch.request.machine else { throw TrustError.mismatch("no machine in the request") }
    let stores = ch.request.stores ?? [], pred = ch.request.predecessorId ?? ""
    let kind: Kind
    if let added = ch.request.addedStore, !added.isEmpty {
      guard pred == m.id else { throw TrustError.mismatch("adding a store names another machine") }
      guard stores.contains(added) else { throw TrustError.mismatch("the added store isn't in the set") }
      kind = .addStore
    } else if !pred.isEmpty {
      // a resume with a change: the old machine must already be burned, by a core-signed burn cert naming it
      guard let b = burnCert else { throw TrustError.mismatch("no burn cert for the old machine") }
      let burn = try CoreCrypto.decode(b, by: coreKey, as: Cert.self, what: "the burn cert")
      guard burn.kind == "burn-cert", burn.machine == nil else { throw TrustError.mismatch("the burn cert isn't a burn cert") }
      guard burn.predecessorId == pred else { throw TrustError.mismatch("the burn cert names another machine") }
      // (a burn cert carries no stores: the core fills the set only for a real successor)
      guard burn.options == ch.request.options else { throw TrustError.mismatch("the harness differs from the burned machine's") }
      kind = .resumeUpgrade
    } else {
      guard ch.request.predecessor == nil else { throw TrustError.mismatch("a new session with a predecessor") }
      kind = .newSession
    }
    guard kind.rawValue == routerKind else { throw TrustError.mismatch("the router calls it \(routerKind), the challenge is \(kind.rawValue)") }
    return Reviewed(kind: kind, challenge: ch, stores: stores, sensitive: ch.request.sensitive ?? [], harness: ch.request.options.harness, image: m.image, addedStore: ch.request.addedStore)
  }

  /// the secure New session page: the challenge carries exactly the stores and harness picked there
  static func matchesPicked(_ r: Reviewed, stores picked: [String], harness: String) throws {
    guard r.kind == .newSession else { throw TrustError.mismatch("not a new session") }
    guard r.stores == picked.sorted() else { throw TrustError.mismatch("stores") }
    guard r.harness == harness else { throw TrustError.mismatch("harness") }
  }

  /// the cert that came back answers this challenge
  static func certFor(_ r: Reviewed, cert doc: SignedDoc, coreKey: String) throws {
    let c = try CoreCrypto.decode(doc, by: coreKey, as: Cert.self, what: "the cert")
    guard c.kind == "succession-cert", c.nonce == r.challenge.nonce, c.machine == r.challenge.request.machine else { throw TrustError.stale("cert") }
  }
}
