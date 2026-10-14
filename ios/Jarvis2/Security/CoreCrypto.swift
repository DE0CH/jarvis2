// The app's side of secrets' formats (core/kernel/secrets, core/kernel/README.md), with no UI, network or Keychain in
// it, so the same file is compiled into the interop test (ios/interop) that runs it against the real secrets binary.
//   - a signed document is {payload, sig}: sig = base64 DER ECDSA-P256-SHA256 over the payload's bytes;
//   - public keys are base64 of the 65-byte uncompressed X9.63 point;
//   - Sealed {e, data}: ephemeral P-256 e, x(e·R) → HKDF-SHA256(salt empty, info, 32 bytes) → AES-256-GCM
//     combined (nonce‖ct‖tag). Infos: "jarvis2/unlock-share" (the phone's share x(p·E) to secrets' one-off key T),
//     "jarvis2/claim" (the claim's bundle to secrets), "jarvis2/backup" (a key's backup to the master key, with
//     "<store>\n<key>" as associated data; an older whole-store backup's with the store's name).
//   - a store is a set of keys: each value under its own data key ("<store>\n<key>" as associated data), the data key
//     wrapped to the store key P + K ("jarvis2/store-data-key").
// Every kernel part's identity: "jarvis2-<role>-identity <signingKey> <agreementKey>", signed by the box key
// (keys/box.pub), which the app checks itself before it trusts a part (Kernel.vouched).
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
    case .mismatch(let s): return "What came back doesn't match what you chose (\(s)) — refusing to sign."
    case .stale(let s): return "The answer isn't for this request (\(s)) — refusing to continue."
    case .backup(let s): return s
    }
  }
}

/// a P-256 key pair's public halves (secrets', the phone's)
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
  /// seal the phone's 32-byte share x(p·E) to secrets' one-off key T → {e, data}
  static func sealShare(_ x: Data, to t: String) throws -> [String: String] { try seal(x, to: t, info: shareInfo) }

  static func nonce() -> String {
    var g = SystemRandomNumberGenerator()
    return hex((0..<16).map { _ in UInt8.random(in: 0...255, using: &g) })
  }

  // ---- secrets' identity ----
  static func identityText(_ k: PublicKeys) -> String { Kernel.identityText(role: "secrets", signingKey: k.signingKey, agreementKey: k.agreementKey) }
  /// the box key (keys/box.pub, from GitHub) vouches for these keys as secrets'
  static func identityVouched(_ k: PublicKeys, boxSig: String, boxKey: String) -> Bool {
    PublicKeys.valid(k) && valid(Data(identityText(k).utf8), sig: boxSig, by: boxKey)
  }
}

// ---- the recovery kit: what Deyao keeps in his password manager --------------------------------------
/// The master private key. It exists only inside the recovery kit: Reset makes it and shows the kit, Recover
/// reads it from the pasted kit; either way the app keeps it in memory just long enough to set secrets up.
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
/// is refused: the router reads the backups now, and nothing trusts a version-1 key.
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

// ---- secrets' documents (core/kernel/secrets) ----
struct StoreView: Codable, Identifiable, Equatable {
  let name: String; let sensitive: Bool; let empty: Bool; let unlocked: Bool; var id: String { name }
  /// the store named `core` holds the spawner's Fly token: it never shows for sessions
  static let coreStore = "core"
  var isCore: Bool { name == StoreView.coreStore }
}
struct StoresDoc: Codable { let kind: String; let nonce: String; let stores: [StoreView] }
/// who wrote a store's key (secrets/keys.go EntryWriter): "setup" (its key's signature over Checks.writerText, checked
/// here), "machine" (a session's machine, as the router says: writing secrets is protected only by the router),
/// "router" (the router itself: the Claude login) or "core" (secrets' own: a Recover's key, a deploy key)
struct StoreWriter: Codable, Equatable {
  let by: String; var sig: String? = nil; var machine: String? = nil
}
/// an open unlock (secrets' signed list): per store, open until locked
struct UnlockRow: Codable, Identifiable, Equatable { let id: String; let store: String; let since: String }
struct UnlockedDoc: Codable { let kind: String; let nonce: String; let unlocked: [UnlockRow] }
/// one key of an unlock (secrets UnlockBegin): its name, E, who wrote it, its data and backup hashes, when
struct KeyBegin: Codable, Equatable {
  let key: String; let e: String; let writer: StoreWriter; let dataSha256: String; var backupSha256: String = ""; var at: String? = nil
}
/// unlock_begin: every key of the store, each opened with its own share
struct UnlockBegin: Codable {
  let kind: String; let pending: String; let store: String; let t: String
  let keys: [KeyBegin]
  var version: String? = nil
  /// the E of every share this unlock needs, in order (one per key)
  var es: [String] { keys.map(\.e) }
}
struct KindDoc: Codable { let kind: String; let id: String?; let store: String?; let name: String?; let stores: Int?; let core: String? }

/// What a secure page checks of secrets' documents and the approvals' drafts (ApprovalChecks.swift)
enum Checks {
  /// a JSON value as one line, keys sorted (what the page shows of a signed value it has no field for)
  static func compact(_ v: Any?) -> String {
    guard let v, JSONSerialization.isValidJSONObject(v),
          let d = try? JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .withoutEscapingSlashes]) else { return v.map { "\($0)" } ?? "none" }
    return String(decoding: d, as: UTF8.self)
  }
  static func isoDate(_ s: String?) -> Date? {
    guard let s else { return nil }
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
    return f.date(from: s)
  }
}

// ---- deploy keys (secrets/deploykeys.go): adding or removing a repo's key, approved by the phone ------------
/// secrets' signed begin document: exactly what will happen, with the token store's E and a one-off T
struct DeployKeyBegin: Codable, Equatable {
  let kind: String, pending: String, action: String, repo: String, store: String
  let sensitive: Bool, replaces: Bool, title: String, tokenStore: String, e: String, t: String
  /// an add: the public key, and each key of the store the app sent (name, E, sha256 of its data)
  var publicKey: String? = nil
  var keys: [DeployKeyItem]? = nil
  /// who wrote the token key (as unlock-begin's writer), its name, data and backup hashes
  var tokenWriter: StoreWriter? = nil
  var tokenDataSha256: String? = nil
  var tokenKey: String? = nil
  var tokenBackupSha256: String? = nil
}
struct DeployKeyItem: Codable, Equatable { let key: String; let e: String; let dataSha256: String }
/// what the app sent with a deploy-key add: the public key and the store as keys
struct DeployKeySent { let publicKey: String; let keys: [KeyEntry] }
/// secrets' answer once it is done: "deploy-key-added" or "deploy-key-removed"
struct DeployKeyAnswer: Codable {
  let kind: String, pending: String, repo: String, store: String
  let sensitive: Bool?, fingerprint: String?, deleted: Int?
  var publicKey: String? = nil
}

extension Checks {
  /// the only store this flow opens: its GitHub token may manage deploy keys, nothing else
  static let deployKeyTokenStore = "github-deploy-keys"

  /// the store a repo's key lives in (secrets' RepoStore): github-<name> for DE0CH's repos, else
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

  /// the begin document is secrets', for exactly this action on this repo: its store, its title on GitHub,
  /// the one token store it opens; asked-for sensitivity is kept (secrets may only add it)
  /// `sent`: the key the app sent (secrets must echo exactly it)
  static func deployKeyBegin(_ doc: SignedDoc, coreKey: String, action: String, repo: String, sensitive: Bool,
                             sent: DeployKeySent? = nil) throws -> DeployKeyBegin {
    let b = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyBegin.self, what: "the deploy-key request")
    if let sent {
      let made = TrustError.mismatch("the key secrets holds isn't the one this iPhone made")
      guard b.publicKey == sent.publicKey else { throw made }
      let want = sent.keys.sorted { $0.key < $1.key }.map { DeployKeyItem(key: $0.key, e: $0.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data($0.data.utf8))) }
      guard b.keys == want else { throw made }
    }
    if action == "remove", b.keys?.isEmpty == false { throw TrustError.mismatch("a remove that brings a key") }
    guard b.kind == "deploy-key-begin", b.action == action else { throw TrustError.mismatch("action") }
    guard b.repo.lowercased() == repo.lowercased() else { throw TrustError.mismatch("repo") }
    guard b.store == repoStore(repo), b.title == "jarvis2 " + b.store else { throw TrustError.mismatch("store") }
    guard b.tokenStore == deployKeyTokenStore else { throw TrustError.mismatch("the store it opens") }
    if action == "add", sensitive, !b.sensitive { throw TrustError.mismatch("sensitive") }
    // Jarvis 2's own repo can push code that changes Jarvis 2: its store is always sensitive (checked here, not only
    // by secrets)
    if action == "add", repo.lowercased() == "de0ch/jarvis2", !b.sensitive { throw TrustError.mismatch("DE0CH/jarvis2's store must be sensitive") }
    return b
  }

  /// secrets' answer is for this request and says it was done
  static func deployKeyAnswer(_ doc: SignedDoc, coreKey: String, begin b: DeployKeyBegin) throws -> DeployKeyAnswer {
    let a = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyAnswer.self, what: "secrets' answer")
    guard a.pending == b.pending, a.repo == b.repo, a.store == b.store else { throw TrustError.stale("deploy key") }
    guard a.kind == (b.action == "add" ? "deploy-key-added" : "deploy-key-removed") else { throw TrustError.stale("answer kind \(a.kind)") }
    if b.action == "add", a.sensitive != b.sensitive { throw TrustError.mismatch("sensitive") }
    return a
  }
}

// ---- who wrote a store, and which image CI built ---------------------------------------------------------------------
extension Checks {
  /// what a key's writer signs (secrets/keys.go WriterText): the store, the key, its E, the sha256 of its data and of its
  /// backup ("" for each of a delete)
  static func writerText(store: String, key: String, e: String, dataSha256: String, backupSha256: String) -> String {
    "jarvis2-store-key\n\(store)\n\(key)\n\(e)\n\(dataSha256)\n\(backupSha256)"
  }

  /// A key the phone's share opens: written by the setup session (its key's signature over writerText, checked here
  /// against keys/setup.pub), by a session's machine or the router itself (the router's word: writing secrets is protected
  /// only by the router; a session's write must be shown on the page: StoreUnlock refuses one it didn't show), or by
  /// secrets itself (a Recover's key, a deploy key). Anything else is refused.
  static func keyWriter(_ w: StoreWriter, store: String, key: String, e: String, dataSha256: String, backupSha256: String, setupKey: String?) throws {
    switch w.by {
    case "core", "router": return
    case "machine":
      guard let m = w.machine, !m.isEmpty else { throw TrustError.mismatch("key \(key) of \(store) was written by a machine no one names") }
    case "setup":
      guard let sig = w.sig, let k = setupKey else { throw TrustError.mismatch("key \(key) of \(store)'s writer can't be checked") }
      let text = writerText(store: store, key: key, e: e, dataSha256: dataSha256, backupSha256: backupSha256)
      guard CoreCrypto.valid(Data(text.utf8), sig: sig, by: k) else { throw TrustError.badSignature("key \(key) of \(store)'s writer (not the setup key)") }
    default: throw TrustError.mismatch("key \(key) of \(store) was written by \(w.by)")
    }
  }

  /// every key of an unlock: its writer checked (an unlock of an empty store is refused: there is nothing to open)
  static func unlockKeys(_ b: UnlockBegin, setupKey: String?) throws {
    let keys = b.keys
    guard !keys.isEmpty else { throw TrustError.mismatch("store \(b.store) has no keys to unlock") }
    guard Set(keys.map(\.key)).count == keys.count else { throw TrustError.mismatch("a key of \(b.store) named twice") }
    for k in keys {
      try keyWriter(k.writer, store: b.store, key: k.key, e: k.e, dataSha256: k.dataSha256, backupSha256: k.backupSha256, setupKey: setupKey)
    }
  }

  /// the keys a session's machine wrote, as secrets names them in these unlocks
  static func sessionWrites(_ begins: [UnlockBegin]) -> [SessionWrite] {
    begins.flatMap { b in b.keys.filter { $0.writer.by == "machine" }.map { SessionWrite(store: b.store, key: $0.key, machine: $0.writer.machine ?? "") } }
  }
  /// the session-written keys these unlocks would open that the page didn't show (a value a session wrote is never
  /// released unseen: Deyao, 2026-10-13)
  static func unseen(_ begins: [UnlockBegin], shown: [SessionWrite]) -> [SessionWrite] {
    let s = Set(shown)
    return sessionWrites(begins).filter { !s.contains($0) }
  }

  /// CI's signature over the session image (keys/ci.pub): "jarvis2-session-image <ref>"
  static func imageAttested(_ image: String, sig: String?, ciKey: String) -> Bool {
    guard let sig, !image.isEmpty else { return false }
    return CoreCrypto.valid(Data("jarvis2-session-image \(image)".utf8), sig: sig, by: ciKey)
  }
}

// ---- the app wraps stores itself: to secrets' signed store key, and a repo's deploy key ------------------------------
/// a data key wrapped to the store key C = P + K (the phone's and secrets' agreement keys), which only the phone's share
/// and secrets together open
struct WrappedKey: Codable, Equatable { let e: String; let wrapped: String }
/// one key of a store as the app writes it (secrets/keys.go KeyEntry): the value under its own data key (the store's and
/// the key's names as associated data), the data key wrapped to the store key
struct KeyEntry: Codable, Equatable {
  let store: String
  let key: String
  let wrapped: WrappedKey
  let data: String
  var json: [String: Any] { ["store": store, "key": key, "wrapped": ["e": wrapped.e, "wrapped": wrapped.wrapped], "data": data] }
}
/// a key a session's machine wrote: the store, the key and the machine (the page names the session that runs on it)
struct SessionWrite: Hashable {
  let store: String; let key: String; let machine: String
  /// the session's title as the router knows it (shown only; not compared)
  var label: String = ""
  static func == (a: SessionWrite, b: SessionWrite) -> Bool { a.store == b.store && a.key == b.key && a.machine == b.machine }
  func hash(into h: inout Hasher) { h.combine(store); h.combine(key); h.combine(machine) }
}
/// secrets' signed answer to POST /store-key: C = P + K for this phone
struct StoreKeyDoc: Codable { let kind: String; let phone: String; let storeKey: String }

extension CoreCrypto {
  static let storeDataKeyInfo = "jarvis2/store-data-key"

  /// the store key for this phone's agreement key, from secrets' signed answer (`coreKey`: secrets' signing key)
  static func storeKey(_ doc: SignedDoc, coreKey: String, phone: String) throws -> String {
    let d = try decode(doc, by: coreKey, as: StoreKeyDoc.self, what: "the store key")
    guard d.kind == "store-key", MasterKey.same(d.phone, phone) else { throw TrustError.stale("store key") }
    guard let b = Data(base64Encoded: d.storeKey), (try? P256.KeyAgreement.PublicKey(x963Representation: b)) != nil else { throw TrustError.badSignature("the store key") }
    return d.storeKey
  }

  /// a key's associated data: its store and its name (a value doesn't decrypt under another)
  static func keyAAD(store: String, key: String) -> Data { Data("\(store)\n\(key)".utf8) }

  /// one key's value under a fresh data key, the data key wrapped to the store key (secrets/keys.go)
  static func wrapKey(store: String, key: String, value: Data, storeKey: String) throws -> KeyEntry {
    guard let cb = Data(base64Encoded: storeKey) else { throw TrustError.badSignature("the store key") }
    let c = try P256.KeyAgreement.PublicKey(x963Representation: cb)
    let dk = SymmetricKey(size: .bits256)
    let e = P256.KeyAgreement.PrivateKey()
    let kek = try e.sharedSecretFromKeyAgreement(with: c)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(storeDataKeyInfo.utf8), outputByteCount: 32)
    guard let wrapped = try AES.GCM.seal(dk.withUnsafeBytes { Data($0) }, using: kek).combined,
          let data = try AES.GCM.seal(value, using: dk, authenticating: keyAAD(store: store, key: key)).combined else { throw TrustError.badSignature("sealing") }
    return KeyEntry(store: store, key: key, wrapped: .init(e: e.publicKey.x963Representation.base64EncodedString(), wrapped: wrapped.base64EncodedString()),
                    data: data.base64EncodedString())
  }
  /// every value of a store as its keys, sorted by name
  static func wrapKeys(store: String, values: [String: String], storeKey: String) throws -> [KeyEntry] {
    try values.keys.sorted().map { try wrapKey(store: store, key: $0, value: Data(values[$0]!.utf8), storeKey: storeKey) }
  }

}

/// A repo's deploy key, made by the app: an ed25519 pair in OpenSSH's formats.
enum OpenSSH {
  private static func string(_ d: Data) -> Data { var n = UInt32(d.count).bigEndian; return Data(bytes: &n, count: 4) + d }
  private static func uint32(_ v: UInt32) -> Data { var n = v.bigEndian; return Data(bytes: &n, count: 4) }

  struct KeyPair { let publicKey: String; let privateKeyFile: String; let wire: Data }

  /// `seed` and `checkint` fixed only by tests; a real key takes fresh randomness
  static func ed25519(comment: String, seed: Data? = nil, checkint: UInt32? = nil) throws -> KeyPair {
    let k = try seed.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) } ?? Curve25519.Signing.PrivateKey()
    let pub = k.publicKey.rawRepresentation
    let wire = string(Data("ssh-ed25519".utf8)) + string(pub)
    let ci = checkint ?? UInt32.random(in: .min ... .max)
    var priv = uint32(ci) + uint32(ci) + string(Data("ssh-ed25519".utf8)) + string(pub) + string(k.rawRepresentation + pub) + string(Data(comment.utf8))
    var pad: UInt8 = 1
    while priv.count % 8 != 0 { priv.append(pad); pad += 1 }
    let body = Data("openssh-key-v1".utf8) + Data([0]) + string(Data("none".utf8)) + string(Data("none".utf8)) + string(Data())
      + uint32(1) + string(wire) + string(priv)
    let b64 = body.base64EncodedString()
    var lines: [String] = []
    var i = b64.startIndex
    while i < b64.endIndex { let j = b64.index(i, offsetBy: 70, limitedBy: b64.endIndex) ?? b64.endIndex; lines.append(String(b64[i..<j])); i = j }
    let file = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines.joined(separator: "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
    return KeyPair(publicKey: "ssh-ed25519 " + wire.base64EncodedString(), privateKeyFile: file, wire: wire)
  }
  /// GitHub's fingerprint: SHA256:<base64 of the wire bytes' sha256, no padding>
  static func fingerprint(wire: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: wire)).base64EncodedString().replacingOccurrences(of: "=", with: "")
  }
  /// DE0CH/china-train → DE0CH_CHINA_TRAIN
  static func slug(_ repo: String) -> String {
    String(repo.uppercased().unicodeScalars.map { s -> Character in (s >= "A" && s <= "Z") || (s >= "0" && s <= "9") ? Character(s) : "_" })
  }
  /// the repo store's values, as machines read them (machine/deploykeys.go)
  static func storeValues(repo: String, privateKeyFile: String) -> [String: String] {
    let s = slug(repo)
    return ["GITHUB_DEPLOY_REPO_\(s)": repo, "GITHUB_DEPLOY_KEY_\(s)": Data(privateKeyFile.utf8).base64EncodedString()]
  }
}
