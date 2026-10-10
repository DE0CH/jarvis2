// Setting the core up — Reset and Recover — with no UI, network or Keychain in it (compiled into the interop test
// too, which runs it against the real core). A new core is empty: it takes a master public key once, from a
// claim statement the master key signs (naming the core and this iPhone), with a bundle of stores sealed to it.
//   Reset:   a new master key, an empty bundle; the stores are filled later by the setup session.
//   Recover: the master key from the kit; the bundle = every store from the backups.
// The backups come from the router, which holds the bucket's read key and passes the objects on as they are:
//   stores/<name>.json    {doc, sig}: doc = {"kind":"store-backup","name","sensitive","sealed":{e,data},"at"},
//                         sig = the setup key's ECDSA over the doc text; sealed to the master key
//                         (info "jarvis2/backup", the store's name as associated data) → JSON values
//   sensitive/<name>.json {doc, sig}: doc = {"kind":"store-sensitive","name","at"} — the store is sensitive
//                         whatever its backup says
// (infra/setup.py writes both.) So the router can't read, change or forge a backup; it can only withhold one or
// serve an older signed version.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// one store as the backups give it back
struct RecoveredStore { let name: String; let values: [String: String]; let sensitive: Bool }

enum CoreSetup {
  // ---- the core: its keys (vouched for by the box key) and its own signed state ----
  struct Identity: Decodable { let signingKey: String; let agreementKey: String; let boxSig: String; let state: SignedDoc }
  struct State: Decodable { let kind: String; let master: String; let phone: PublicKeys? }
  /// the core as this iPhone sees it
  enum Status: Equatable {
    case empty                // waiting for Reset or Recover
    case mine                 // set up with this iPhone's master key and this iPhone
    case otherPhone           // set up with this master key, but for another iPhone (or this one before a reinstall)
    case foreign              // set up with a master key that isn't this iPhone's
  }

  /// the box key (keys/box.pub) signed the core's keys, and the core signed its state: or nothing goes on
  static func check(_ id: Identity, boxKey: String) throws -> (keys: PublicKeys, state: State) {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard CoreCrypto.identityVouched(k, boxSig: id.boxSig, boxKey: boxKey) else { throw TrustError.badSignature("the core's keys (not the box key's)") }
    let st = try CoreCrypto.decode(id.state, by: k.signingKey, as: State.self, what: "the core's state")
    guard st.kind == "core-state" else { throw TrustError.mismatch("not the core's state") }
    return (k, st)
  }
  static func status(_ st: State, myMaster: String?, myPhone: PublicKeys) -> Status {
    if st.master.isEmpty { return .empty }
    guard let m = myMaster, MasterKey.same(m, st.master) else { return .foreign }
    return st.phone == myPhone ? .mine : .otherPhone
  }

  // ---- the backups, as the router serves them ----
  struct BackupObject: Decodable { let key: String; let body: String }
  struct Signed: Decodable { let doc: String; let sig: String }
  struct BackupDoc: Decodable { let kind: String; let name: String; let sensitive: Bool; let sealed: [String: String] }
  struct MarkerDoc: Decodable { let kind: String; let name: String }

  static func name(of key: String, prefix: String) -> String? {
    guard key.hasPrefix(prefix), key.hasSuffix(".json") else { return nil }
    return String(key.dropFirst(prefix.count).dropLast(5))
  }
  private static func signed(_ body: String, key: String, setupKey: String) throws -> Data {
    guard let o = try? JSONDecoder().decode(Signed.self, from: Data(body.utf8)) else { throw TrustError.backup("\(key) isn't a signed document.") }
    let doc = Data(o.doc.utf8)
    guard CoreCrypto.valid(doc, sig: o.sig, by: setupKey) else { throw TrustError.backup("\(key) isn't signed by the setup key.") }
    return doc
  }

  /// every store in the backups, checked (setup key) and decrypted (master key)
  static func readBackups(_ objects: [BackupObject], master: MasterKey, setupKey: String) throws -> [RecoveredStore] {
    var marked = Set<String>()
    for o in objects {
      guard let n = name(of: o.key, prefix: "sensitive/") else { continue }
      let m = try JSONDecoder().decode(MarkerDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard m.kind == "store-sensitive", m.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      marked.insert(n)
    }
    var out: [String: RecoveredStore] = [:]
    for o in objects {
      guard let n = name(of: o.key, prefix: "stores/") else { continue }
      guard out[n] == nil else { throw TrustError.backup("\(o.key) comes twice.") }
      let d = try JSONDecoder().decode(BackupDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard d.kind == "store-backup", d.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      let plain: Data
      do { plain = try CoreCrypto.open(d.sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: Data(n.utf8)) }
      catch { throw TrustError.backup("\(o.key) doesn't open with this recovery kit.") }
      guard let values = try? JSONDecoder().decode([String: String].self, from: plain) else { throw TrustError.backup("\(o.key) holds something that isn't a store.") }
      out[n] = RecoveredStore(name: n, values: values, sensitive: d.sensitive || marked.contains(n))
    }
    return out.values.sorted { $0.name < $1.name }
  }

  /// the bundle's exact bytes (Reset: no stores)
  static func bundle(_ stores: [RecoveredStore]) throws -> Data {
    struct S: Encodable { let name: String; let values: [String: String] }
    struct B: Encodable { let stores: [S]; let notSensitive: [String] }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try e.encode(B(stores: stores.map { S(name: $0.name, values: $0.values) }, notSensitive: stores.filter { !$0.sensitive }.map(\.name)))
  }

  /// the claim statement: this master key sets up this core for this iPhone, with this bundle
  static func statement(master: String, core: PublicKeys, phone: PublicKeys, bundle: Data) throws -> String {
    struct St: Encodable { let kind = "claim"; let master: String; let core: PublicKeys; let phone: PublicKeys; let bundleSha256: String }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try e.encode(St(master: master, core: core, phone: phone, bundleSha256: CoreCrypto.sha256hex(bundle))), as: UTF8.self)
  }

  /// the body of POST /api/core/claim
  static func claim(core: PublicKeys, phone: PublicKeys, master: MasterKey, bundle: Data) throws -> [String: Any] {
    let st = try statement(master: master.publicKey, core: core, phone: phone, bundle: bundle)
    return ["statement": st, "masterSig": try master.sign(st), "bundle": try CoreCrypto.seal(bundle, to: core.agreementKey, info: CoreCrypto.claimInfo)]
  }

  /// the body of POST /api/core/wipe: the core's own master key ends it (a new, empty core takes its place)
  static func wipe(core: PublicKeys, master: MasterKey) throws -> [String: Any] {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    struct W: Encodable { let kind = "wipe"; let core: String }
    let st = String(decoding: try e.encode(W(core: core.signingKey)), as: UTF8.self)
    return ["statement": st, "masterSig": try master.sign(st)]
  }
}
