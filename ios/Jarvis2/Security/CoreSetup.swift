// Setting secrets up — Reset and Recover — with no UI, network or Keychain in it (compiled into the interop test too,
// which runs it against the real secrets binary). A new secrets is empty: it takes a master public key once, from a
// claim statement the master key signs (naming secrets and this iPhone's keys), with a bundle of stores sealed to it.
//   Reset:   a new master key, an empty bundle; the stores are filled later by the setup session.
//   Recover: the master key from the kit; the bundle = every store from the backups, each key wrapped by the app.
// The claim statement also names this iPhone's root key (`root`, PhoneKeys.rootPublic) and its device key (`device`):
// secrets ignores both; the master key's signature vouches for them to the setup session, which takes the phone and root
// keys for the kernel's roster from the claim it keeps (GET /setup/secrets-cert).
// The backups come from the router, which holds the bucket's read key and passes the objects on as they are:
//   stores/<name>.json    {doc, sig}: doc = {"kind":"store-backup","name","sensitive","sealed":{e,data},"at"},
//                         sig = the setup key's ECDSA over the doc text; sealed to the master key
//                         (info "jarvis2/backup", the store's name as associated data) → JSON values
//   sensitive/<name>.json {doc, sig}: doc = {"kind":"store-sensitive","name","at"} — the store is sensitive
//                         whatever its backup says
//   keys/<store>/<key>.json {kind "key-backup", store, key, deleted, sealed {e,data} | null, backupSha256, e,
//                         dataSha256, writer {by "setup"|"router"|"machine"|"restore", sig, machine?, receipt?}, secrets
//                         (secrets' identity), explanation, at (RFC 3339)}: one key, written after the whole-store backups
//                         (router/storedocs.go, storerestore.go). A setup writer signed Checks.writerText (backupSha256 =
//                         sha256(sealed.e + "\n" + sealed.data)) with the setup key; a router or machine writer is the
//                         router's word (writing secrets is protected only by the router); a phone-approved restore
//                         carries the receipt of a secrets whose identity the box key signed. Sealed to the master key
//                         (info "jarvis2/backup", "<store>\n<key>" as associated data) → the value's raw bytes.
// (infra/setup.py writes the first two; the router the key backups.) So the router can't read a backup; it can withhold
// one, serve an older signed version, or (as any writer of secrets can) write a key in a session's or its own name. A
// store is its whole-store backup with every later key backup of that store laid over it (a deleted one removes the key).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// one store as the backups give it back
struct RecoveredStore { let name: String; let values: [String: String]; let sensitive: Bool }

enum CoreSetup {
  // ---- secrets: its keys (vouched for by the box key) and its own signed state ----
  /// GET api/secrets/identity (kernel Identity)
  struct Identity: Codable, Equatable {
    var role: String? = nil
    let signingKey: String; let agreementKey: String; var boxSig: String? = nil
  }
  struct State: Decodable { let kind: String; let master: String; let phone: PublicKeys? }
  /// secrets as this iPhone sees it
  enum Status: Equatable {
    case empty                // waiting for Reset or Recover
    case mine                 // set up with this iPhone's master key and this iPhone
    case otherPhone           // set up with this master key, but for another iPhone (or this one before a reinstall)
    case foreign              // set up with a master key that isn't this iPhone's
  }

  /// the box key (keys/box.pub) signed secrets' keys, and secrets signed its state: or nothing goes on
  static func check(_ id: Identity, state: SignedDoc, boxKey: String) throws -> (keys: PublicKeys, state: State) {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard id.role == nil || id.role == "secrets", let sig = id.boxSig, CoreCrypto.identityVouched(k, boxSig: sig, boxKey: boxKey) else {
      throw TrustError.badSignature("secrets' keys (not the box key's)")
    }
    let st = try CoreCrypto.decode(state, by: k.signingKey, as: State.self, what: "secrets' state")
    guard st.kind == "secrets-state" else { throw TrustError.mismatch("not secrets' state") }
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
  struct BackupDoc: Decodable { let kind: String; let name: String; let sensitive: Bool; let sealed: [String: String]; var at: Double? = nil }
  /// keys/<store>/<key>.json (router/storedocs.go)
  struct KeyBackup: Decodable {
    /// setup: sig; router, machine: the router's word (machine: its id); restore: secrets' signed receipt (a
    /// phone-approved restore, secrets/history.go)
    struct Writer: Decodable { let by: String; var sig: String? = nil; var machine: String? = nil; var receipt: SignedDoc? = nil }
    let kind: String; let store: String; let key: String; let deleted: Bool
    var sealed: [String: String]? = nil
    let backupSha256: String; let e: String; let dataSha256: String
    let writer: Writer
    var secrets: Identity? = nil
    let at: String
  }
  /// a restore's receipt (secrets/history.go "store-restore-approved"): each key put back with its hashes, each removed
  struct RestoreReceipt: Decodable {
    struct Put: Decodable { let key: String; let e: String; let dataSha256: String; let backupSha256: String }
    let kind: String; let store: String; var put: [Put]? = nil; var remove: [String]? = nil
  }
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

  /// every store in the backups, checked (the setup key; a restore's receipt from a secrets the box key vouched for) and
  /// decrypted (master key): each store's whole-store backup, then its later key backups
  static func readBackups(_ objects: [BackupObject], master: MasterKey, setupKey: String, boxKey: String? = nil) throws -> [RecoveredStore] {
    var marked = Set<String>()
    for o in objects {
      guard let n = name(of: o.key, prefix: "sensitive/") else { continue }
      let m = try JSONDecoder().decode(MarkerDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard m.kind == "store-sensitive", m.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      marked.insert(n)
    }
    var whole: [String: (values: [String: String], sensitive: Bool, at: Date)] = [:]
    for o in objects {
      guard let n = name(of: o.key, prefix: "stores/") else { continue }
      guard whole[n] == nil else { throw TrustError.backup("\(o.key) comes twice.") }
      let d = try JSONDecoder().decode(BackupDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard d.kind == "store-backup", d.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      let plain: Data
      do { plain = try CoreCrypto.open(d.sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: Data(n.utf8)) }
      catch { throw TrustError.backup("\(o.key) doesn't open with this recovery kit.") }
      guard let values = try? JSONDecoder().decode([String: String].self, from: plain) else { throw TrustError.backup("\(o.key) holds something that isn't a store.") }
      whole[n] = (values, d.sensitive || marked.contains(n), Date(timeIntervalSince1970: d.at ?? 0))
    }
    // key backups, each checked and opened, laid over their store's whole-store backup in the order they were written
    var keyed: [(store: String, key: String, value: String?, at: Date)] = []
    var seen = Set<String>()
    for o in objects where o.key.hasPrefix("keys/") {
      guard seen.insert(o.key).inserted else { throw TrustError.backup("\(o.key) comes twice.") }
      let (b, value) = try openKeyBackup(o, master: master, setupKey: setupKey, boxKey: boxKey)
      guard let at = Checks.isoDate(b.at) else { throw TrustError.backup("\(o.key) has no time it was written.") }
      keyed.append((b.store, b.key, value, at))
    }
    var out: [String: RecoveredStore] = [:]
    for (n, w) in whole { out[n] = RecoveredStore(name: n, values: w.values, sensitive: w.sensitive) }
    for k in keyed.sorted(by: { $0.at < $1.at }) {
      if let w = whole[k.store], k.at <= w.at { continue } // the whole-store backup is newer: it holds the key as it was then
      // a store only key backups name: sensitive (only create_store makes a store that isn't, and its backup says so)
      var s = out[k.store] ?? RecoveredStore(name: k.store, values: [:], sensitive: true)
      var v = s.values
      v[k.key] = k.value
      s = RecoveredStore(name: s.name, values: v, sensitive: s.sensitive || marked.contains(k.store))
      out[k.store] = s
    }
    return out.values.sorted { $0.name < $1.name }
  }

  /// "keys/<store>/<key>.json" → (store, key)
  static func keyName(_ key: String) -> (store: String, key: String)? {
    guard let rest = name(of: key, prefix: "keys/") else { return nil }
    let parts = rest.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
    return (String(parts[0]), String(parts[1]))
  }

  /// one key backup: it names its own store and key, its hash is of its sealed value, and its writer is one the app takes
  /// (the setup key's signature; the router's word for itself or a session's machine; a restore's receipt from a secrets
  /// the box key vouched for). Problems as one plain sentence.
  static func checkKeyBackup(_ o: BackupObject, setupKey: String, boxKey: String?) throws -> KeyBackup {
    guard let (store, key) = keyName(o.key) else { throw TrustError.backup("\(o.key) isn't a key backup.") }
    guard let b = try? JSONDecoder().decode(KeyBackup.self, from: Data(o.body.utf8)), b.kind == "key-backup" else { throw TrustError.backup("\(o.key) isn't a key backup.") }
    guard b.store == store, b.key == key else { throw TrustError.backup("\(o.key) names another key.") }
    if b.deleted {
      guard b.sealed == nil, b.e.isEmpty, b.dataSha256.isEmpty, b.backupSha256.isEmpty else { throw TrustError.backup("\(o.key) is a delete that carries a value.") }
    } else {
      guard let s = b.sealed, let se = s["e"], let sd = s["data"],
            CoreCrypto.sha256hex(Data("\(se)\n\(sd)".utf8)) == b.backupSha256 else { throw TrustError.backup("\(o.key)'s hash isn't of its sealed value.") }
    }
    let text = Data(Checks.writerText(store: store, key: key, e: b.e, dataSha256: b.dataSha256, backupSha256: b.backupSha256).utf8)
    /// the secrets the object names, vouched for by the box key
    func vouchedSecrets(_ what: String) throws -> PublicKeys {
      guard let boxKey, let id = b.secrets else { throw TrustError.backup("\(o.key)'s \(what) can't be checked.") }
      let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
      guard let sig = id.boxSig, CoreCrypto.identityVouched(k, boxSig: sig, boxKey: boxKey) else { throw TrustError.backup("\(o.key) names a secrets the box key didn't vouch for.") }
      return k
    }
    let sig = b.writer.sig ?? ""
    switch b.writer.by {
    case "setup":
      guard CoreCrypto.valid(text, sig: sig, by: setupKey) else { throw TrustError.backup("\(o.key) isn't signed by the setup key.") }
    case "restore":
      // a phone-approved restore: secrets' signed receipt names this key put back (its hashes) or removed
      let k = try vouchedSecrets("restore")
      guard let rd = b.writer.receipt, let r = try? CoreCrypto.decode(rd, by: k.signingKey, as: RestoreReceipt.self, what: "the restore receipt"),
            r.kind == "store-restore-approved", r.store == store else { throw TrustError.backup("\(o.key)'s restore receipt isn't that secrets'.") }
      if b.deleted {
        guard (r.remove ?? []).contains(key) else { throw TrustError.backup("\(o.key)'s restore receipt doesn't remove it.") }
      } else {
        guard (r.put ?? []).contains(where: { $0.key == key && $0.e == b.e && $0.dataSha256 == b.dataSha256 && $0.backupSha256 == b.backupSha256 })
        else { throw TrustError.backup("\(o.key)'s restore receipt doesn't name this value.") }
      }
    case "router":
      break // the router's own write (the Claude login): its word
    case "machine":
      guard let m = b.writer.machine, !m.isEmpty else { throw TrustError.backup("\(o.key) names no session machine as its writer.") }
    default:
      throw TrustError.backup("\(o.key) was written by \(b.writer.by).")
    }
    return b
  }

  /// a key backup checked and opened: its value (nil for a delete)
  static func openKeyBackup(_ o: BackupObject, master: MasterKey, setupKey: String, boxKey: String?) throws -> (KeyBackup, String?) {
    let b = try checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey)
    guard !b.deleted, let sealed = b.sealed else { return (b, nil) }
    let plain: Data
    do { plain = try CoreCrypto.open(sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: b.store, key: b.key)) }
    catch { throw TrustError.backup("\(o.key) doesn't open with this recovery kit.") }
    guard let v = String(data: plain, encoding: .utf8) else { throw TrustError.backup("\(o.key) holds something that isn't text.") }
    return (b, v)
  }

  /// the claim statement: this master key sets up this secrets (`core`: its keys) for this iPhone, with this bundle.
  /// `root`: this iPhone's root key (PhoneKeys.rootPublic), `device`: this install's long-lived device key
  /// (PhoneKeys.devicePublic): both inside the master-signed text so the setup session takes them only from there (a
  /// router can't attach its own); secrets ignores them
  static func statement(master: String, core: PublicKeys, phone: PublicKeys, bundle: Data, root: String? = nil, device: String? = nil) throws -> String {
    struct St: Encodable { let kind = "claim"; let master: String; let core: PublicKeys; let phone: PublicKeys; let bundleSha256: String; let root: String?; let device: String? }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try e.encode(St(master: master, core: core, phone: phone, bundleSha256: CoreCrypto.sha256hex(bundle), root: root, device: device)), as: UTF8.self)
  }

  /// the body of POST /api/secrets/claim
  static func claim(core: PublicKeys, phone: PublicKeys, master: MasterKey, bundle: Data, root: String? = nil, device: String? = nil) throws -> [String: Any] {
    let st = try statement(master: master.publicKey, core: core, phone: phone, bundle: bundle, root: root, device: device)
    return ["statement": st, "masterSig": try master.sign(st), "bundle": try CoreCrypto.seal(bundle, to: core.agreementKey, info: CoreCrypto.claimInfo)]
  }

  /// the body of POST /api/secrets/wipe: secrets' own master key ends it (a new, empty secrets takes its place)
  static func wipe(core: PublicKeys, master: MasterKey, device: String? = nil) throws -> [String: Any] {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    struct W: Encodable { let kind = "wipe"; let core: String; let device: String? }
    let st = String(decoding: try e.encode(W(core: core.signingKey, device: device)), as: UTF8.self)
    return ["statement": st, "masterSig": try master.sign(st)]
  }
}

// ---- Recover: every key wrapped on its own to secrets' store key ------------------------------------------------------
extension CoreSetup {
  /// the bundle secrets reads (format "keys"): every store's name but `core`, every key of them wrapped to the store key
  /// (its value's raw bytes, "<store>\n<key>" as associated data), which stores are not sensitive, which repo owns each
  /// deploy-key store. The `core` store's Fly token isn't in it: secrets never holds it (the setup session gives it to
  /// the spawner, POST /setup/fly-token).
  static func keysBundle(_ stores: [RecoveredStore], storeKey: String) throws -> Data {
    struct B: Encodable {
      let format = "keys"; let keys: [KeyEntry]; let notSensitive: [String]; let owners: [String: String]; let stores: [String]
    }
    let rest = stores.filter { $0.name != StoreView.coreStore }
    let keys = try rest.flatMap { try CoreCrypto.wrapKeys(store: $0.name, values: $0.values, storeKey: storeKey) }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try e.encode(B(keys: keys, notSensitive: rest.filter { !$0.sensitive }.map(\.name), owners: owners(rest), stores: rest.map(\.name)))
  }
  /// a deploy-key store → its repo (from its GITHUB_DEPLOY_REPO_ key)
  static func owners(_ stores: [RecoveredStore]) -> [String: String] {
    var owners: [String: String] = [:]
    for s in stores where s.name.hasPrefix("github-") {
      if let repo = s.values.first(where: { $0.key.hasPrefix("GITHUB_DEPLOY_REPO_") })?.value { owners[s.name] = repo }
    }
    return owners
  }
}

// ---- the offline copy (Settings → Encrypted backup) ---------------------------------------------------------------
// The objects exactly as the router served them, each signature checked against keys/setup.pub like Recover does, and
// saved as ONE file: {format "jarvis2-backup-export", version 1, bucket, fetchedAt, setupKey, setupKeySource, objects}.
// Nothing is opened here and no kit is needed: tools/decrypt-backup.py opens the file offline with the kit (it checks
// the signatures again, against the file's setup key and keys/setup.pub).
extension CoreSetup {
  /// one object's check: nil problem = signed by the setup key and naming its own store
  struct BackupCheck: Equatable, Identifiable { let key: String; let problem: String?; var id: String { key } }
  static let exportFormat = "jarvis2-backup-export", exportVersion = 1

  /// the same per-object checks as readBackups, minus opening: signed, the setup key's, the doc names its own key
  static func checkSignatures(_ objects: [BackupObject], setupKey: String, boxKey: String? = nil) -> [BackupCheck] {
    var seen = Set<String>()
    return objects.map { o in
      if o.key.hasPrefix("keys/") {
        guard seen.insert(o.key).inserted else { return BackupCheck(key: o.key, problem: "Comes twice") }
        do { _ = try checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey); return BackupCheck(key: o.key, problem: nil) }
        catch { return BackupCheck(key: o.key, problem: (error as? LocalizedError)?.errorDescription ?? "Not a key backup") }
      }
      guard let s = try? JSONDecoder().decode(Signed.self, from: Data(o.body.utf8)) else { return BackupCheck(key: o.key, problem: "Not a signed document") }
      guard CoreCrypto.valid(Data(s.doc.utf8), sig: s.sig, by: setupKey) else { return BackupCheck(key: o.key, problem: "Not signed by the setup key") }
      let doc = (try? JSONDecoder().decode(MarkerDoc.self, from: Data(s.doc.utf8)))
      if let n = name(of: o.key, prefix: "stores/") {
        guard doc?.kind == "store-backup", doc?.name == n else { return BackupCheck(key: o.key, problem: "Names another store") }
        guard seen.insert(n).inserted else { return BackupCheck(key: o.key, problem: "Comes twice") }
      } else if let n = name(of: o.key, prefix: "sensitive/") {
        guard doc?.kind == "store-sensitive", doc?.name == n else { return BackupCheck(key: o.key, problem: "Names another store") }
      } else {
        return BackupCheck(key: o.key, problem: "Not a store backup")
      }
      return BackupCheck(key: o.key, problem: nil)
    }
  }

  /// the file's bytes (sorted keys, slashes as they are; each body unchanged)
  static func exportFile(bucket: String, objects: [BackupObject], setupKey: String, setupKeySource: String, fetchedAt: Date) throws -> Data {
    struct O: Encodable { let key: String; let body: String }
    struct F: Encodable {
      let format = CoreSetup.exportFormat; let version = CoreSetup.exportVersion
      let bucket: String; let fetchedAt: String; let setupKey: String; let setupKeySource: String; let objects: [O]
    }
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime]
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
    return try e.encode(F(bucket: bucket, fetchedAt: iso.string(from: fetchedAt), setupKey: setupKey, setupKeySource: setupKeySource,
                          objects: objects.map { O(key: $0.key, body: $0.body) }))
  }

  /// jarvis2-backup-2026-10-13-1015.json (UTC)
  static func exportName(_ at: Date) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd-HHmm"
    return "jarvis2-backup-\(f.string(from: at)).json"
  }
}
