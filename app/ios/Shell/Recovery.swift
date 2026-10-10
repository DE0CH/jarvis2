// Recovery's work, with no UI or Keychain in it (compiled into the interop test too): read the store backups
// from the versioned bucket (S3 SigV4 with CryptoKit's HMAC — no AWS SDK), check each object's signature by
// the setup key, decrypt each with the master key, and build what POST /api/core/recover takes.
//   stores/<name>.json    {doc, sig}: doc = {"kind":"store-backup","name","sensitive","sealed":{e,data},"at"},
//                         sig = the setup key's ECDSA over the doc text; sealed to the master key
//                         (info "jarvis2/backup", the store's name as associated data) → JSON values
//   sensitive/<name>.json {doc, sig}: doc = {"kind":"store-sensitive","name","at"} — the store is sensitive
//                         whatever its backup says
// (infra/setup.py writes both.) The bundle {stores:[{name, values}], notSensitive:[names]} goes sealed to the
// core (info "jarvis2/recover"); the statement {"kind":"recovery","core":{…},"phone":{…},"bundleSha256"} is
// signed by the master key.
// The read keys themselves reach the phone sealed to the master key (openKeys) and go into the recovery kit
// (CoreCrypto.swift RecoveryKit), the one string Deyao keeps.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(FoundationXML)
import FoundationXML
#endif

/// the backup bucket (production values; a CI build may point elsewhere — Trust.swift)
struct S3Bucket {
  var endpoint = "https://fsn1.your-objectstorage.com"
  var region = "fsn1"
  var bucket = "jarvis2-backup-de0ch"
}

/// S3 reads (ListObjectsV2, GetObject), path-style, signed with AWS Signature V4
struct S3Reader {
  let bucket: S3Bucket, creds: S3Credentials
  var session: URLSession = .shared

  static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
  static func enc(_ s: String, slash: Bool = false) -> String {
    s.addingPercentEncoding(withAllowedCharacters: slash ? unreserved.union(CharacterSet(charactersIn: "/")) : unreserved) ?? s
  }
  private static func hmac(_ key: Data, _ msg: String) -> Data { Data(HMAC<SHA256>.authenticationCode(for: Data(msg.utf8), using: SymmetricKey(data: key))) }

  /// a signed GET request for /<bucket>/<key>?<query>
  func request(key: String, query: [String: String], now: Date = Date()) -> URLRequest {
    let base = bucket.endpoint.hasSuffix("/") ? String(bucket.endpoint.dropLast()) : bucket.endpoint
    let path = "/" + S3Reader.enc(bucket.bucket) + (key.isEmpty ? "" : "/" + S3Reader.enc(key, slash: true))
    let q = query.sorted { $0.key < $1.key }.map { S3Reader.enc($0.key) + "=" + S3Reader.enc($0.value) }.joined(separator: "&")
    let url = URL(string: base + path + (q.isEmpty ? "" : "?" + q))!
    let host = url.host! + (url.port.map { ":\($0)" } ?? "")
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"; let amzDate = f.string(from: now)
    let day = String(amzDate.prefix(8))
    let payload = CoreCrypto.sha256hex(Data())
    let signed = "host;x-amz-content-sha256;x-amz-date"
    let canonical = ["GET", path, q, "host:\(host)\nx-amz-content-sha256:\(payload)\nx-amz-date:\(amzDate)\n", signed, payload].joined(separator: "\n")
    let scope = "\(day)/\(bucket.region)/s3/aws4_request"
    let toSign = "AWS4-HMAC-SHA256\n\(amzDate)\n\(scope)\n\(CoreCrypto.sha256hex(Data(canonical.utf8)))"
    var k = S3Reader.hmac(Data("AWS4\(creds.secretKey)".utf8), day)
    for part in [bucket.region, "s3", "aws4_request"] { k = S3Reader.hmac(k, part) }
    let sig = CoreCrypto.hex(S3Reader.hmac(k, toSign))
    var r = URLRequest(url: url)
    r.httpMethod = "GET"
    r.cachePolicy = .reloadIgnoringLocalCacheData
    r.timeoutInterval = 60
    r.setValue(payload, forHTTPHeaderField: "x-amz-content-sha256")
    r.setValue(amzDate, forHTTPHeaderField: "x-amz-date")
    r.setValue("AWS4-HMAC-SHA256 Credential=\(creds.accessKey)/\(scope), SignedHeaders=\(signed), Signature=\(sig)", forHTTPHeaderField: "Authorization")
    return r
  }

  private func fetch(_ r: URLRequest) async throws -> Data {
    let (status, data): (Int, Data) = try await withCheckedThrowingContinuation { k in
      session.dataTask(with: r) { d, resp, err in
        if let err { k.resume(throwing: err) } else { k.resume(returning: ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data())) }
      }.resume()
    }
    guard status == 200 else {
      let code = S3Reader.xmlValue(data, "Code") ?? "HTTP \(status)"
      throw TrustError.backup("The backup bucket refused the request: \(code)\(code == "SignatureDoesNotMatch" || code == "InvalidAccessKeyId" ? " — check the bucket credentials." : "")")
    }
    return data
  }

  /// every key under `prefix` (all pages)
  func list(prefix: String) async throws -> [String] {
    var keys: [String] = [], token: String?
    repeat {
      var q = ["list-type": "2", "prefix": prefix]
      if let token { q["continuation-token"] = token }
      let d = try await fetch(request(key: "", query: q))
      let p = ListParser(); let x = XMLParser(data: d); x.delegate = p
      guard x.parse() else { throw TrustError.backup("The backup bucket's listing isn't readable.") }
      keys += p.keys
      token = p.truncated ? p.next : nil
    } while token != nil
    return keys
  }
  func get(_ key: String) async throws -> Data { try await fetch(request(key: key, query: [:])) }

  static func xmlValue(_ d: Data, _ tag: String) -> String? {
    let s = String(decoding: d, as: UTF8.self)
    guard let a = s.range(of: "<\(tag)>"), let b = s.range(of: "</\(tag)>", range: a.upperBound..<s.endIndex) else { return nil }
    return String(s[a.upperBound..<b.lowerBound])
  }
}

private final class ListParser: NSObject, XMLParserDelegate {
  var keys: [String] = [], truncated = false, next: String?
  private var text = ""
  func parser(_ parser: XMLParser, didStartElement e: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) { text = "" }
  func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
  func parser(_ parser: XMLParser, didEndElement e: String, namespaceURI: String?, qualifiedName: String?) {
    switch e {
    case "Key": keys.append(text)
    case "IsTruncated": truncated = text == "true"
    case "NextContinuationToken": next = text
    default: break
    }
  }
}

/// one store as the backups give it back
struct RecoveredStore { let name: String; let values: [String: String]; let sensitive: Bool }

enum Recovery {
  struct Signed: Decodable { let doc: String; let sig: String }
  struct BackupDoc: Decodable { let kind: String; let name: String; let sensitive: Bool; let sealed: [String: String] }
  struct MarkerDoc: Decodable { let kind: String; let name: String }

  static func name(of key: String, prefix: String) -> String? {
    guard key.hasPrefix(prefix), key.hasSuffix(".json") else { return nil }
    return String(key.dropFirst(prefix.count).dropLast(5))
  }
  private static func signed(_ data: Data, key: String, setupKey: String) throws -> Data {
    guard let o = try? JSONDecoder().decode(Signed.self, from: data) else { throw TrustError.backup("\(key) in the bucket isn't a signed document.") }
    let doc = Data(o.doc.utf8)
    guard CoreCrypto.valid(doc, sig: o.sig, by: setupKey) else { throw TrustError.backup("\(key) in the bucket isn't signed by the setup key — refusing to recover from it.") }
    return doc
  }

  /// every store in the bucket, checked (setup key) and decrypted (master key)
  static func readBackups(_ s3: S3Reader, master: MasterKey, setupKey: String, progress: (String) -> Void = { _ in }) async throws -> [RecoveredStore] {
    progress("Listing the backups…")
    let storeKeys = try await s3.list(prefix: "stores/"), markerKeys = try await s3.list(prefix: "sensitive/")
    var marked = Set<String>()
    for k in markerKeys {
      guard let n = name(of: k, prefix: "sensitive/") else { continue }
      let m = try JSONDecoder().decode(MarkerDoc.self, from: try signed(try await s3.get(k), key: k, setupKey: setupKey))
      guard m.kind == "store-sensitive", m.name == n else { throw TrustError.backup("\(k) names another store.") }
      marked.insert(n)
    }
    var out: [RecoveredStore] = []
    for (i, k) in storeKeys.enumerated() {
      guard let n = name(of: k, prefix: "stores/") else { continue }
      progress("Reading backup \(i + 1) of \(storeKeys.count)…")
      let d = try JSONDecoder().decode(BackupDoc.self, from: try signed(try await s3.get(k), key: k, setupKey: setupKey))
      guard d.kind == "store-backup", d.name == n else { throw TrustError.backup("\(k) names another store.") }
      let plain: Data
      do { plain = try CoreCrypto.open(d.sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: Data(n.utf8)) }
      catch { throw TrustError.backup("\(k) doesn't open with this master key — is it the right one?") }
      guard let values = try? JSONDecoder().decode([String: String].self, from: plain) else { throw TrustError.backup("\(k) holds something that isn't a store.") }
      out.append(RecoveredStore(name: n, values: values, sensitive: d.sensitive || marked.contains(n)))
    }
    return out.sorted { $0.name < $1.name }
  }

  /// the bundle's exact bytes; the `core` store (FLY_API_TOKEN, FLY_APP) must be there
  static func bundle(_ stores: [RecoveredStore]) throws -> Data {
    guard let c = stores.first(where: { $0.name == StoreView.coreStore }), !(c.values["FLY_API_TOKEN"] ?? "").isEmpty, !(c.values["FLY_APP"] ?? "").isEmpty else {
      throw TrustError.backup("The backups have no core store with FLY_API_TOKEN and FLY_APP — the core can't start machines without it.")
    }
    struct S: Encodable { let name: String; let values: [String: String] }
    struct B: Encodable { let stores: [S]; let notSensitive: [String] }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try e.encode(B(stores: stores.map { S(name: $0.name, values: $0.values) }, notSensitive: stores.filter { !$0.sensitive }.map(\.name)))
  }

  static func statement(core: PublicKeys, phone: PublicKeys, bundle: Data) throws -> String {
    struct St: Encodable { let kind = "recovery"; let core: PublicKeys; let phone: PublicKeys; let bundleSha256: String }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try e.encode(St(core: core, phone: phone, bundleSha256: CoreCrypto.sha256hex(bundle))), as: UTF8.self)
  }

  // ---- the backup bucket's read keys, from the setup session through the router (GET /api/recovery-keys) ----
  /// {doc, sig}: doc = {"kind":"recovery-keys","bucket","credential","sealed":{e,data},"at"}, sig = the setup
  /// key's ECDSA over the doc text; sealed to the master key (info "jarvis2/backup", associated data
  /// "jarvis2/recovery-keys") → {"accessKey","secretKey"} (infra/setup.py recovery-keys writes it)
  struct SealedKeys: Codable { let doc: String; let sig: String }
  struct SealedKeysDoc: Decodable { let kind: String; let bucket: String?; let credential: String?; let sealed: [String: String]; let at: Int? }
  static let recoveryKeysAAD = Data("jarvis2/recovery-keys".utf8)

  /// checked against the setup key (keys/setup.pub), opened with the master key
  static func openKeys(_ k: SealedKeys, setupKey: String, master: MasterKey) throws -> (creds: S3Credentials, doc: SealedKeysDoc) {
    guard CoreCrypto.valid(Data(k.doc.utf8), sig: k.sig, by: setupKey) else {
      throw TrustError.badSignature("the backup bucket's read keys (not the setup key's)")
    }
    guard let d = try? JSONDecoder().decode(SealedKeysDoc.self, from: Data(k.doc.utf8)), d.kind == "recovery-keys" else {
      throw TrustError.backup("The sealed read keys aren't a recovery-keys document.")
    }
    let plain: Data
    do { plain = try CoreCrypto.open(d.sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: recoveryKeysAAD) }
    catch { throw TrustError.backup("The sealed read keys don't open with this master key — is it the right one?") }
    guard let c = try? JSONDecoder().decode(S3Credentials.self, from: plain), !c.accessKey.isEmpty, !c.secretKey.isEmpty else {
      throw TrustError.backup("The sealed read keys hold something that isn't a credential.")
    }
    return (c, d)
  }

  /// the body of POST /api/core/recover
  static func request(core: PublicKeys, phone: PublicKeys, master: MasterKey, bundle: Data) throws -> [String: Any] {
    let st = try statement(core: core, phone: phone, bundle: bundle)
    return ["statement": st, "masterSig": try master.sign(st), "bundle": try CoreCrypto.seal(bundle, to: core.agreementKey, info: CoreCrypto.recoverInfo)]
  }
}
