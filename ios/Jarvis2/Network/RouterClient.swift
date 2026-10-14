// The app's client of the router (docs/API.md) — an ordinary network path: integrity comes from the kernel's signatures
// (secrets' checked here against the keys pinned when this iPhone set secrets up; the other parts' against the box key's
// word for them, KernelTrust) and the phone's (made here). Sign-in:
// ASWebAuthenticationSession on /api/auth/start → jarvis2://auth#token=<Access JWT>, kept in the Keychain and sent as
// `cf-access-token` on every request (never cookies, except into the terminal page's WebView: TerminalView).
import AuthenticationServices
import Foundation
import UIKit

/// a failed request, in words; `status` and `body` for the callers that act on them (a 403 {needsTerminal}, a 404)
struct RouterError: LocalizedError {
  let message: String
  var status = 0
  var body: JSON = .null
  var errorDescription: String? { message }
}
/// Cloudflare Access refused the login and the sign-in sheet didn't complete
struct SignedOut: LocalizedError { var errorDescription: String? { "Signed out of Cloudflare Access." } }

@MainActor
final class RouterClient: NSObject, ASWebAuthenticationPresentationContextProviding {
  static let shared = RouterClient()
  let base: URL = {
    let s = (Bundle.main.object(forInfoDictionaryKey: "JarvisBase") as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "https://jarvis2.deyaochen.com/"
    return URL(string: s.hasSuffix("/") ? s : s + "/") ?? URL(string: "https://jarvis2.deyaochen.com/")!
  }()
  var token: String { Keychain.string("access-token") ?? "" }
  /// told when sign-in failed or came back (AppModel shows the signed-out screen)
  var onSignedOut: ((Bool) -> Void)?

  // ---- sign-in ----
  private var signing: Task<String, Never>?
  private var webSession: ASWebAuthenticationSession?
  /// runs the sign-in sheet once (callers meanwhile share it); "" when cancelled or failed
  func signIn() async -> String {
    if let signing { return await signing.value }
    let t = Task { @MainActor () -> String in
      defer { signing = nil }
      var c = URLComponents(url: base.appending(path: "api/auth/start"), resolvingAgainstBaseURL: false)
      c?.queryItems = [URLQueryItem(name: "redirect", value: "jarvis2://auth")]
      guard let start = c?.url else { return "" }
      // not while the phone is locked or the app is on its way back (a refresh on unlock finds the login expired):
      // the sheet can't present then, so wait until the app is active with a window to present on
      while UIApplication.shared.applicationState != .active || Self.keyWindow == nil {
        try? await Task.sleep(for: .milliseconds(300))
      }
      // ResumeOnce: a sheet that can't present both calls back (with an error) and returns false from start()
      let url: URL? = await ResumeOnce.run(failed: nil) { done in
        let s = ASWebAuthenticationSession(url: start, callback: .customScheme("jarvis2")) { u, _ in done(u) }
        s.presentationContextProvider = self
        webSession = s
        return s.start()
      }
      webSession = nil
      guard let frag = url?.fragment, let tok = URLComponents(string: "x:?" + frag)?.queryItems?.first(where: { $0.name == "token" })?.value, !tok.isEmpty else {
        onSignedOut?(true)
        return ""
      }
      Keychain.setString("access-token", tok)
      onSignedOut?(false)
      return tok
    }
    signing = t
    return await t.value
  }
  private static var keyWindow: UIWindow? {
    UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.keyWindow }.first
  }
  nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    MainActor.assumeIsolated { Self.keyWindow ?? ASPresentationAnchor() }
  }

  // ---- requests ----
  /// Access turned the request away: it ended on the Access login, or a 401/403 that isn't JSON, or the router's own
  /// "Access login required"
  private func refused(_ resp: HTTPURLResponse, _ data: Data) -> Bool {
    if (resp.url?.host ?? "").hasSuffix("cloudflareaccess.com") { return true }
    guard resp.statusCode == 401 || resp.statusCode == 403 else { return false }
    let ct = resp.value(forHTTPHeaderField: "Content-Type") ?? ""
    return !ct.contains("json") || String(decoding: data, as: UTF8.self).contains("Access login required")
  }
  func url(_ path: String) -> URL {
    // a path with a query ("api/search?q=…") is resolved as a relative reference, so the query stays a query
    URL(string: path, relativeTo: base)?.absoluteURL ?? base.appending(path: path)
  }
  /// `upload`: raw bytes as the body instead of JSON, with `headers`
  func raw(_ method: String, _ path: String, _ body: [String: Any]? = nil, upload: Data? = nil, headers: [String: String] = [:],
           timeout: TimeInterval = 60) async throws -> (Int, Data) {
    for attempt in 0..<2 {
      var r = URLRequest(url: url(path))
      r.httpMethod = method
      r.timeoutInterval = timeout
      if let body { r.httpBody = try JSONSerialization.data(withJSONObject: body); r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
      if let upload { r.httpBody = upload; r.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type") }
      for (k, v) in headers { r.setValue(v, forHTTPHeaderField: k) }
      if !token.isEmpty { r.setValue(token, forHTTPHeaderField: "cf-access-token") }
      r.httpShouldHandleCookies = false
      let (data, resp) = try await URLSession.shared.data(for: r)
      guard let h = resp as? HTTPURLResponse else { throw RouterError(message: "no HTTP answer") }
      if refused(h, data) {
        if attempt == 0, !(await signIn()).isEmpty { continue }
        throw SignedOut()
      }
      return (h.statusCode, data)
    }
    throw SignedOut()
  }
  /// JSON answer; errors (the router's {error} or a kernel part's signed error doc) as their message
  func json<T: Decodable>(_ method: String, _ path: String, _ body: [String: Any]? = nil, as: T.Type = T.self) async throws -> T {
    let (status, data) = try await raw(method, path, body)
    guard (200..<300).contains(status) else { throw Self.failure(method, path, status, data) }
    return try JSONDecoder().decode(T.self, from: data)
  }
  /// any router call, its answer as JSON
  @discardableResult
  func call(_ method: String, _ path: String, _ body: [String: Any]? = nil, timeout: TimeInterval = 60) async throws -> JSON {
    let (status, data) = try await raw(method, path, body, timeout: timeout)
    guard (200..<300).contains(status) else { throw Self.failure(method, path, status, data) }
    return JSON.parse(data)
  }
  func get(_ path: String) async throws -> JSON { try await call("GET", path) }

  // ---- first-prompt attachments (router/uploads.go) ----
  /// the router's record of one uploaded file: the name it made safe, the size it stored
  struct Uploaded: Decodable { let name: String; let size: Int; let isImage: Bool }
  /// RFC 3986 unreserved characters (ASCII only: a header value and a URL path segment)
  static func escaped(_ s: String) -> String {
    s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")) ?? s
  }
  /// one file of New session's attachments, staged on the router under `id` (the form's upload id)
  func upload(id: String, name: String, data: Data) async throws -> Uploaded {
    let (status, out) = try await raw("POST", "api/uploads", upload: data, headers: ["x-upload-id": id, "x-upload-name": Self.escaped(name)], timeout: 300)
    guard (200..<300).contains(status) else { throw Self.failure("POST", "api/uploads", status, out) }
    return try JSONDecoder().decode(Uploaded.self, from: out)
  }
  /// a staged file of a session not started yet (the approval page hashes it against the signed config)
  func attachment(session: String, name: String) async throws -> Data {
    let path = "api/sessions/\(Self.escaped(session))/attachments/\(Self.escaped(name))"
    let (status, out) = try await raw("GET", path, timeout: 120)
    guard (200..<300).contains(status) else { throw Self.failure("GET", path, status, out) }
    return out
  }

  static func failure(_ method: String, _ path: String, _ status: Int, _ data: Data) -> RouterError {
    let hint: [Int: String] = [400: "bad request", 401: "not authorised", 403: "forbidden", 404: "not found", 409: "conflict", 413: "request too large",
                               423: "locked", 429: "rate-limited, try again shortly", 500: "router error", 502: "bad gateway", 503: "unavailable", 504: "timed out"]
    let why = reason(data) ?? hint[status] ?? "request failed"
    return RouterError(message: why, status: status, body: JSON.parse(data))
  }
  static func reason(_ data: Data) -> String? {
    guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    if let p = j["payload"] as? String, let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let e = pj["error"] as? String { return e }
    return (j["error"] as? String) ?? (j["message"] as? String)
  }

  // ---- secrets, relayed (api/secrets/*): every answer checked against the pinned key ----
  func stores() async throws -> [StoreView] { try await storesDoc().stores }

  /// the content stores (router/content.go): name, file count, bytes
  struct ContentStoreDTO: Decodable, Identifiable, Hashable { let name: String; let files: Int; let bytes: Int; var id: String { name } }
  private struct ContentList: Decodable { let stores: [ContentStoreDTO] }
  func contentStores() async throws -> [ContentStoreDTO] { try await json("GET", "api/content", as: ContentList.self).stores }
  /// secrets' signed store list
  func storesDoc() async throws -> StoresDoc {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/stores", ["nonce": n], as: SignedDoc.self), by: try CoreTrust.key(), as: StoresDoc.self, what: "the store list")
    guard d.kind == "stores", d.nonce == n else { throw TrustError.stale("store list") }
    return d
  }
  /// the setup key from git, only when a writer needs checking
  private func setupKeyIfNeeded(_ ws: [StoreWriter?]) async throws -> String? {
    ws.contains { $0?.by == "setup" } ? try await KeySource.key("setup.pub") : nil
  }
  private func setupKeyIfNeeded(_ w: StoreWriter?) async throws -> String? { try await setupKeyIfNeeded([w]) }
  func unlocked() async throws -> [UnlockRow] {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/unlocked", ["nonce": n], as: SignedDoc.self), by: try CoreTrust.key(), as: UnlockedDoc.self, what: "the unlocked list")
    guard d.kind == "unlocked-list", d.nonce == n else { throw TrustError.stale("unlocked list") }
    return d.unlocked
  }
  /// an unlock of one store: secrets' signed begin, every key's writer checked (the setup key's signature, a session's
  /// machine or the router: the page names a session's write, or secrets itself)
  func unlockBegin(_ store: String) async throws -> UnlockBegin {
    let b = try CoreCrypto.decode(try await json("POST", "api/secrets/unlock/begin", ["store": store], as: SignedDoc.self), by: try CoreTrust.key(), as: UnlockBegin.self, what: "the unlock")
    guard b.kind == "unlock-begin", b.store == store else { throw TrustError.stale("unlock of \(b.store)") }
    try Checks.unlockKeys(b, setupKey: try await setupKeyIfNeeded(b.keys.map(\.writer)))
    return b
  }
  /// this phone's shares x(p·E), one per `b.es` in order, each sealed to secrets' one-off key T
  func unlockFinish(_ b: UnlockBegin, shares: [Data]) async throws {
    guard shares.count == b.es.count else { throw TrustError.stale("unlock of \(b.store)") }
    var m: [String: Any] = [:]
    for (k, x) in zip(b.keys, shares) { m[k.key] = try CoreCrypto.sealShare(x, to: b.t) }
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/unlock/finish", ["pending": b.pending, "shares": m], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the unlocked answer")
    guard d.kind == "unlocked", d.store == b.store else { throw TrustError.stale("unlocked \(d.store ?? "?")") }
  }
  func lock(_ id: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/lock", ["id": id], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the locked answer")
    guard d.kind == "locked", d.id == id else { throw TrustError.stale("lock") }
  }
  func markSensitive(_ name: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/stores/mark-sensitive", ["name": name], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the mark")
    guard d.kind == "marked-sensitive", d.name == name else { throw TrustError.stale("mark") }
  }
  func createStore(_ name: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/stores/create", ["name": name], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the new store")
    guard d.kind == "store-created", d.name == name else { throw TrustError.stale("create") }
  }

  // ---- deploy keys: a repo added or removed (secrets/deploykeys.go) ----
  /// secrets' signed begin document, checked: this action, this repo, its store, the one token store it opens. An add:
  /// the app makes the ed25519 pair, wraps the private half into the repo's store keys to secrets' store key, and sends
  /// both; the signed begin must echo them.
  func deployKeyBegin(action: String, repo: String, sensitive: Bool) async throws -> (doc: SignedDoc, begin: DeployKeyBegin) {
    let store = Checks.repoStore(repo), title = "jarvis2 " + store
    var body: [String: Any] = ["action": action, "repo": repo, "sensitive": sensitive, "store": store, "title": title]
    var sent: DeployKeySent?
    if action == "add" {
      let sk = try await storeKey(coreKey: try CoreTrust.key())
      let kp = try OpenSSH.ed25519(comment: title)
      let values = OpenSSH.storeValues(repo: repo, privateKeyFile: kp.privateKeyFile)
      // each value under its own data key, "<store>\n<key>" as associated data
      let keys = try CoreCrypto.wrapKeys(store: store, values: values, storeKey: sk)
      body["publicKey"] = kp.publicKey
      body["keys"] = keys.map(\.json)
      sent = DeployKeySent(publicKey: kp.publicKey, keys: keys)
    }
    let d = try await json("POST", "api/repos/key/begin", body, as: SignedDoc.self)
    let b = try Checks.deployKeyBegin(d, coreKey: try CoreTrust.key(), action: action, repo: repo, sensitive: sensitive, sent: sent)
    try await checkTokenWriter(b)
    return (d, b)
  }
  /// who wrote the GitHub token the phone's share opens: the setup key (its signature over the token key's writer text)
  /// or secrets; never a session or the router
  private func checkTokenWriter(_ b: DeployKeyBegin) async throws {
    guard let key = b.tokenKey, let w = b.tokenWriter, w.by == "setup" || w.by == "core" else { throw TrustError.mismatch("the GitHub token's writer") }
    try Checks.keyWriter(w, store: b.tokenStore, key: key, e: b.e, dataSha256: b.tokenDataSha256 ?? "", backupSha256: b.tokenBackupSha256 ?? "",
                         setupKey: try await setupKeyIfNeeded(w))
  }
  /// the phone's signature over the begin document and its share of the token store; the answer, checked
  func deployKeyFinish(_ b: DeployKeyBegin, signature: Data, share: Data) async throws -> DeployKeyAnswer {
    let body: [String: Any] = ["pending": b.pending, "signature": signature.base64EncodedString(), "share": try CoreCrypto.sealShare(share, to: b.t)]
    return try Checks.deployKeyAnswer(try await json("POST", "api/repos/key/finish", body, as: SignedDoc.self), coreKey: try CoreTrust.key(), begin: b)
  }

  /// secrets' store key C = P + K for this phone's agreement key, checked against `coreKey` (secrets' signing key)
  func storeKey(coreKey: String) async throws -> String {
    let phone = try PhoneKeys.shared.publicKeys().agreementKey
    let d = try await json("POST", "api/secrets/store-key", ["phone": phone], as: SignedDoc.self)
    return try CoreCrypto.storeKey(d, coreKey: coreKey, phone: phone)
  }

  // ---- what each store and key is for (router/storedocs.go): names, writers, explanations; never values ----
  // ---- a store's earlier versions and putting one back (secrets/history.go, router/storerestore.go) ----
  /// secrets' signed list of a store's kept versions (checked: secrets' key, this call's nonce, this store)
  func storeVersions(_ store: String) async throws -> StoreVersionsDoc {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/stores/versions", ["store": store, "nonce": n], as: SignedDoc.self), by: try CoreTrust.key(),
                                  as: StoreVersionsDoc.self, what: "the store's versions")
    guard d.kind == "store-versions", d.nonce == n, d.store == store else { throw TrustError.stale("versions of \(store)") }
    return d
  }
  /// secrets' signed begin document of putting version `seq` back, checked (each key put back has a writer the phone
  /// accepts); the payload is what the phone signs
  func restoreBegin(_ store: String, seq: Int) async throws -> (doc: SignedDoc, begin: RestoreBegin) {
    let doc = try await json("POST", "api/secrets/stores/restore/begin", ["store": store, "seq": seq], as: SignedDoc.self)
    let b = try CoreCrypto.decode(doc, by: try CoreTrust.key(), as: RestoreBegin.self, what: "the restore")
    try Checks.restoreBegin(b, store: store, seq: seq, setupKey: try await setupKeyIfNeeded(b.put.map { Optional($0.writer) }))
    return (doc, b)
  }
  /// the phone's signature over the begin document and its share of every key put back (in `b.es` order): the router
  /// writes secrets' backups, then secrets commits; the committed answer is checked
  func restoreFinish(_ b: RestoreBegin, signature: Data, shares: [Data]) async throws -> RestoreDone {
    guard shares.count == b.put.count else { throw TrustError.stale("restore of \(b.store)") }
    var m: [String: Any] = [:]
    for (p, x) in zip(b.put, shares) { m[p.key] = try CoreCrypto.sealShare(x, to: b.t) }
    struct Out: Decodable { let restored: SignedDoc }
    let out = try await json("POST", "api/stores/restore/finish", ["pending": b.pending, "signature": signature.base64EncodedString(), "shares": m], as: Out.self)
    let d = try CoreCrypto.decode(out.restored, by: try CoreTrust.key(), as: RestoreDone.self, what: "the restored answer")
    try Checks.restoreDone(d, begin: b)
    return d
  }

  func storeRows() async throws -> [StoreRowDTO] {
    struct L: Decodable { let stores: [StoreRowDTO] }
    return try await json("GET", "api/stores", as: L.self).stores
  }
  /// a store's about text (nil = unchanged) and its keys' explanations ("" removes one)
  func setStoreDocs(_ store: String, about: String?, keys: [String: String]) async throws {
    var body: [String: Any] = ["keys": keys]
    if let about { body["about"] = about }
    try await call("PUT", "api/stores/\(Self.escaped(store))/docs", body)
  }

  // ---- setting secrets up: Reset and Recover ----
  /// secrets' keys with the box key's signature over them, and its signed state (the caller checks both:
  /// CoreSetup.check). Throws CoreNotRunning when there is no secrets to ask (its pod restarting, e.g. after a wipe: 503
  /// {kernelDown}; 502/504 from the edge mean the same)
  func identity() async throws -> (id: CoreSetup.Identity, state: SignedDoc) {
    let (status, data) = try await raw("GET", "api/secrets/identity", nil)
    if status == 503 || status == 502 || status == 504 { throw CoreNotRunning() }
    guard status == 200 else { throw Self.failure("GET", "api/secrets/identity", status, data) }
    let id = try JSONDecoder().decode(CoreSetup.Identity.self, from: data)
    let (s2, d2) = try await raw("POST", "api/secrets/state", [:])
    if s2 == 503 || s2 == 502 || s2 == 504 { throw CoreNotRunning() }
    guard s2 == 200 else { throw Self.failure("POST", "api/secrets/state", s2, d2) }
    return (id, try JSONDecoder().decode(SignedDoc.self, from: d2))
  }
  struct CoreNotRunning: Error {}
  /// POST api/secrets/claim; the answer must be that secrets' signed "claimed"
  func claim(_ body: [String: Any], core: PublicKeys) async throws -> Int {
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/claim", body, as: SignedDoc.self), by: core.signingKey, as: KindDoc.self, what: "secrets' answer")
    guard d.kind == "claimed" else { throw TrustError.stale("claim") }
    return d.stores ?? 0
  }
  /// POST api/secrets/wipe; the answer must be that secrets' signed "wiping" (it then ends; a new, empty one follows)
  func wipe(_ body: [String: Any], core: PublicKeys) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/secrets/wipe", body, as: SignedDoc.self), by: core.signingKey, as: KindDoc.self, what: "secrets' answer")
    guard d.kind == "wiping", d.core == core.signingKey else { throw TrustError.stale("wipe") }
  }
  /// the locked store backups, as the router reads them from the bucket (the caller checks and opens them)
  func backups() async throws -> [CoreSetup.BackupObject] {
    struct B: Decodable { let objects: [CoreSetup.BackupObject] }
    return try await json("GET", "api/backups", as: B.self).objects
  }
  /// the same with the bucket's name, for the offline copy (Settings → Encrypted backup)
  func backupDump() async throws -> (bucket: String, objects: [CoreSetup.BackupObject]) {
    struct B: Decodable { let bucket: String?; let objects: [CoreSetup.BackupObject] }
    let b = try await json("GET", "api/backups", as: B.self)
    return (b.bucket ?? "", b.objects)
  }

  // ---- approvals (docs/API.md "Approvals"): the drafts are checked by Checks.review before anything is signed ----
  struct SessionDTO: Decodable { let id: String; let state: String; let createRequestId: String? }
  struct StateDTO: Decodable { let sessions: [SessionDTO]; let approvals: [ApprovalDTO] }
  func approvalsState() async throws -> StateDTO { try await json("GET", "api/state") }
  func approval(_ id: String) async throws -> ApprovalDTO? { try await approvalsState().approvals.first { $0.id == id } }
  /// one signature per draft, in order (one Face ID) → the session the approval was for
  func respond(_ id: String, signatures: [Data]) async throws -> String {
    struct R: Decodable { let session: String? }
    return try await json("POST", "api/approvals/\(id)/respond", ["signatures": signatures.map { $0.base64EncodedString() }], as: R.self).session ?? ""
  }
  func reject(_ id: String) async throws { try await call("POST", "api/approvals/\(id)/reject") }

  // ---- the kernel's documents the router carried (GET api/sessions/:id/chain, api/kernel/*) ----
  struct ChainDTO: Decodable { let session: String; var main: SignedDoc? = nil; var held: SignedDoc? = nil; var spawn: KNotarized? = nil; var origin: KNotarized? = nil }
  func chain(_ session: String) async throws -> ChainDTO { try await json("GET", "api/sessions/\(Self.escaped(session))/chain") }
  /// root's ⊤ on the sink, signed by the root key once at setup (PUT api/kernel/root-grant)
  func putRootGrant(sig: Data) async throws {
    try await call("PUT", "api/kernel/root-grant", ["payload": Kernel.rootGrantPayload, "sig": sig.base64EncodedString()])
  }

  // ---- add-ons and narrowing (docs/API.md "Requests", "Sessions") ----
  /// file a terminal (minutes, at most 10), a command or an added store for a session: → the approval's id
  func requestAddOn(_ intent: String, _ body: [String: Any]) async throws -> String {
    struct R: Decodable { let id: String }
    return try await json("POST", "api/requests/\(intent)", body, as: R.self).id
  }
  /// keep only `stores` (the main grant moved along the machine's identity edge) → the stores it holds now
  func narrow(_ session: String, keep stores: [String]) async throws -> [String] {
    try await call("POST", "api/sessions/\(Self.escaped(session))/narrow", ["stores": stores])["stores"].strings
  }

  // ---- the Inbox (docs/API.md "Requests") ----
  /// one Inbox entry (GET api/requests/:id); nil when it is gone
  func inboxItem(_ id: String) async throws -> InboxItem? {
    let (status, data) = try await raw("GET", "api/requests/\(id)")
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/requests/\(id)", status, data) }
    return InboxItem(j: JSON.parse(data))
  }
  func inboxDeny(_ id: String) async throws { try await call("DELETE", "api/requests/\(id)") }
  /// one batch with its items (GET api/requests/batches/:id); nil when it is gone
  func inboxBatch(_ id: String) async throws -> (batch: InboxBatch, items: [InboxItem])? {
    let (status, data) = try await raw("GET", "api/requests/batches/\(id)")
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/requests/batches/\(id)", status, data) }
    let j = JSON.parse(data)
    return (InboxBatch(j: j["batch"]), j["items"].array.map(InboxItem.init))
  }
  /// Deny the whole batch: its requests leave, its approvals are rejected
  func inboxDenyBatch(_ id: String) async throws { try await call("DELETE", "api/requests/batches/\(id)") }
  func inboxDone(_ id: String) async { _ = try? await raw("POST", "api/requests/\(id)/done") }
  /// an api-call request (router/apicalls.go): the router runs the call now as Deyao → its outcome
  func inboxApproveCall(_ id: String) async throws -> JSON { try await call("POST", "api/requests/\(id)/approve") }
}
