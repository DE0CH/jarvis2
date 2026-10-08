// The shell's own client of the router (docs/API.md) — an ordinary network path: integrity comes from the
// core's signatures (checked here against the paired core key) and the phone's (made here). The shell also
// owns sign-in: ASWebAuthenticationSession on /api/auth/start → jarvis2://auth#token=<Access JWT>, kept in
// the shell's Keychain, sent as `cf-access-token`, and handed to the React Native UI over XPC.
import AuthenticationServices
import Foundation
import UIKit

struct RouterError: LocalizedError { let message: String; var errorDescription: String? { message } }

@MainActor
final class RouterClient: NSObject, ASWebAuthenticationPresentationContextProviding {
  static let shared = RouterClient()
  let base: URL = {
    let s = (Bundle.main.object(forInfoDictionaryKey: "JarvisBase") as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "https://jarvis2.deyaochen.com/"
    return URL(string: s.hasSuffix("/") ? s : s + "/")!
  }()
  var token: String { Keychain.string("access-token") ?? "" }

  // ---- sign-in ----
  private var signing: Task<String, Never>?
  private var webSession: ASWebAuthenticationSession?
  /// runs the sign-in sheet once (callers meanwhile share it); "" when cancelled or failed
  func signIn() async -> String {
    if let signing { return await signing.value }
    let t = Task { @MainActor () -> String in
      defer { signing = nil }
      var c = URLComponents(url: base.appendingPathComponent("api/auth/start"), resolvingAgainstBaseURL: false)!
      c.queryItems = [URLQueryItem(name: "redirect", value: "jarvis2://auth")]
      let url: URL? = await withCheckedContinuation { k in
        let s = ASWebAuthenticationSession(url: c.url!, callback: .customScheme("jarvis2")) { u, _ in k.resume(returning: u) }
        s.presentationContextProvider = self
        webSession = s
        if !s.start() { k.resume(returning: nil) }
      }
      webSession = nil
      guard let frag = url?.fragment, let tok = URLComponents(string: "x:?" + frag)?.queryItems?.first(where: { $0.name == "token" })?.value, !tok.isEmpty else { return "" }
      Keychain.setString("access-token", tok)
      return tok
    }
    signing = t
    return await t.value
  }
  nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    MainActor.assumeIsolated {
      UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.keyWindow }.first ?? ASPresentationAnchor()
    }
  }

  // ---- requests ----
  /// Access turned the request away: it ended on the Access login, or a 401/403 that isn't JSON, or the
  /// router's own "Access login required"
  private func refused(_ resp: HTTPURLResponse, _ data: Data) -> Bool {
    if (resp.url?.host ?? "").hasSuffix("cloudflareaccess.com") { return true }
    guard resp.statusCode == 401 || resp.statusCode == 403 else { return false }
    let ct = resp.value(forHTTPHeaderField: "Content-Type") ?? ""
    return !ct.contains("json") || String(decoding: data, as: UTF8.self).contains("Access login required")
  }
  func raw(_ method: String, _ path: String, _ body: [String: Any]? = nil, timeout: TimeInterval = 60) async throws -> (Int, Data) {
    for attempt in 0..<2 {
      var r = URLRequest(url: base.appendingPathComponent(path))
      r.httpMethod = method
      r.timeoutInterval = timeout
      if let body { r.httpBody = try JSONSerialization.data(withJSONObject: body); r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
      if !token.isEmpty { r.setValue(token, forHTTPHeaderField: "cf-access-token") }
      r.httpShouldHandleCookies = false
      let (data, resp) = try await URLSession.shared.data(for: r)
      guard let h = resp as? HTTPURLResponse else { throw RouterError(message: "no HTTP answer") }
      if refused(h, data) {
        if attempt == 0, !(await signIn()).isEmpty { continue }
        throw RouterError(message: "Signed out of Cloudflare Access.")
      }
      return (h.statusCode, data)
    }
    throw RouterError(message: "Signed out of Cloudflare Access.")
  }
  /// JSON answer; errors (the router's {error} or the core's signed error doc) as their message
  func json<T: Decodable>(_ method: String, _ path: String, _ body: [String: Any]? = nil, as: T.Type = T.self) async throws -> T {
    let (status, data) = try await raw(method, path, body)
    guard status == 200 else { throw RouterError(message: Self.reason(data) ?? "HTTP \(status) from \(path)") }
    return try JSONDecoder().decode(T.self, from: data)
  }
  static func reason(_ data: Data) -> String? {
    guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    if let p = j["payload"] as? String, let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let e = pj["error"] as? String { return "core: " + e }
    return j["error"] as? String
  }

  // ---- the core, relayed: every answer checked against the paired core key ----
  func stores() async throws -> [StoreView] {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/core/stores", ["nonce": n], as: SignedDoc.self), by: try CoreTrust.key(), as: StoresDoc.self, what: "the store list")
    guard d.kind == "stores", d.nonce == n else { throw TrustError.stale("store list") }
    return d.stores
  }
  func unlocked() async throws -> [UnlockRow] {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/core/unlocked", ["nonce": n], as: SignedDoc.self), by: try CoreTrust.key(), as: UnlockedDoc.self, what: "the unlocked list")
    guard d.kind == "unlocked-list", d.nonce == n else { throw TrustError.stale("unlocked list") }
    return d.unlocked
  }
  func unlockBegin(_ store: String) async throws -> UnlockBegin {
    let b = try CoreCrypto.decode(try await json("POST", "api/core/unlock/begin", ["store": store], as: SignedDoc.self), by: try CoreTrust.key(), as: UnlockBegin.self, what: "the unlock")
    guard b.kind == "unlock-begin", b.store == store else { throw TrustError.stale("unlock of \(b.store)") }
    return b
  }
  func unlockFinish(_ b: UnlockBegin, share: [String: String]) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/unlock/finish", ["pending": b.pending, "share": share], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the unlocked answer")
    guard d.kind == "unlocked", d.store == b.store else { throw TrustError.stale("unlocked \(d.store ?? "?")") }
  }
  func lock(_ id: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/lock", ["id": id], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the locked answer")
    guard d.kind == "locked", d.id == id else { throw TrustError.stale("lock") }
  }
  func markSensitive(_ name: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/mark-sensitive", ["name": name], as: SignedDoc.self), by: try CoreTrust.key(), as: KindDoc.self, what: "the mark")
    guard d.kind == "marked-sensitive", d.name == name else { throw TrustError.stale("mark") }
  }
  func coreKeyNow() async -> String? { (try? await json("GET", "api/core/key", as: [String: String].self))?["signingKey"] }

  // ---- sessions + approvals ----
  struct ApprovalDTO: Decodable { let id: String; let kind: String; let session: String?; let label: String?; let challenge: SignedDoc; let burnCert: SignedDoc?; let options: [String: String]? }
  struct SessionDTO: Decodable { let id: String; let state: String; let createRequestId: String?; let label: String?; let name: String? }
  struct StateDTO: Decodable { let sessions: [SessionDTO]; let approvals: [ApprovalDTO] }
  struct RespondDTO: Decodable { let cert: SignedDoc; let session: String }
  func state() async throws -> StateDTO { try await json("GET", "api/state") }
  func approval(_ id: String) async throws -> ApprovalDTO? { try await state().approvals.first { $0.id == id } }
  func createSession(_ body: [String: Any]) async throws { let _: [String: String?] = try await json("POST", "api/sessions", body) }
  func respond(_ id: String, signature: Data) async throws -> RespondDTO { try await json("POST", "api/approvals/\(id)/respond", ["signature": signature.base64EncodedString()]) }
  func reject(_ id: String) async throws { let _: [String: Bool] = try await json("POST", "api/approvals/\(id)/reject") }
}
