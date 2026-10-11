// Where the shell gets what it trusts besides the router: the public keys in git (keys/box.pub vouches for a
// core's identity, keys/setup.pub for the backups), fetched from GitHub — never from the router. A CI build
// (compiled with JARVIS_CI, simulator walkthrough only) may point at a local stand-in through its Info.plist.
// Any build may name another git ref of the same repo (JarvisKeysRef, a branch name only): the phone replica's
// Release build reads its throwaway box's keys from a rehearsal branch (infra/phone-replica.sh). The TestFlight
// archive must leave it empty (app.yml checks).
import Foundation

enum KeySource {
  static let githubKeys = "https://raw.githubusercontent.com/DE0CH/jarvis2/main/keys/"

  private static func plist(_ k: String) -> String? {
    #if JARVIS_CI
    if let s = Bundle.main.object(forInfoDictionaryKey: k) as? String, !s.isEmpty { return s }
    #endif
    return nil
  }
  /// the git ref the keys come from: main, or the Info.plist's JarvisKeysRef (letters, digits, - _ . / only)
  static var keysRef: String {
    let r = (Bundle.main.object(forInfoDictionaryKey: "JarvisKeysRef") as? String ?? "").trimmingCharacters(in: .whitespaces)
    let ok = !r.isEmpty && !r.contains("..") && r.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_./".contains($0)) }
    return ok ? r : "main"
  }
  static var keysBase: String {
    let b = plist("JarvisCIKeysBase") ?? githubKeys.replacingOccurrences(of: "/main/keys/", with: "/\(keysRef)/keys/")
    return b.hasSuffix("/") ? b : b + "/"
  }

  /// keys/<name> from git (base64 X9.63), no cache
  static func key(_ name: String) async throws -> String {
    var r = URLRequest(url: URL(string: keysBase + name)!)
    r.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    r.timeoutInterval = 30
    let (d, resp) = try await URLSession.shared.data(for: r)
    guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw RouterError(message: "Couldn't fetch keys/\(name) from \(keysBase).") }
    return String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
