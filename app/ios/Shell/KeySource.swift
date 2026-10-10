// Where the shell gets what it trusts besides the router: the public keys in git (keys/box.pub vouches for a
// core's identity, keys/setup.pub for the backups), fetched from GitHub — never from the router. A CI build
// (compiled with JARVIS_CI, simulator walkthrough only) may point at a local stand-in through its Info.plist;
// release builds have no such code path.
import Foundation

enum KeySource {
  static let githubKeys = "https://raw.githubusercontent.com/DE0CH/jarvis2/main/keys/"

  private static func plist(_ k: String) -> String? {
    #if JARVIS_CI
    if let s = Bundle.main.object(forInfoDictionaryKey: k) as? String, !s.isEmpty { return s }
    #endif
    return nil
  }
  static var keysBase: String { let b = plist("JarvisCIKeysBase") ?? githubKeys; return b.hasSuffix("/") ? b : b + "/" }

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
