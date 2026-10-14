// Which stores each harness brings, pinned in the app from git, and the kernel's part keys as the box key vouches for them.
import Foundation

/// Which stores each harness brings, as this app was built with them (policy/stores.json, bundled from git: the same
/// push path as the app's code). The router's api/policy is only a hint for hiding stores in pickers; what may be
/// signed beyond the stores picked on New session is decided here (audit finding 2). A CI build also takes the
/// router's list, since its throwaway router runs a test policy.
enum PinnedPolicy {
  static let harnessStores: [String: [String]] = {
    guard let u = Bundle.main.url(forResource: "stores", withExtension: "json"), let d = try? Data(contentsOf: u),
          let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let h = j["harnesses"] as? [String: Any] else { return [:] }
    return h.compactMapValues { ($0 as? [String: Any])?["stores"] as? [String] }
  }()
  static func stores(_ harness: String, router: [String: [String]]) -> [String] {
    var s = harnessStores[harness] ?? []
    #if JARVIS_CI
    s += router[harness] ?? []
    #endif
    return Array(Set(s)).sorted()
  }
}

/// The kernel's parts (log notary, notarizer, mover, merger, spawner, secrets…) as the box key (keys/box.pub, from git)
/// vouches for them: GET api/kernel/identities, each identity checked against the box key here, never taken from the
/// router's word. Read afresh for each review page (a part may have restarted with new keys).
@MainActor
enum KernelTrust {
  static func roster() async throws -> KRoster {
    let ids = try await RouterClient.shared.json("GET", "api/kernel/identities", as: [String: Kernel.Identity?].self)
    return Kernel.roster(ids, boxKey: try await KeySource.key("box.pub"))
  }
}
