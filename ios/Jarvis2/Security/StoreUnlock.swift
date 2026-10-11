// Opening locked stores: each unlock is the core's signed begin naming the store plus this phone's share x(p·E) sealed
// to the core's one-off key, all under ONE Face ID together with an optional signature (New session's Start, an
// approval, the unlock review).
import Foundation

@MainActor
enum StoreUnlock {
  @discardableResult
  static func signAndUnlock(payload: String?, stores: [String], reason: String, for forNonce: String?) async throws -> Data? {
    var begins: [UnlockBegin] = []
    for n in stores { begins.append(try await RouterClient.shared.unlockBegin(n, for: forNonce)) }
    let es = begins.map(\.e)
    let out = try await offMain { try PhoneKeys.shared.signAndShares(payload, es: es, reason: reason) }
    for (b, x) in zip(begins, out.shares) {
      try await RouterClient.shared.unlockFinish(b, share: try CoreCrypto.sealShare(x, to: b.t))
    }
    return out.signature
  }
}

/// a key use waits for Face ID: keep it off the main thread
func offMain<T: Sendable>(_ fn: @escaping @Sendable () throws -> T) async throws -> T {
  try await Task.detached(priority: .userInitiated) { try fn() }.value
}

/// an error in words
func errText(_ e: Error) -> String { (e as? LocalizedError)?.errorDescription ?? e.localizedDescription }
