// Opening locked stores: each unlock is secrets' signed begin naming the store's keys plus this phone's share x(p·E) of
// every key, each sealed to secrets' one-off key, all under ONE Face ID together with the signatures of an approval's
// drafts (New session's Start, an approval, the unlock review). An unlock is per store and never ends by itself: it
// serves every grant that names the store until it is locked (Stores → Lock).
import Foundation

@MainActor
enum StoreUnlock {
  /// `shown`: the session-written keys the page showed for these stores (SessionWrites). A key secrets' signed begin
  /// names as written by a session's machine that isn't among them is refused before Face ID: a value a session wrote is
  /// never released unseen (Deyao, 2026-10-13). The Face ID prompt names the session-written keys too.
  /// Returns one signature per payload, in order.
  @discardableResult
  static func signAndUnlock(payloads: [String], stores: [String], reason: String, shown: [SessionWrite],
                            auth: PhoneAuth? = nil) async throws -> [Data] {
    var begins: [UnlockBegin] = []
    for n in stores { begins.append(try await RouterClient.shared.unlockBegin(n)) }
    if let w = Checks.unseen(begins, shown: shown).first {
      throw TrustError.mismatch("key \(w.key) of \(w.store) was written by a session this page didn't show; reload it")
    }
    let written = Checks.sessionWrites(begins)
    let why = written.isEmpty ? reason : reason + " (written by a session: " + written.map { "\($0.store) \($0.key)" }.joined(separator: ", ") + ")"
    let es = begins.flatMap(\.es)
    let out = try await offMain { try PhoneKeys.shared.signAndShares(payloads, es: es, reason: why, auth: auth) }
    guard out.shares.count == es.count, out.signatures.count == payloads.count else { throw TrustError.stale("signatures and shares") }
    var i = 0
    for b in begins {
      let n = b.es.count
      try await RouterClient.shared.unlockFinish(b, shares: Array(out.shares[i..<i + n]))
      i += n
    }
    return out.signatures
  }
}

/// a key use waits for Face ID: keep it off the main thread
func offMain<T: Sendable>(_ fn: @escaping @Sendable () throws -> T) async throws -> T {
  try await Task.detached(priority: .userInitiated) { try fn() }.value
}

/// an error in words
func errText(_ e: Error) -> String { (e as? LocalizedError)?.errorDescription ?? e.localizedDescription }
