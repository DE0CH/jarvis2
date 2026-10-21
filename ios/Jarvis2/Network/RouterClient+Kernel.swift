// The kernel's routes (router/kernelline.go): its status, the root grant, and secrets' own API relayed as is
// (/api/kernel/secrets/…). Every document of secrets is checked here against the keys this iPhone pinned
// (KernelTrust), or, before a claim, against the box key.
import Foundation

extension RouterClient {
  struct KernelStatus: Decodable { let configured: Bool; let serves: Bool; let root: Bool }
  func kernelStatus() async throws -> KernelStatus { try await json("GET", "api/kernel") }

  /// secrets' identity, checked against the box key (keys/box.pub)
  func kernelIdentity(boxKey: String) async throws -> (keys: PublicKeys, state: KernelSetup.State) {
    try KernelSetup.check(try await json("GET", "api/kernel/secrets/identity", as: KernelSetup.Identity.self), boxKey: boxKey)
  }
  /// secrets' store key C = P + K for this phone, with `secrets` (a Recover's derived K), checked against `signedBy`
  func kernelStoreKey(signedBy: String, secrets: String) async throws -> String {
    struct SK: Decodable { let kind: String; let phone: String; let storeKey: String; let secrets: String? }
    let phone = try PhoneKeys.shared.publicKeys().agreementKey
    let d = try await json("POST", "api/kernel/secrets/store-key", ["phone": phone, "secrets": secrets], as: SignedDoc.self)
    let sk = try CoreCrypto.decode(d, by: signedBy, as: SK.self, what: "secrets' store key")
    guard sk.kind == "store-key", sk.phone == phone, sk.secrets == secrets else { throw TrustError.stale("store key") }
    return sk.storeKey
  }
  /// the claim (KernelSetup.claim's body); its answer is checked against the keys the kit derives
  func kernelClaim(_ body: [String: Any], derived: PublicKeys) async throws {
    struct C: Decodable { let kind: String }
    let d = try await json("POST", "api/kernel/secrets/claim", body, as: SignedDoc.self)
    guard (try CoreCrypto.decode(d, by: derived.signingKey, as: C.self, what: "secrets' claim answer")).kind == "claimed" else { throw TrustError.stale("claim") }
  }

  /// what the root key signs once: ⊤ on the sink (the router fills in the sink's keys, hashed from its name)
  func rootGrantDraft() async throws -> String {
    struct D: Decodable { let payload: String }
    let d: D = try await json("GET", "api/kernel/root-grant/draft")
    struct G: Decodable {
      struct P: Decodable { struct A: Decodable { let except: [String]? ; let only: [String]? }; let allowed: A; let conditions: [String] }
      let kind: String; let machine: String; let pair: P; let from: [String]
    }
    let g = try JSONDecoder().decode(G.self, from: Data(d.payload.utf8))
    guard g.kind == "grant", g.machine == "sink", g.pair.allowed.only == nil, g.pair.allowed.except == [], g.pair.conditions.isEmpty, g.from.isEmpty else {
      throw TrustError.mismatch("the root grant's draft isn't ⊤ on the sink")
    }
    return d.payload
  }
  func postRootGrant(_ payload: String, signature: Data) async throws {
    try await call("POST", "api/kernel/root-grant", ["grant": ["payload": payload, "sig": signature.base64EncodedString()]])
  }

  /// secrets' signed store list, checked against the pinned keys
  func kernelStores() async throws -> StoresDoc {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/kernel/secrets/stores", ["nonce": n], as: SignedDoc.self), by: try KernelTrust.key(),
                                  as: StoresDoc.self, what: "the kernel's store list")
    guard d.kind == "stores", d.nonce == n else { throw TrustError.stale("store list") }
    return d
  }
  /// an unlock of one store in the kernel's secrets (it stays open until locked: D2): begin, the phone's shares under
  /// the given Face ID, finish
  func kernelUnlock(_ store: String, reason: String, auth: PhoneAuth?) async throws {
    let begin = try await json("POST", "api/kernel/secrets/unlock/begin", ["store": store], as: SignedDoc.self)
    let ub = try CoreCrypto.decode(begin, by: try KernelTrust.key(), as: UnlockBegin.self, what: "the kernel's unlock")
    guard ub.kind == "unlock-begin", ub.store == store else { throw TrustError.stale("unlock of \(store)") }
    let es = ub.es
    let (_, xs) = try await offMain { try PhoneKeys.shared.signAndShares(nil, es: es, reason: reason, auth: auth) }
    var shares: [String: Any] = [:]
    for (k, x) in zip(ub.keys, xs) { shares[k.key] = try CoreCrypto.sealShare(x, to: ub.t) }
    struct U: Decodable { let kind: String; let store: String }
    let d = try await json("POST", "api/kernel/secrets/unlock/finish", ["pending": ub.pending, "shares": shares], as: SignedDoc.self)
    let u = try CoreCrypto.decode(d, by: try KernelTrust.key(), as: U.self, what: "the kernel's unlock answer")
    guard u.kind == "unlocked", u.store == store else { throw TrustError.stale("unlock of \(store)") }
  }
  /// an approval answered with the phone's signatures, one per line (an add-store on a kernel line signs two certs)
  func respond(_ id: String, signatures: [Data]) async throws -> RespondDTO {
    try await json("POST", "api/approvals/\(id)/respond", ["signature": signatures.map { $0.base64EncodedString() }.joined(separator: "\n")])
  }
}
