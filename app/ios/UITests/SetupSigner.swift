// The setup session's side of the core's /setup/* calls (docs/API.md "Setup"), for the tests only: CI makes
// a fresh setup key pair per run, gives the core the public half (SETUP_KEY) and the tests the private half
// (base64 DER, PKCS#8 or SEC1). Shared by the UI test and the interop test (symlinked into ios/interop).
//   - each call is signed: X-Setup-Time (unix s), X-Setup-Sig = base64 DER ECDSA-P256-SHA256 over
//     "<METHOD> <path> <time> <sha256hex body>"; the core takes each signature once, within ±2 min;
//   - a store's values are sealed to the core's agreement key: ephemeral e, x(e·K) →
//     HKDF-SHA256(salt empty, info "jarvis2/setup") → AES-256-GCM combined (nonce‖ct‖tag).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct SetupSigner {
  let key: P256.Signing.PrivateKey
  init?(base64DER: String) {
    guard let d = Data(base64Encoded: base64DER.trimmingCharacters(in: .whitespacesAndNewlines)),
          let k = try? P256.Signing.PrivateKey(derRepresentation: d) else { return nil }
    key = k
  }

  /// the two headers for one call; `time` is overridable to test the core's clock window
  func headers(_ method: String, _ path: String, _ body: Data, time: Int = Int(Date().timeIntervalSince1970)) -> [String: String] {
    let h = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    let msg = "\(method) \(path) \(time) \(h)"
    let sig = try! key.signature(for: Data(msg.utf8)).derRepresentation.base64EncodedString()
    return ["X-Setup-Time": String(time), "X-Setup-Sig": sig]
  }

  /// a store's values sealed to the core's agreement key (base64 X9.63) → {e, data}
  static func seal(_ values: [String: String], to agreementKey: String) -> [String: String] {
    let k = try! P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: agreementKey)!)
    let r = P256.KeyAgreement.PrivateKey()
    let key = try! r.sharedSecretFromKeyAgreement(with: k)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("jarvis2/setup".utf8), outputByteCount: 32)
    let plain = try! JSONSerialization.data(withJSONObject: values)
    let box = try! AES.GCM.seal(plain, using: key)
    return ["e": r.publicKey.x963Representation.base64EncodedString(), "data": box.combined!.base64EncodedString()]
  }
}
