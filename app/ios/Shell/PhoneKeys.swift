// The phone's two keys and the shell's Keychain items. Only the shell (this app's own Keychain access
// group, which the extension's process doesn't share) reads them.
//   - signing key: Secure Enclave P-256, Face ID on every use (.biometryAny) — signs challenges;
//   - agreement key: Secure Enclave P-256, Face ID on every use — computes this phone's share p·E of an unlock.
// The simulator builds use software keys (its Face ID can't be driven from CI); the pages say so.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum Keychain {
  private static let service = "dev.de0ch.jarvis2.shell"
  static func get(_ account: String) -> Data? {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true]
    var out: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
  }
  static func set(_ account: String, _ data: Data?) {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    SecItemDelete(q as CFDictionary)
    guard let data else { return }
    var add = q
    add[kSecValueData as String] = data
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    SecItemAdd(add as CFDictionary, nil)
  }
  static func string(_ account: String) -> String? { get(account).flatMap { String(data: $0, encoding: .utf8) } }
  static func setString(_ account: String, _ s: String?) { set(account, s.map { Data($0.utf8) }) }
}

enum KeyError: LocalizedError {
  case noAccessControl
  var errorDescription: String? { "Could not create the Secure Enclave key's access control." }
}

final class PhoneKeys {
  static let shared = PhoneKeys()
  var usesEnclave: Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    return SecureEnclave.isAvailable
    #endif
  }
  var how: String { usesEnclave ? "Face ID" : "a software key (simulator)" }
  private var account: String { usesEnclave ? "se" : "sw" }

  private func accessControl() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryAny], &err) else { throw KeyError.noAccessControl }
    return ac
  }

  // ---- the public halves (no Face ID needed); made on first use ----
  func publicKeys() throws -> PublicKeys {
    PublicKeys(signingKey: try signingPublic().base64EncodedString(), agreementKey: try agreementPublic().base64EncodedString())
  }
  private func signingPublic() throws -> Data {
    if usesEnclave {
      if let b = Keychain.get("signing-" + account) { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b).publicKey.x963Representation }
      let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl())
      Keychain.set("signing-" + account, k.dataRepresentation)
      return k.publicKey.x963Representation
    }
    return softSigning().publicKey.x963Representation
  }
  private func agreementPublic() throws -> Data {
    if usesEnclave {
      if let b = Keychain.get("agreement-" + account) { return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: b).publicKey.x963Representation }
      let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl())
      Keychain.set("agreement-" + account, k.dataRepresentation)
      return k.publicKey.x963Representation
    }
    return softAgreement().publicKey.x963Representation
  }
  private func softSigning() -> P256.Signing.PrivateKey {
    if let b = Keychain.get("signing-sw"), let k = try? P256.Signing.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.Signing.PrivateKey(); Keychain.set("signing-sw", k.rawRepresentation); return k
  }
  private func softAgreement() -> P256.KeyAgreement.PrivateKey {
    if let b = Keychain.get("agreement-sw"), let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.KeyAgreement.PrivateKey(); Keychain.set("agreement-sw", k.rawRepresentation); return k
  }

  // ---- uses (one Face ID each on a real iPhone) ----
  /// DER signature over exactly `payload`'s bytes
  func sign(_ payload: String, reason: String) throws -> Data {
    _ = try signingPublic()
    if usesEnclave {
      let ctx = LAContext(); ctx.localizedReason = reason
      let k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
      return try k.signature(for: Data(payload.utf8)).derRepresentation
    }
    return try softSigning().signature(for: Data(payload.utf8)).derRepresentation
  }
  /// this phone's share of an unlock: x(p·E), 32 bytes
  func share(with e: String, reason: String) throws -> Data {
    _ = try agreementPublic()
    guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
    let pub = try P256.KeyAgreement.PublicKey(x963Representation: eb)
    let secret: SharedSecret
    if usesEnclave {
      let ctx = LAContext(); ctx.localizedReason = reason
      let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
      secret = try k.sharedSecretFromKeyAgreement(with: pub)
    } else {
      secret = try softAgreement().sharedSecretFromKeyAgreement(with: pub)
    }
    return secret.withUnsafeBytes { Data($0) }
  }
}

/// The core this phone recovered: its keys, pinned in the shell's Keychain when the core accepted the
/// master-signed recovery statement naming them. Every core document is verified against them — they are
/// never learned from the network.
enum CoreTrust {
  static var pinned: PublicKeys? { Keychain.get("core-keys").flatMap { try? JSONDecoder().decode(PublicKeys.self, from: $0) } }
  static func pin(_ k: PublicKeys) { Keychain.set("core-keys", try? JSONEncoder().encode(k)) }
  static func key() throws -> String { guard let p = pinned else { throw TrustError.notRecovered }; return p.signingKey }
}
