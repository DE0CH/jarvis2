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

/// The master private key made on this iPhone (the master key page), held until Deyao has saved the recovery
/// kit made from it. Only its public half is ever shown; the private half goes from here into the kit string
/// and is then deleted. Keychain items of the shell (the extension's process can't read them), this device
/// only (never synced, never in a backup): the private half behind Face ID on every read on a real iPhone, the
/// public half readable without it so pages can say whether it is the key in keys/master.pub.
enum HeldMaster {
  private static let priv = "held-master", pub = "held-master-public"
  private static let service = "dev.de0ch.jarvis2.shell"

  /// the held key's public half (base64 X9.63), if this iPhone holds one
  static var publicKey: String? { Keychain.string(pub) }

  /// keep `k`, replacing any held key
  static func hold(_ k: MasterKey) throws {
    delete()
    var add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                              kSecAttrAccount as String: priv, kSecValueData as String: k.signing.rawRepresentation,
                              kSecAttrSynchronizable as String: false]
    if PhoneKeys.shared.usesEnclave {
      var err: Unmanaged<CFError>?
      guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.biometryAny], &err) else { throw KeyError.noAccessControl }
      add[kSecAttrAccessControl as String] = ac
    } else {
      add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
    let st = SecItemAdd(add as CFDictionary, nil)
    guard st == errSecSuccess else { throw TrustError.badKit("Couldn't keep the master key in this iPhone's Keychain (\(st)).") }
    Keychain.setString(pub, k.publicKey)
  }

  /// the held key itself (one Face ID on a real iPhone); nil when none is held
  static func load(reason: String) throws -> MasterKey? {
    var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                            kSecAttrAccount as String: priv, kSecReturnData as String: true]
    if PhoneKeys.shared.usesEnclave { let ctx = LAContext(); ctx.localizedReason = reason; q[kSecUseAuthenticationContext as String] = ctx }
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    if st == errSecItemNotFound { return nil }
    guard st == errSecSuccess, let d = out as? Data, let k = try? P256.Signing.PrivateKey(rawRepresentation: d) else {
      throw TrustError.badKit(st == errSecUserCanceled || st == errSecAuthFailed ? "Face ID didn't go through; try again." : "Couldn't read the master key from this iPhone's Keychain (\(st)).")
    }
    return MasterKey(signing: k)
  }

  /// forget it: once the recovery kit holding it is saved, the kit is the only copy
  static func delete() {
    SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: priv] as CFDictionary)
    Keychain.set(pub, nil)
  }

  #if JARVIS_CI
  /// CI only (the simulator walkthrough): hold the public TEST master key (e2e/testdata) as if this simulator had
  /// made it, so the walkthrough can make a kit for the backups sealed to it. Release builds have no such path.
  static func ciSeed() {
    guard publicKey == nil, let b64 = ProcessInfo.processInfo.environment["JARVIS2_CI_HELD_MASTER"], let k = try? MasterKey(pkcs8: b64) else { return }
    try? hold(k)
  }
  #endif
}
