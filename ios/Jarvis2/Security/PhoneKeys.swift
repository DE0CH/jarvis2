// The phone's two keys and the shell's Keychain items. Only the shell (this app's own Keychain access
// group, which the extension's process doesn't share) reads them.
//   - signing key: Secure Enclave P-256, Face ID on every use (.biometryAny) — signs challenges;
//   - agreement key: Secure Enclave P-256, Face ID on every use — computes this phone's share p·E of an unlock.
// The simulator has no Secure Enclave, so its builds use software keys (the pages say so); when the simulator has
// Face ID enrolled (the phone replica enrols it and drives matches and failures with simctl), every use asks for
// Face ID first, as the iPhone does.
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

  /// the simulator's stand-in for the Secure Enclave's Face ID check: with Face ID enrolled, a use needs a match
  private func simulatorFaceID(_ reason: String) throws {
    #if targetEnvironment(simulator)
    let ctx = LAContext()
    var e: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e) else { return } // not enrolled
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var err: Error?
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
      if !ok { err = error ?? LAError(.authenticationFailed) }
      sem.signal()
    }
    sem.wait()
    if let err { throw err }
    #endif
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
    try simulatorFaceID(reason)
    return try softSigning().signature(for: Data(payload.utf8)).derRepresentation
  }
  /// a signature over `payload` and this phone's share x(p·E), under ONE Face ID: both Enclave keys use the same
  /// LAContext, which the first use authenticates (a deploy key: the phone approves the request and opens the
  /// token store for it)
  func signAndShare(_ payload: String, e: String, reason: String) throws -> (signature: Data, share: Data) {
    _ = try signingPublic(); _ = try agreementPublic()
    guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
    let pub = try P256.KeyAgreement.PublicKey(x963Representation: eb)
    if usesEnclave {
      let ctx = LAContext(); ctx.localizedReason = reason
      let s = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
      let sig = try s.signature(for: Data(payload.utf8)).derRepresentation
      let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
      let secret = try a.sharedSecretFromKeyAgreement(with: pub)
      return (sig, secret.withUnsafeBytes { Data($0) })
    }
    let sig = try softSigning().signature(for: Data(payload.utf8)).derRepresentation
    let secret = try softAgreement().sharedSecretFromKeyAgreement(with: pub)
    return (sig, secret.withUnsafeBytes { Data($0) })
  }
  /// an optional signature over `payload` and this phone's share x(p·E) for each store key in `es`, under ONE Face
  /// ID (one LAContext for every Enclave use): New session's Start signs the approval and opens the session's locked
  /// stores at once; the unlock review page opens several stores at once
  func signAndShares(_ payload: String?, es: [String], reason: String) throws -> (signature: Data?, shares: [Data]) {
    _ = try signingPublic(); _ = try agreementPublic()
    let pubs = try es.map { e -> P256.KeyAgreement.PublicKey in
      guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
      return try P256.KeyAgreement.PublicKey(x963Representation: eb)
    }
    if usesEnclave {
      let ctx = LAContext(); ctx.localizedReason = reason
      var sig: Data?
      if let payload {
        let k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
        sig = try k.signature(for: Data(payload.utf8)).derRepresentation
      }
      var shares: [Data] = []
      if !pubs.isEmpty {
        let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
        for pub in pubs { shares.append(try a.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }) }
      }
      return (sig, shares)
    }
    let sig = try payload.map { try softSigning().signature(for: Data($0.utf8)).derRepresentation }
    let shares = try pubs.map { try softAgreement().sharedSecretFromKeyAgreement(with: $0).withUnsafeBytes { Data($0) } }
    return (sig, shares)
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
      try simulatorFaceID(reason)
      secret = try softAgreement().sharedSecretFromKeyAgreement(with: pub)
    }
    return secret.withUnsafeBytes { Data($0) }
  }
}

/// The core this iPhone set up (Reset or Recover): its keys and the master public key it was set up with, pinned
/// in the shell's Keychain when the core accepted the master-signed claim naming them. Every core document is
/// verified against the pinned core key — never learned from the network — and a core set up with another master
/// key is refused (the setup page says so).
enum CoreTrust {
  static var pinned: PublicKeys? { Keychain.get("core-keys").flatMap { try? JSONDecoder().decode(PublicKeys.self, from: $0) } }
  /// this iPhone's master public key (the private half is only in Deyao's recovery kit)
  static var master: String? { Keychain.string("master-public") }
  static func pin(_ k: PublicKeys, master: String) {
    Keychain.set("core-keys", try? JSONEncoder().encode(k))
    Keychain.setString("master-public", master)
  }
  static func key() throws -> String { guard let p = pinned else { throw TrustError.notSetUp }; return p.signingKey }
}
