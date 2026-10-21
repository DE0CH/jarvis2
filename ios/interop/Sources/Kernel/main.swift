// The app's kernel code (Security/KernelSetup.swift, with CoreCrypto and CoreSetup) against the REAL kernel secrets
// binary (kernel/cmd/secrets with a throwaway box key) and the certs as the Go side makes them (kernel/cmd/vectors):
// secrets' identity (box-vouched, its signed state), the claim with the kit-derived keys and the root key, the keys
// derived the same in Swift and Go, the split-key unlock, the keys statement; then the cert checks the approval pages
// make before Face ID, and their refusals.
// Configuration (env): KERNEL_SECRETS (its URL), KERNEL_BOX_PUB (the box public key, base64), KERNEL_VECTORS (a file
// with kernel/cmd/vectors' output).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

let env = ProcessInfo.processInfo.environment
func need(_ k: String) -> String { guard let v = env[k], !v.isEmpty else { print("missing \(k)"); exit(2) }; return v }
let secrets = need("KERNEL_SECRETS")
let boxKey = try! String(contentsOfFile: need("KERNEL_BOX_PUB"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
let vectors = try! JSONDecoder().decode([String: String].self, from: try! Data(contentsOf: URL(fileURLWithPath: need("KERNEL_VECTORS"))))
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }
func call(_ path: String, _ body: Any? = nil, method: String = "POST") -> (Int, Data) {
  var r = URLRequest(url: URL(string: secrets + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = method; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }

// ---- identity ----
func identity() -> KernelSetup.Identity { try! JSONDecoder().decode(KernelSetup.Identity.self, from: call("/identity").1) }
let id0 = identity()
let c0 = try? KernelSetup.check(id0, boxKey: boxKey)
check(c0 != nil && c0?.state.master == "", "secrets' keys are the box key's and it is empty")
check(throwsErr { _ = try KernelSetup.check(KernelSetup.Identity(signingKey: id0.agreementKey, agreementKey: id0.signingKey, boxSig: id0.boxSig, state: id0.state), boxKey: boxKey) }, "…not for other keys")
let other = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
check(throwsErr { _ = try KernelSetup.check(id0, boxKey: other) }, "…not with another box key")

// ---- the claim: a Recover with one store, the kit's derived keys, the root key ----
let master = MasterKey.generate()
let phoneSig = P256.Signing.PrivateKey(), phoneAgree = P256.KeyAgreement.PrivateKey(), root = P256.Signing.PrivateKey()
let phone = PublicKeys(signingKey: phoneSig.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgree.publicKey.x963Representation.base64EncodedString())
let rootPub = root.publicKey.x963Representation.base64EncodedString()
let seed = KernelContinuity.seed(master)
let derived = try! KernelContinuity.keys(seed: seed)
let skDoc = doc(call("/store-key", ["phone": phone.agreementKey, "secrets": derived.agreementKey]).1)
struct SK: Decodable { let storeKey: String }
let sk = try! CoreCrypto.decode(skDoc, by: c0!.keys.signingKey, as: SK.self, what: "store key")
let stores = [RecoveredStore(name: "default", values: ["A": "1", "B": "2"], sensitive: false)]
let bundle = try! KernelSetup.bundle(stores, storeKey: sk.storeKey, seed: seed)
let k0 = c0!.keys
// refused: signed by another key, for another secrets, a phone key as the root key
var bad = try! KernelSetup.claim(secrets: k0, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)
bad["masterSig"] = try! MasterKey.generate().sign(bad["statement"] as! String)
check(call("/claim", bad).0 == 403, "a claim not signed by its master key is refused")
check(call("/claim", try! KernelSetup.claim(secrets: k0, phone: phone, root: phone.signingKey, master: master, bundle: bundle, identity: derived)).0 == 400, "…the phone's key as the root key too")
check(call("/claim", try! KernelSetup.claim(secrets: PublicKeys(signingKey: derived.signingKey, agreementKey: k0.agreementKey), phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)).0 == 403, "…and a claim for another secrets")
let (code, _) = call("/claim", try! KernelSetup.claim(secrets: k0, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived))
check(code == 200, "the claim goes through")
let c1 = try? KernelSetup.check(identity(), boxKey: boxKey)
check(c1?.keys == derived, "secrets now answers with the keys the kit derives (Swift and Go derive the same)")
check(c1.map { MasterKey.same($0.state.master, master.publicKey) && $0.state.phone == phone && $0.state.root == rootPub } ?? false, "its state names the master, the phone and the root key")
check(call("/claim", try! KernelSetup.claim(secrets: derived, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)).0 == 409, "a second claim is refused")

// ---- the keys statement and the split-key unlock ----
struct KS: Decodable { let kind: String; let phone: String; let root: String }
let ks = try? CoreCrypto.decode(doc(call("/keys", [String: String]()).1), by: derived.signingKey, as: KS.self, what: "keys")
check(ks?.phone == phone.signingKey && ks?.root == rootPub, "the keys statement names the phone's and the root key")
let begin = doc(call("/unlock/begin", ["store": "default"]).1)
struct UB: Decodable { let pending: String; let t: String; let keys: [K] ; struct K: Decodable { let key: String; let e: String } }
let ub = try! CoreCrypto.decode(begin, by: derived.signingKey, as: UB.self, what: "unlock begin")
var shares: [String: [String: String]] = [:]
for k in ub.keys {
  let pub = try! P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: k.e)!)
  let x = try! phoneAgree.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
  shares[k.key] = try! CoreCrypto.sealShare(x, to: ub.t)
}
check(call("/unlock/finish", ["pending": ub.pending, "shares": shares]).0 == 200, "the phone's shares unlock a store wrapped by the app")

// ---- the certs the phone signs ----
let s = try? KernelChecks.source(payload: vectors["source"]!, session: "s1")
check(s?.stores == ["default", "tunnel"] && s?.harness == "claude" && s?.permissionMode == "auto" && s?.config["label"]?.string == "x" && s?.snapshot == nil,
      "a new source as Go makes it reads as its stores, harness, mode and settings")
check((try? KernelChecks.source(payload: vectors["restore"]!, session: "s1"))?.snapshot?.count == 64, "a restore's source names the snapshot hash")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["source"]!, session: "s2") }, "…not for another session")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["shell"]!, session: "s1") }, "…not a source that allows a shell")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["otherSession"]!, session: "s1") }, "…not one whose conditions name another session")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["otherImage"]!, session: "s1") }, "…not another repo's image")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["addSecond"]!, session: "s1") }, "…not a cert onto a machine")
let a = try? KernelChecks.add(first: vectors["addFirst"]!, second: vectors["addSecond"]!, session: "s1", store: "extra")
check(a?.machine == "0123456789abcd", "an add-store's two certs read as the store onto the running machine")
check(throwsErr { _ = try KernelChecks.add(first: vectors["addFirst"]!, second: vectors["addSecond"]!, session: "s1", store: "other") }, "…not for another store")
check(throwsErr { _ = try KernelChecks.add(first: vectors["source"]!, second: vectors["addSecond"]!, session: "s1", store: "extra") }, "…not when the second cert leaves another source")

// ---- the spawner's Fly token (KERNEL_SPAWNER: a running kernel/cmd/spawner with the same box key) ----
if let sp = env["KERNEL_SPAWNER"], !sp.isEmpty {
  func spCall(_ path: String, _ body: Any? = nil) -> (Int, Data) {
    var r = URLRequest(url: URL(string: sp + path)!)
    if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var out: (Int, Data) = (0, Data())
    URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
    sem.wait()
    return out
  }
  let idDoc = doc(spCall("/identity").1)
  let spk = try? KernelSetup.component(idDoc, role: "spawner", boxKey: boxKey)
  check(spk != nil, "the spawner's identity is the box key's")
  check(throwsErr { _ = try KernelSetup.component(idDoc, role: "secrets", boxKey: boxKey) }, "…not as another role")
  check(throwsErr { _ = try KernelSetup.component(idDoc, role: "spawner", boxKey: other) }, "…not with another box key")
  let (code, body) = spCall("/fly-token", try! KernelSetup.flyToken("fly-test-token", to: spk!))
  check(code == 200 && String(decoding: body, as: UTF8.self).contains("fly-token-set"), "the spawner opens the Fly token the app sealed to it")
}

print(failures == 0 ? "all kernel checks passed" : "\(failures) kernel check(s) FAILED")
exit(failures == 0 ? 0 : 1)
