// Round trips between the shell's CoreCrypto and the real core (fakefly build): pairing strings, signed
// store lists, split-key unlock, lock, the signed unlocked list, a new-session approval and a
// resume-with-upgrade approval (burn cert) — plus the refusals: a forged signature, a wrong share, a
// challenge for other stores, an upgrade without its burn cert; and setup: signed by the setup key (unsigned,
// replayed, stale or wrongly-signed calls refused), store values sealed to the core, the `core` store seeded
// and unlocked but never given to a session.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

let args = CommandLine.arguments
guard args.count == 3 else { print("usage: Interop <core url> <setup private key, base64 DER>"); exit(2) }
let core = args[1].hasSuffix("/") ? String(args[1].dropLast()) : args[1]
guard let setupKey = SetupSigner(base64DER: args[2]) else { print("the setup key isn't a base64 DER P-256 private key"); exit(2) }
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }

/// setup: nil = no signature; else the headers to send (from SetupSigner.headers over this exact body)
func call(_ path: String, _ body: Any? = nil, headers: ((Data) -> [String: String])? = nil) -> (Int, Data) {
  var r = URLRequest(url: URL(string: core + path)!)
  var raw = Data()
  if let body { raw = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = "POST"; r.httpBody = raw; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  for (k, v) in headers?(raw) ?? [:] { r.setValue(v, forHTTPHeaderField: k) }
  let sem = DispatchSemaphore(value: 0)
  var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
let P256Other = SetupSigner(base64DER: P256.Signing.PrivateKey().derRepresentation.base64EncodedString())!
func setup(_ path: String, _ body: Any) -> (Int, Data) { call(path, body, headers: { setupKey.headers("POST", path, $0) }) }
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
func docJSON(_ d: SignedDoc) -> [String: String] { ["payload": d.payload, "sig": d.sig] }

// ---- pairing: the phone's software keys (what the simulator build uses) ----
let signing = P256.Signing.PrivateKey(), agreement = P256.KeyAgreement.PrivateKey()
let phone = KeyPairString(role: "phone", signingKey: signing.publicKey.x963Representation.base64EncodedString(), agreementKey: agreement.publicKey.x963Representation.base64EncodedString())
check((try? KeyPairString.parse(phone.text, role: "phone")) == phone, "phone string round-trips")
let key = try! JSONSerialization.jsonObject(with: call("/key").1) as! [String: String]

// ---- setup: signed by the setup key, each signature once, within the clock window ----
let phoneBody = ["signingKey": phone.signingKey, "agreementKey": phone.agreementKey]
check(call("/setup/phone", phoneBody).0 == 401, "an unsigned setup call is refused")
check(call("/setup/phone", phoneBody, headers: { P256Other.headers("POST", "/setup/phone", $0) }).0 == 401, "a setup call signed by another key is refused")
check(call("/setup/phone", phoneBody, headers: { setupKey.headers("POST", "/setup/phone", $0, time: Int(Date().timeIntervalSince1970) - 600) }).0 == 401, "a setup call 10 minutes old is refused")
check(call("/setup/phone", phoneBody, headers: { setupKey.headers("POST", "/setup/store", $0) }).0 == 401, "a signature for another path is refused")
let phoneRaw = try! JSONSerialization.data(withJSONObject: phoneBody), phoneHdr = setupKey.headers("POST", "/setup/phone", phoneRaw)
check(call("/setup/phone", phoneBody, headers: { raw in raw == phoneRaw ? phoneHdr : [:] }).0 == 200, "core accepts the phone's keys")
check(call("/setup/phone", phoneBody, headers: { _ in phoneHdr }).0 == 401, "a replayed setup signature is refused")
func seed(_ name: String, _ values: [String: String], sensitive: Bool) -> Int {
  setup("/setup/store", ["name": name, "values": SetupSigner.seal(values, to: key["agreementKey"]!), "sensitive": sensitive]).0
}
check(setup("/setup/store", ["name": "plain", "values": ["A": "1"], "sensitive": false]).0 == 400, "unsealed store values are refused")
check(setup("/setup/store", ["name": "plain", "values": SetupSigner.seal(["A": "1"], to: phone.agreementKey), "sensitive": false]).0 == 400, "values sealed to another key are refused")
check(seed("default", ["A": "1", "B": "2"], sensitive: false) == 200, "seed store default (sealed)")
check(seed("gmail", ["G": "x"], sensitive: true) == 200, "seed store gmail (sensitive)")
check(seed("default", ["A": "3"], sensitive: false) != 200, "a store is never replaced")
let coreStr = try! KeyPairString.parse("jarvis2-core:\(key["signingKey"]!):\(key["agreementKey"]!)", role: "core")
let coreKey = coreStr.signingKey
check(throwsErr { _ = try KeyPairString.parse(coreStr.text, role: "phone") }, "a core string is refused where the phone's belongs")

// ---- stores (signed, with the caller's nonce) ----
let n1 = CoreCrypto.nonce()
let sd = doc(call("/stores", ["nonce": n1]).1)
let stores = try! CoreCrypto.decode(sd, by: coreKey, as: StoresDoc.self, what: "stores")
check(stores.kind == "stores" && stores.nonce == n1, "store list is signed and carries my nonce")
check(stores.stores.map(\.name) == ["default", "gmail"] && stores.stores[1].sensitive && !stores.stores[0].sensitive, "store list content")
check(throwsErr { _ = try CoreCrypto.verified(SignedDoc(payload: sd.payload.replacingOccurrences(of: "gmail", with: "gmaiL"), sig: sd.sig), by: coreKey, what: "x") }, "an altered payload is refused")
check(throwsErr { _ = try CoreCrypto.verified(sd, by: phone.signingKey, what: "x") }, "a document signed by another key is refused")

// ---- split-key unlock ----
func unlock(_ store: String, share: (UnlockBegin) throws -> Data) -> (Int, Data) {
  let b = try! CoreCrypto.decode(doc(call("/unlock/begin", ["store": store]).1), by: coreKey, as: UnlockBegin.self, what: "unlock-begin")
  check(b.kind == "unlock-begin" && b.store == store, "unlock-begin for \(store) is signed")
  let x = try! share(b)
  return call("/unlock/finish", ["pending": b.pending, "share": try! CoreCrypto.sealShare(x, to: b.t)])
}
let (st, body) = unlock("default") { b in
  let e = try P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)
  return try agreement.sharedSecretFromKeyAgreement(with: e).withUnsafeBytes { Data($0) }
}
check(st == 200, "core opens the store with the phone's sealed share (HTTP \(st))")
let u = try! CoreCrypto.decode(doc(body), by: coreKey, as: KindDoc.self, what: "unlocked")
check(u.kind == "unlocked" && u.store == "default" && u.id != nil, "unlocked answer is signed")
let (bad, _) = unlock("gmail") { _ in Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }
check(bad != 200, "a wrong share doesn't open a store (HTTP \(bad))")
let n2 = CoreCrypto.nonce()
let ul = try! CoreCrypto.decode(doc(call("/unlocked", ["nonce": n2]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul.kind == "unlocked-list" && ul.nonce == n2 && ul.unlocked.map(\.id) == [u.id!], "unlocked list is signed, fresh and complete")

// ---- a new session: start (fake machine) → challenge → checks → phone signature → cert ----
struct StartedDoc: Codable { let kind: String; let machine: StartedMachine }
func start(_ image: String) -> StartedMachine {
  try! CoreCrypto.decode(doc(call("/start", ["image": image, "region": "lhr", "size": "small"]).1), by: coreKey, as: StartedDoc.self, what: "start").machine
}
let m1 = start("img")
let ch1 = doc(call("/succession", ["predecessor": NSNull(), "machine": m1.id, "stores": ["default"], "options": ["harness": "claude"]]).1)
let r1 = try! Checks.review(challenge: ch1, routerKind: "new-session", burnCert: nil, coreKey: coreKey)
check(r1.kind == .newSession && r1.stores == ["default"] && r1.harness == "claude", "new-session challenge reviewed")
check(!throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harness: "claude") }, "matches what was picked")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default", "gmail"], harness: "claude") }, "refused when the stores differ")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harness: "opencode") }, "refused when the harness differs")
check(throwsErr { _ = try Checks.review(challenge: ch1, routerKind: "add-store", burnCert: nil, coreKey: coreKey) }, "refused when the router mislabels the kind")
let forged = try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()
check(call("/respond/phone", ["challenge": docJSON(ch1), "signature": forged]).0 == 403, "core refuses a signature by another key")
let sig1 = try! signing.signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()
let cert1 = doc(call("/respond/phone", ["challenge": docJSON(ch1), "signature": sig1]).1)
check(!throwsErr { try Checks.certFor(r1, cert: cert1, coreKey: coreKey) }, "core issues the cert for the phone's signature")

// ---- resume with the latest image: kill, burn (dead-machine responder), new machine, iPhone approval ----
check(call("/kill", ["machine": m1.id]).0 == 200, "kill the first machine")
let burnCh = doc(call("/succession", ["predecessor": docJSON(cert1), "machine": "", "stores": ["default"], "options": ["harness": "claude"]]).1)
let (bs, bb) = call("/respond/dead", ["challenge": docJSON(burnCh)])
check(bs == 200, "dead-machine responder burns it")
let burn = doc(bb)
let m2 = start("img2")
let ch2 = doc(call("/succession", ["predecessor": docJSON(cert1), "machine": m2.id, "stores": ["default"], "options": ["harness": "claude"]]).1)
check((try? Checks.review(challenge: ch2, routerKind: "resume-upgrade", burnCert: burn, coreKey: coreKey))?.kind == .resumeUpgrade, "resume-upgrade reviewed with its burn cert")
check(throwsErr { _ = try Checks.review(challenge: ch2, routerKind: "resume-upgrade", burnCert: nil, coreKey: coreKey) }, "refused without a burn cert")
check(throwsErr { _ = try Checks.review(challenge: ch2, routerKind: "resume-upgrade", burnCert: cert1, coreKey: coreKey) }, "refused with a succession cert in place of the burn cert")
let r2 = try! Checks.review(challenge: ch2, routerKind: "resume-upgrade", burnCert: burn, coreKey: coreKey)
let cert2 = doc(call("/respond/phone", ["challenge": docJSON(ch2), "signature": try! signing.signature(for: Data(ch2.payload.utf8)).derRepresentation.base64EncodedString()]).1)
check(!throwsErr { try Checks.certFor(r2, cert: cert2, coreKey: coreKey) }, "core issues the resumed machine's cert")

// ---- the core store: seeded and unlocked like any other, never given to a session ----
check(seed("core", ["FLY_API_TOKEN": "ci-dummy", "FLY_APP": "ci-dummy"], sensitive: true) == 200, "seed the core store")
let (cs, cb) = unlock("core") { b in
  let e = try P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)
  return try agreement.sharedSecretFromKeyAgreement(with: e).withUnsafeBytes { Data($0) }
}
check(cs == 200, "the core store unlocks (HTTP \(cs))")
let m3 = start("img3")
let (rs, _) = call("/succession", ["predecessor": NSNull(), "machine": m3.id, "stores": ["core"], "options": ["harness": "claude"]])
check(rs == 400, "a new session asking for the core store is refused (HTTP \(rs))")
let (rs2, _) = call("/succession", ["predecessor": NSNull(), "machine": m3.id, "stores": ["default", "core"], "options": ["harness": "claude"]])
check(rs2 == 400, "…also alongside another store (HTTP \(rs2))")
let cu = try! CoreCrypto.decode(doc(cb), by: coreKey, as: KindDoc.self, what: "unlocked")
check((try? CoreCrypto.decode(doc(call("/lock", ["id": cu.id!]).1), by: coreKey, as: KindDoc.self, what: "locked"))?.kind == "locked", "the core store locks")

// ---- lock ----
let lk = try! CoreCrypto.decode(doc(call("/lock", ["id": u.id!]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(lk.kind == "locked" && lk.id == u.id, "lock releases the unlock id")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
