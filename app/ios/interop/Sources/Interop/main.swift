// The shell's CoreCrypto + Recovery against the REAL core binary (fakefly build, the public TEST master key,
// a throwaway box key) and the backup bucket on a local S3 stand-in seeded by infra/setup.py's own code
// (ios/ci/standin.py): the identity and its 8 words, the recovery kit formats, reading + checking + decrypting
// the backups, recovery itself, the signed store list (sensitivity), create / mark sensitive, split-key
// unlock, approvals (new session, add a store, resume on the latest image), grants (the session cert, the
// draft checks) — and the refusals: a box
// signature by another key, a tampered backup, wrong bucket credentials, a wrong master key, no core store,
// a statement for another core or bundle, a second recovery, a forged phone signature, a wrong share.
// Configuration (env): INTEROP_CORE, INTEROP_S3_ENDPOINT, INTEROP_S3_KIT ("jarvis2-s3:<access>:<secret>"),
// INTEROP_KEYS (the dir with box.pub + setup.pub), INTEROP_WORDS (core/words.txt), INTEROP_WORDS_EXPECTED
// (what the core logged), INTEROP_MASTER_PEM (e2e/testdata/master-test.pem).
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
let core = need("INTEROP_CORE")
let keysDir = need("INTEROP_KEYS")
let boxKey = try! String(contentsOfFile: keysDir + "/box.pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
let setupKey = try! String(contentsOfFile: keysDir + "/setup.pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
let words = try! String(contentsOfFile: need("INTEROP_WORDS"), encoding: .utf8).split(whereSeparator: \.isWhitespace).map(String.init)
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }
func asyncResult<T>(_ fn: @escaping () async throws -> T) -> Result<T, Error> {
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: Result<T, Error>!
  Task { do { out = .success(try await fn()) } catch { out = .failure(error) }; sem.signal() }
  sem.wait()
  return out
}

func call(_ path: String, _ body: Any? = nil) -> (Int, Data) {
  var r = URLRequest(url: URL(string: core + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
func docJSON(_ d: SignedDoc) -> [String: String] { ["payload": d.payload, "sig": d.sig] }

// ---- the core's identity ----
let idj = try! JSONSerialization.jsonObject(with: call("/identity").1) as! [String: String]
let coreKeys = PublicKeys(signingKey: idj["signingKey"]!, agreementKey: idj["agreementKey"]!)
check(CoreCrypto.identityVouched(coreKeys, boxSig: idj["boxSig"]!, boxKey: boxKey), "the core's identity is signed by the box key")
check(!CoreCrypto.identityVouched(coreKeys, boxSig: idj["boxSig"]!, boxKey: setupKey), "…and not by another key")
check(!CoreCrypto.identityVouched(PublicKeys(signingKey: coreKeys.agreementKey, agreementKey: coreKeys.signingKey), boxSig: idj["boxSig"]!, boxKey: boxKey), "…and not for other keys")
let w = CoreCrypto.identityWords(coreKeys, words: words)
check(w == need("INTEROP_WORDS_EXPECTED"), "the 8 words match the core's own (\(w))")

// ---- the kit ----
let pem = try! String(contentsOfFile: need("INTEROP_MASTER_PEM"), encoding: .utf8)
let master = try! MasterKey.parse(pem)
check((try? MasterKey.parse(master.kit))?.publicKey == master.publicKey, "the master key's kit string round-trips (\(master.kit.prefix(24))…)")
let fresh = MasterKey.generate()
check((try? MasterKey.parse(fresh.kit))?.publicKey == fresh.publicKey, "a generated master key's kit parses back")
check(fresh.kit.hasPrefix("jarvis2-master:MIG"), "the kit is PKCS#8 DER (starts MIG…)")
check(throwsErr { _ = try MasterKey.parse("jarvis2-master:AAAA") }, "a broken master key is refused")
check(throwsErr { _ = try S3Credentials.parse("jarvis2-s3:only-one") }, "broken bucket credentials are refused")
let creds = try! S3Credentials.parse(need("INTEROP_S3_KIT"))
func reader(_ bucket: String, _ c: S3Credentials = creds) -> S3Reader { S3Reader(bucket: S3Bucket(endpoint: need("INTEROP_S3_ENDPOINT"), region: "fsn1", bucket: bucket), creds: c) }

// ---- the backups ----
let readOK = asyncResult { try await Recovery.readBackups(reader("jarvis2-backup-ci"), master: master, setupKey: setupKey) }
guard case .success(let stores) = readOK else { print("FAIL reading the backups: \(readOK)"); exit(1) }
check(stores.map(\.name) == ["claude-login", "core", "default", "gmail", "marked"], "every store comes back (\(stores.map(\.name)))")
let sens = Dictionary(uniqueKeysWithValues: stores.map { ($0.name, $0.sensitive) })
check(sens["default"] == false && sens["claude-login"] == false && sens["gmail"] == true && sens["core"] == true, "sensitivity from the backups")
check(sens["marked"] == true, "a sensitive/ marker makes a store sensitive whatever its backup says")
check(stores.first { $0.name == "default" }?.values == ["GITHUB_TOKEN": "ci-dummy", "OTHER": "x"], "values decrypt with the master key")
func fails(_ r: Result<[RecoveredStore], Error>, _ what: String) {
  if case .failure(let e) = r { check(true, "\(what): \((e as? LocalizedError)?.errorDescription ?? "\(e)")") } else { check(false, what) }
}
fails(asyncResult { try await Recovery.readBackups(reader("jarvis2-backup-tampered"), master: master, setupKey: setupKey) }, "a backup signed by another key is refused")
fails(asyncResult { try await Recovery.readBackups(reader("jarvis2-backup-ci", S3Credentials(accessKey: creds.accessKey, secretKey: "wrong")), master: master, setupKey: setupKey) }, "wrong bucket credentials are refused by the bucket")
fails(asyncResult { try await Recovery.readBackups(reader("jarvis2-backup-ci"), master: fresh, setupKey: setupKey) }, "another master key doesn't open the backups")
if case .success(let nc) = asyncResult({ try await Recovery.readBackups(reader("jarvis2-backup-nocore"), master: master, setupKey: setupKey) }) {
  check(throwsErr { _ = try Recovery.bundle(nc) }, "backups without the core store can't make a bundle")
} else { check(false, "the no-core bucket reads") }

// ---- recovery ----
let phoneSigning = P256.Signing.PrivateKey(), phoneAgreement = P256.KeyAgreement.PrivateKey()
let phone = PublicKeys(signingKey: phoneSigning.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgreement.publicKey.x963Representation.base64EncodedString())
let bundle = try! Recovery.bundle(stores)
func recover(_ body: [String: Any]) -> (Int, Data) { call("/recover", body) }
var bad = try! Recovery.request(core: coreKeys, phone: phone, master: fresh, bundle: bundle)
check(recover(bad).0 == 403, "a statement signed by another master key is refused")
bad = try! Recovery.request(core: phone, phone: phone, master: master, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle, to: coreKeys.agreementKey, info: CoreCrypto.recoverInfo)
check(recover(bad).0 == 403, "a statement naming another core is refused")
bad = try! Recovery.request(core: coreKeys, phone: phone, master: master, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle + Data(" ".utf8), to: coreKeys.agreementKey, info: CoreCrypto.recoverInfo)
check(recover(bad).0 == 403, "a bundle other than the signed one is refused")
let (rs, rb) = recover(try! Recovery.request(core: coreKeys, phone: phone, master: master, bundle: bundle))
check(rs == 200, "the core recovers (HTTP \(rs) \(String(decoding: rb.prefix(200), as: UTF8.self)))")
let rec = try? CoreCrypto.decode(doc(rb), by: coreKeys.signingKey, as: KindDoc.self, what: "recovered")
check(rec?.kind == "recovered" && rec?.stores == 4, "the answer is the core's signed 'recovered' (4 stores, core's own excluded)")
check(recover(try! Recovery.request(core: coreKeys, phone: phone, master: master, bundle: bundle)).0 == 409, "a second recovery is refused")
let coreKey = coreKeys.signingKey

// ---- stores (signed, with the caller's nonce) ----
func list() -> [StoreView] {
  let n = CoreCrypto.nonce()
  let d = try! CoreCrypto.decode(doc(call("/stores", ["nonce": n]).1), by: coreKey, as: StoresDoc.self, what: "stores")
  check(d.kind == "stores" && d.nonce == n, "store list is signed and carries my nonce")
  return d.stores
}
var l = list()
check(l.map(\.name) == ["claude-login", "default", "gmail", "marked"], "the core lists every store but its own")
check(l.filter(\.sensitive).map(\.name) == ["gmail", "marked"], "sensitivity in the core's list")
check(throwsErr { _ = try CoreCrypto.verified(SignedDoc(payload: "{}", sig: doc(call("/stores", ["nonce": "x"]).1).sig), by: coreKey, what: "x") }, "an altered payload is refused")
check(call("/stores/create", ["name": "notes"]).0 == 200, "create a store")
check(call("/stores/create", ["name": "notes"]).0 == 409, "…once")
l = list()
check(l.first { $0.name == "notes" }.map { !$0.sensitive && $0.empty } == true, "a created store is empty and not sensitive")
let mk = try? CoreCrypto.decode(doc(call("/stores/mark-sensitive", ["name": "notes"]).1), by: coreKey, as: KindDoc.self, what: "mark")
check(mk?.kind == "marked-sensitive" && mk?.name == "notes", "mark sensitive")
check(call("/stores/mark-sensitive", ["name": "notes"]).0 == 409, "…one way")

// ---- split-key unlock ----
func unlock(_ store: String, share: (UnlockBegin) throws -> Data) -> (Int, Data) {
  let b = try! CoreCrypto.decode(doc(call("/unlock/begin", ["store": store]).1), by: coreKey, as: UnlockBegin.self, what: "unlock-begin")
  check(b.kind == "unlock-begin" && b.store == store, "unlock-begin for \(store) is signed")
  return call("/unlock/finish", ["pending": b.pending, "share": try! CoreCrypto.sealShare(try! share(b), to: b.t)])
}
let realShare: (UnlockBegin) throws -> Data = { b in
  try phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
}
let (us, ub) = unlock("default", share: realShare)
check(us == 200, "the core opens the recovered store with the phone's sealed share (HTTP \(us))")
let u = try? CoreCrypto.decode(doc(ub), by: coreKey, as: KindDoc.self, what: "unlocked")
check(u?.kind == "unlocked" && u?.store == "default", "unlocked answer is signed")
check(unlock("gmail") { _ in Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }.0 != 200, "a wrong share doesn't open a store")
let n2 = CoreCrypto.nonce()
let ul = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": n2]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul?.nonce == n2 && ul?.unlocked.map(\.id) == [u?.id ?? "?"], "unlocked list is signed, fresh and complete")

// ---- approvals: the challenge before any machine ----
func challenge(_ body: [String: Any]) -> SignedDoc {
  let (s, d) = call("/succession", body)
  if s != 200 { print("succession HTTP \(s): \(String(decoding: d, as: UTF8.self))") }
  return doc(d)
}
func approve(_ ch: SignedDoc) -> (Int, SignedDoc?) {
  let sig = try! phoneSigning.signature(for: Data(ch.payload.utf8)).derRepresentation.base64EncodedString()
  let (s, d) = call("/approve/by-phone", ["challenge": docJSON(ch), "signature": sig])
  return (s, s == 200 ? doc(d) : nil)
}
struct StartedDoc: Codable { let kind: String; let machine: StartedMachine }
func start(_ image: String) -> StartedMachine {
  try! CoreCrypto.decode(doc(call("/start", ["image": image, "region": "lhr", "size": "small"]).1), by: coreKey, as: StartedDoc.self, what: "start").machine
}

// new session
let ch1 = challenge(["predecessor": NSNull(), "stores": ["default", "claude-login"], "options": ["harness": "claude"], "image": "img"])
let r1 = try! Checks.review(challenge: ch1, coreKey: coreKey)
check(r1.kind == .newSession && r1.stores == ["claude-login", "default"] && r1.harness == "claude" && r1.image == "img", "new-session challenge read from its own fields")
check(!throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude") }, "matches what was picked plus the harness's store")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default", "gmail"], harnessStores: ["claude-login"], harness: "claude") }, "refused when the stores differ")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "opencode") }, "refused when the harness differs")
check(throwsErr { _ = try Checks.review(challenge: SignedDoc(payload: ch1.payload, sig: try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()), coreKey: coreKey) }, "a challenge not signed by the core is refused")
let forged = try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()
check(call("/approve/by-phone", ["challenge": docJSON(ch1), "signature": forged]).0 == 403, "the core refuses a signature by another key")
let (a1s, a1) = approve(ch1)
check(a1s == 200 && !throwsErr { try Checks.answerFor(r1, answer: a1!, coreKey: coreKey) }, "the phone's signature → the core's approval")
let m1 = start("img")
let (c1s, c1d) = call("/certify", ["approval": docJSON(a1!), "machine": m1.id])
check(c1s == 200, "the approval certifies the started machine")
let cert1 = doc(c1d)

// ---- grants: the session's cert, then the router's draft checked against what the grant page chose ----
let sc = try? Checks.cert(cert1, coreKey: coreKey)
check(sc != nil && sc!.line == m1.id && sc!.phone == phone.signingKey && sc!.sensitive == false && Set(sc!.stores ?? []) == ["claude-login", "default"],
      "the session cert names its line, this phone and its stores (\(sc?.line ?? "?"))")
check(throwsErr { _ = try Checks.cert(SignedDoc(payload: cert1.payload, sig: ch1.sig), coreKey: coreKey) }, "a cert with another signature is refused")
let holderKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation.base64EncodedString()
func iso(_ d: Date) -> String { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f.string(from: d) }
func grantText(_ f: [String: Any]) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: f, options: [.sortedKeys]), as: UTF8.self) }
let now = Date()
let good: [String: Any] = ["kind": "grant", "holder": holderKey, "session": m1.id, "scope": "shell", "issued": iso(now), "expires": iso(now.addingTimeInterval(600))]
func review(_ f: [String: Any], kind: String = "grant", minutes: Int = 10, until: Date? = nil, cert: SessionCert? = nil, phoneKey: String? = nil) -> Bool {
  guard let c = cert ?? sc else { return false }
  let pk = phoneKey ?? phone.signingKey
  return !throwsErr { _ = try Checks.reviewGrant(text: grantText(f), cert: c, phoneKey: pk, holderKey: holderKey, kind: kind, minutes: minutes, until: until, now: now) }
}
check(review(good), "a 10-minute grant for this line and holder passes")
var g2 = good; g2["session"] = "other-line"
check(!review(g2), "…refused for another line")
g2 = good; g2["holder"] = phone.signingKey
check(!review(g2), "…refused for another holder")
g2 = good; g2["expires"] = iso(now.addingTimeInterval(1200))
check(!review(g2), "…refused when longer than chosen")
check(!review(good, minutes: 11), "…refused beyond 10 minutes")
g2 = good; g2["scope"] = "root"
check(!review(g2), "…refused with another scope")
g2 = good; g2["extra"] = "x"
check(!review(g2), "…refused with an extra field")
g2 = good; g2["issued"] = iso(now.addingTimeInterval(-3600)); g2["expires"] = iso(now.addingTimeInterval(-3000))
check(!review(g2), "…refused when not issued now")
check(!review(good, phoneKey: P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()), "…refused when the cert names another phone")
let end = now.addingTimeInterval(30 * 86400)
let rule: [String: Any] = ["kind": "rule", "holder": holderKey, "session": m1.id, "scope": "shell", "issued": iso(now), "until": iso(end)]
check(review(rule, kind: "rule", until: end), "a standing rule until the chosen date passes")
check(!review(rule, kind: "rule", until: end.addingTimeInterval(86400)), "…refused for another date")
check(!review(rule, kind: "grant"), "…refused as a grant")
let sig = try! phoneSigning.signature(for: Data(grantText(good).utf8)).derRepresentation.base64EncodedString()
check(CoreCrypto.valid(Data(grantText(good).utf8), sig: sig, by: sc?.phone ?? ""), "the phone's signature checks against the key in the cert (what the machine does)")

// add a store (the machine exists)
let ch2 = challenge(["predecessor": docJSON(cert1), "machine": m1.id, "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude"]])
let r2 = try! Checks.review(challenge: ch2, coreKey: coreKey)
check(r2.kind == .addStore && r2.addedStore == "gmail" && r2.sensitive == ["gmail"], "add-store challenge: one more store, marked sensitive")
let (a2s, a2) = approve(ch2)
check(a2s == 200 && !throwsErr { try Checks.answerFor(r2, answer: a2!, coreKey: coreKey) }, "adding a store answers with the machine's new succession cert")
check(throwsErr { try Checks.answerFor(r2, answer: a1!, coreKey: coreKey) }, "another answer is refused")

// resume on the latest image: approval first, then the machine
check(call("/kill", ["machine": m1.id]).0 == 200, "kill the machine (pause)")
let ch3 = challenge(["predecessor": docJSON(a2!), "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude"], "image": "img2"])
let r3 = try! Checks.review(challenge: ch3, coreKey: coreKey)
check(r3.kind == .resumeUpgrade && r3.image == "img2", "resume-upgrade challenge read from its own fields")
let (a3s, a3) = approve(ch3)
check(a3s == 200 && !throwsErr { try Checks.answerFor(r3, answer: a3!, coreKey: coreKey) }, "the phone approves the resume")
let m2 = start("img2")
check(call("/certify", ["approval": docJSON(a3!), "machine": m2.id]).0 == 200, "…and the new machine is certified")

// a sensitive line: no standing rule
let ch4 = challenge(["predecessor": NSNull(), "stores": ["gmail"], "options": ["harness": "claude"], "image": "img"])
let (a4s, a4) = approve(ch4)
let (c4s, c4d) = a4 == nil ? (0, Data()) : call("/certify", ["approval": docJSON(a4!), "machine": start("img").id])
if a4s == 200, c4s == 200, let sc4 = try? Checks.cert(doc(c4d), coreKey: coreKey) {
  check(sc4.sensitive == true, "a session with a sensitive store has a sensitive cert")
  var r4 = rule; r4["session"] = sc4.line
  check(!review(r4, kind: "rule", until: end, cert: sc4), "…and the grant page refuses a standing rule for it")
} else { check(false, "a sensitive session certifies") }

// ---- lock ----
let lk = try? CoreCrypto.decode(doc(call("/lock", ["id": u?.id ?? ""]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(lk?.kind == "locked", "lock releases the unlock id")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
