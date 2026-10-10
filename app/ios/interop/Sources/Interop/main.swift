// The shell's CoreCrypto + CoreSetup against the REAL core binary (fakefly build, a throwaway box key) and the
// backups as the router serves them (a router on the runner reading a local S3 stand-in that infra/setup.py's own
// code seeded, ios/ci/standin.py): the core's identity and signed state (empty, then set up), the recovery kit
// string (round trip, the old version refused), reading + checking + decrypting the backups with the kit's master
// key, Recover itself (the claim), the signed store list (sensitivity), create / mark sensitive, split-key unlock,
// approvals (new session, add a store, resume on the latest image), grants (the session cert, the draft checks),
// the Fly token sealed to the core, and Reset's wipe at the end — and the refusals: a box signature by another key,
// a state not signed by the core, a tampered backup, a wrong master key, a claim for another core or bundle or
// signed by another key, a second claim, a forged phone signature, a wrong share, a wipe by another key.
// Configuration (env): INTEROP_CORE, INTEROP_ROUTER (its /api/backups reads the stand-in bucket jarvis2-backup-ci),
// INTEROP_KEYS (the dir with box.pub + setup.pub), INTEROP_BACKUPS (standin.py's dump: {bucket: [{key, body}]}),
// INTEROP_MASTER_PEM (e2e/testdata/master-test.pem).
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
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }

func call(_ path: String, _ body: Any? = nil, base: String = core) -> (Int, Data) {
  var r = URLRequest(url: URL(string: base + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
func docJSON(_ d: SignedDoc) -> [String: String] { ["payload": d.payload, "sig": d.sig] }

// ---- the core's identity: box-signed keys, its own signed state ----
func identity() -> CoreSetup.Identity { try! JSONDecoder().decode(CoreSetup.Identity.self, from: call("/identity").1) }
let id0 = identity()
let checked = try? CoreSetup.check(id0, boxKey: boxKey)
check(checked != nil, "the core's keys are signed by the box key and its state by the core")
let coreKeys = checked?.keys ?? PublicKeys(signingKey: "", agreementKey: "")
check(checked?.state.master == "" && checked?.state.phone == nil, "a new core is empty")
check(throwsErr { _ = try CoreSetup.check(id0, boxKey: setupKey) }, "…not with another box key")
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(signingKey: id0.agreementKey, agreementKey: id0.signingKey, boxSig: id0.boxSig, state: id0.state), boxKey: boxKey) }, "…not for other keys")
let otherSigner = P256.Signing.PrivateKey()
let forgedState = SignedDoc(payload: id0.state.payload, sig: try! otherSigner.signature(for: Data(id0.state.payload.utf8)).derRepresentation.base64EncodedString())
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(signingKey: id0.signingKey, agreementKey: id0.agreementKey, boxSig: id0.boxSig, state: forgedState), boxKey: boxKey) }, "…not with a state the core didn't sign")

// ---- the master key and the recovery kit (the ONE string) ----
let pem = try! String(contentsOfFile: need("INTEROP_MASTER_PEM"), encoding: .utf8)
let master = MasterKey(signing: try! P256.Signing.PrivateKey(pemRepresentation: pem))
check((try? MasterKey(pkcs8: master.pkcs8))?.publicKey == master.publicKey, "the master key's PKCS#8 part round-trips (\(master.pkcs8.prefix(8))…)")
let fresh = MasterKey.generate()
check((try? MasterKey(pkcs8: fresh.pkcs8))?.publicKey == fresh.publicKey && fresh.pkcs8.hasPrefix("MIG"), "a generated master key is PKCS#8 DER and parses back")
check(throwsErr { _ = try MasterKey(pkcs8: "AAAA") }, "a broken master key is refused")
check(MasterKey.same(master.publicKey, master.publicKey) && !MasterKey.same(fresh.publicKey, master.publicKey) && !MasterKey.same("", ""), "public keys compare by their bytes")
let kitString = RecoveryKit(master: master).string
check(kitString.hasPrefix("jarvis2-kit:2:MIG") && !kitString.dropFirst(14).contains(":"), "the kit string is the version and the master key only (\(kitString.prefix(20))…)")
let kit = try? RecoveryKit.parse(kitString)
check(kit?.master.publicKey == master.publicKey, "the kit round-trips")
let wrapped = String(kitString.enumerated().map { $0.offset > 0 && $0.offset % 64 == 0 ? "\n\($0.element)" : "\($0.element)" }.joined()) + "\n"
check((try? RecoveryKit.parse("  " + wrapped))?.master.publicKey == master.publicKey, "a kit pasted with line breaks and spaces still parses")
func kitError(_ s: String) -> String { do { _ = try RecoveryKit.parse(s); return "" } catch { return (error as? LocalizedError)?.errorDescription ?? "?" } }
check(kitError("jarvis2-kit:1:\(master.pkcs8):AK:SK").contains("older Jarvis 2"), "a version-1 kit is refused with a plain message (\(kitError("jarvis2-kit:1:x")))")
check(kitError(master.pkcs8) == "That isn't a recovery kit.", "a bare master key is not a kit")
check(!kitError("jarvis2-kit:2:AAAA").isEmpty, "a kit with a broken master key is refused")
check(!kitError("jarvis2-kit:3:" + master.pkcs8).isEmpty, "another kit version is refused")
let kitMaster = kit?.master ?? fresh

// ---- the backups, as the router serves them ----
let dumps = try! JSONDecoder().decode([String: [CoreSetup.BackupObject]].self, from: Data(contentsOf: URL(fileURLWithPath: need("INTEROP_BACKUPS"))))
struct Served: Decodable { let objects: [CoreSetup.BackupObject] }
let (bs, bd) = call("/api/backups", base: need("INTEROP_ROUTER"))
let served = (try? JSONDecoder().decode(Served.self, from: bd))?.objects ?? []
check(bs == 200 && Set(served.map { $0.key + $0.body }) == Set((dumps["jarvis2-backup-ci"] ?? []).map { $0.key + $0.body }), "the router serves the bucket's objects unchanged (HTTP \(bs), \(served.count) objects)")
let stores: [RecoveredStore]
do { stores = try CoreSetup.readBackups(served, master: kitMaster, setupKey: setupKey) } catch { print("FAIL reading the backups: \(error)"); exit(1) }
check(stores.map(\.name) == ["claude-login", "core", "default", "gmail", "marked"], "every store comes back (\(stores.map(\.name)))")
let sens = Dictionary(uniqueKeysWithValues: stores.map { ($0.name, $0.sensitive) })
check(sens["default"] == false && sens["claude-login"] == false && sens["gmail"] == true && sens["core"] == true, "sensitivity from the backups")
check(sens["marked"] == true, "a sensitive/ marker makes a store sensitive whatever its backup says")
check(stores.first { $0.name == "default" }?.values == ["GITHUB_TOKEN": "ci-dummy", "OTHER": "x"], "values decrypt with the master key")
check(throwsErr { _ = try CoreSetup.readBackups(dumps["jarvis2-backup-tampered"] ?? [], master: master, setupKey: setupKey) }, "a backup signed by another key is refused")
check(throwsErr { _ = try CoreSetup.readBackups(served, master: fresh, setupKey: setupKey) }, "another master key doesn't open the backups")
check(throwsErr { _ = try CoreSetup.readBackups(served + [served[0]], master: master, setupKey: setupKey) }, "a backup served twice is refused")
let nocore = try? CoreSetup.readBackups(dumps["jarvis2-backup-nocore"] ?? [], master: master, setupKey: setupKey)
check(nocore?.map(\.name) == ["default"] && (try? CoreSetup.bundle(nocore ?? [])) != nil, "backups without the core store still make a bundle (the token comes later)")

// ---- Recover: the claim, signed with the kit's master key ----
let phoneSigning = P256.Signing.PrivateKey(), phoneAgreement = P256.KeyAgreement.PrivateKey()
let phone = PublicKeys(signingKey: phoneSigning.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgreement.publicKey.x963Representation.base64EncodedString())
let bundle = try! CoreSetup.bundle(stores)
func claim(_ body: [String: Any]) -> (Int, Data) { call("/claim", body) }
var bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)
bad["masterSig"] = try! fresh.sign(bad["statement"] as! String)
check(claim(bad).0 == 403, "a claim signed by another key than the master key it names is refused")
bad = try! CoreSetup.claim(core: phone, phone: phone, master: kitMaster, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle, to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a claim naming another core is refused")
bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle + Data(" ".utf8), to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a bundle other than the signed one is refused")
check(call("/wipe", try! CoreSetup.wipe(core: coreKeys, master: kitMaster)).0 == 409, "an empty core can't be wiped")
let (rs, rb) = claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle))
check(rs == 200, "the core is set up (HTTP \(rs) \(String(decoding: rb.prefix(200), as: UTF8.self)))")
let rec = try? CoreCrypto.decode(doc(rb), by: coreKeys.signingKey, as: KindDoc.self, what: "claimed")
check(rec?.kind == "claimed" && rec?.stores == 4, "the answer is the core's signed 'claimed' (4 stores, the core's own excluded)")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)).0 == 409, "a second claim is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: fresh, bundle: try! CoreSetup.bundle([]))).0 == 409, "…and a Reset's claim with a new key too")
let st1 = (try? CoreSetup.check(identity(), boxKey: boxKey))?.state
check(st1 != nil && CoreSetup.status(st1!, myMaster: kitMaster.publicKey, myPhone: phone) == .mine, "the core's state now names this master key and this phone (mine)")
check(st1 != nil && CoreSetup.status(st1!, myMaster: fresh.publicKey, myPhone: phone) == .foreign, "…a phone with another master key sees it as foreign")
check(st1 != nil && CoreSetup.status(st1!, myMaster: kitMaster.publicKey, myPhone: PublicKeys(signingKey: phone.agreementKey, agreementKey: phone.signingKey)) == .otherPhone, "…and another phone with the same kit as set up for another iPhone")
check(st1 != nil && CoreSetup.status(st1!, myMaster: nil, myPhone: phone) == .foreign, "…and a phone with no master key as foreign")

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
let ch1 = challenge(["predecessor": NSNull(), "stores": ["default", "claude-login"], "options": ["harness": "claude", "permissionMode": "bypass"], "image": "img"])
let r1 = try! Checks.review(challenge: ch1, coreKey: coreKey)
check(r1.kind == .newSession && r1.stores == ["claude-login", "default"] && r1.harness == "claude" && r1.image == "img", "new-session challenge read from its own fields")
check(r1.permissionMode == "bypass", "the permission mode is read from the signed challenge (\(r1.permissionMode))")
check(!throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "matches what was picked plus the harness's store")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default", "gmail"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "refused when the stores differ")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "opencode", permissionMode: "bypass") }, "refused when the harness differs")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "auto") }, "refused when the permission mode differs")
let chAuto = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude"], "image": "img"])
check((try? Checks.review(challenge: chAuto, coreKey: coreKey))?.permissionMode == "auto", "a challenge without a mode reads as auto (the core's default)")
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

// a task's line: an ordinary new-session challenge whose signed harness is task:<template>
let chT = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "task:hello", "permissionMode": "auto"], "image": "img"])
let rT = try? Checks.review(challenge: chT, coreKey: coreKey)
check(rT?.kind == .newSession && rT?.harness == "task:hello" && rT?.permissionMode == "auto", "a task's challenge is a new session on harness task:hello (\(rT?.harness ?? "?"))")
if let rt = rT {
  check(!throwsErr { try Checks.matchesPicked(rt, stores: ["default"], harnessStores: [], harness: "task:hello", permissionMode: "auto") }, "…and matches its template's harness and stores")
} else { check(false, "…and matches its template's harness and stores") }
let (aTs, aT) = approve(chT)
check(aTs == 200 && rT != nil && !throwsErr { try Checks.answerFor(rT!, answer: aT!, coreKey: coreKey) }, "the phone approves a task's line once")

// add a store (the machine exists)
let ch2 = challenge(["predecessor": docJSON(cert1), "machine": m1.id, "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude", "permissionMode": "bypass"]])
let r2 = try! Checks.review(challenge: ch2, coreKey: coreKey)
check(r2.kind == .addStore && r2.addedStore == "gmail" && r2.sensitive == ["gmail"], "add-store challenge: one more store, marked sensitive")
let (a2s, a2) = approve(ch2)
check(a2s == 200 && !throwsErr { try Checks.answerFor(r2, answer: a2!, coreKey: coreKey) }, "adding a store answers with the machine's new succession cert")
check(throwsErr { try Checks.answerFor(r2, answer: a1!, coreKey: coreKey) }, "another answer is refused")

// resume on the latest image: approval first, then the machine
check(call("/kill", ["machine": m1.id]).0 == 200, "kill the machine (pause)")
let ch3 = challenge(["predecessor": docJSON(a2!), "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude", "permissionMode": "auto"], "image": "img2"])
let r3 = try! Checks.review(challenge: ch3, coreKey: coreKey)
check(r3.kind == .resumeUpgrade && r3.image == "img2" && r3.permissionMode == "auto", "resume-upgrade challenge read from its own fields (mode \(r3.permissionMode))")
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

// ---- the Fly token, sealed to the core (infra/setup.py backup-core) ----
let tok = try! CoreCrypto.seal(Data(#"{"FLY_API_TOKEN":"ci-token"}"#.utf8), to: coreKeys.agreementKey, info: "jarvis2/fly-token")
let ft = try? CoreCrypto.decode(doc(call("/fly-token", ["sealed": tok]).1), by: coreKey, as: KindDoc.self, what: "fly token")
check(ft?.kind == "fly-token-set", "the core takes a Fly token sealed to it")
check(call("/fly-token", ["sealed": try! CoreCrypto.seal(Data(#"{"FLY_API_TOKEN":"x"}"#.utf8), to: coreKeys.agreementKey, info: CoreCrypto.shareInfo)]).0 == 400, "…not one sealed for something else")

// ---- Reset on a set-up core: only the master key it was set up with ends it ----
check(call("/wipe", try! CoreSetup.wipe(core: coreKeys, master: fresh)).0 == 403, "a wipe signed by another key is refused")
var w2 = try! CoreSetup.wipe(core: phone, master: kitMaster)
check(call("/wipe", w2).0 == 403, "a wipe naming another core is refused")
w2 = try! CoreSetup.wipe(core: coreKeys, master: kitMaster)
let (ws, wd) = call("/wipe", w2)
let wiping = try? CoreCrypto.decode(doc(wd), by: coreKey, as: KindDoc.self, what: "wiping")
check(ws == 200 && wiping?.kind == "wiping" && wiping?.core == coreKey, "the master key ends the core (a signed 'wiping')")
sleep(3)
check(call("/key").0 == 0, "…and the core process is gone (Kubernetes starts a new, empty one)")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
