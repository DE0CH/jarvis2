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
// INTEROP_MASTER_PEM (e2e/testdata/master-test.pem), INTEROP_EXPORT_OUT (optional: where the offline copy's file goes).
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
check(stores.map(\.name) == ["claude-login", "core", "default", "github-deploy-keys", "gmail", "marked"], "every store comes back (\(stores.map(\.name)))")
let sens = Dictionary(uniqueKeysWithValues: stores.map { ($0.name, $0.sensitive) })
check(sens["default"] == false && sens["claude-login"] == false && sens["gmail"] == true && sens["core"] == true, "sensitivity from the backups")
check(sens["marked"] == true, "a sensitive/ marker makes a store sensitive whatever its backup says")
check(stores.first { $0.name == "default" }?.values == ["GITHUB_TOKEN": "ci-dummy", "OTHER": "x"], "values decrypt with the master key")
check(throwsErr { _ = try CoreSetup.readBackups(dumps["jarvis2-backup-tampered"] ?? [], master: master, setupKey: setupKey) }, "a backup signed by another key is refused")
check(throwsErr { _ = try CoreSetup.readBackups(served, master: fresh, setupKey: setupKey) }, "another master key doesn't open the backups")
check(throwsErr { _ = try CoreSetup.readBackups(served + [served[0]], master: master, setupKey: setupKey) }, "a backup served twice is refused")
let nocore = try? CoreSetup.readBackups(dumps["jarvis2-backup-nocore"] ?? [], master: master, setupKey: setupKey)
check(nocore?.map(\.name) == ["default"] && (try? CoreSetup.bundle(nocore ?? [])) != nil, "backups without the core store still make a bundle (the token comes later)")

// ---- the offline copy (Settings → Encrypted backup): checked, never opened; tools/decrypt-backup.py opens the file (ios.yml)
let exportChecks = CoreSetup.checkSignatures(served, setupKey: setupKey)
check(exportChecks.count == served.count && exportChecks.allSatisfy { $0.problem == nil }, "the offline copy: every served object is signed by the setup key")
let tamperedChecks = CoreSetup.checkSignatures(dumps["jarvis2-backup-tampered"] ?? [], setupKey: setupKey)
check(tamperedChecks.filter { $0.problem != nil }.map(\.key) == ["stores/default.json"], "…and names the one that isn't (\(tamperedChecks.filter { $0.problem != nil }.map(\.key)))")
if let s0 = served.first(where: { $0.key.hasPrefix("stores/") }) {
  check(CoreSetup.checkSignatures(served + [s0], setupKey: setupKey).last?.problem == "Comes twice", "…a store served twice")
  let moved = CoreSetup.BackupObject(key: "stores/elsewhere.json", body: s0.body)
  check(CoreSetup.checkSignatures([moved], setupKey: setupKey).first?.problem == "Names another store", "…a backup under another store's key")
}
let exportAt = Date()
let exported = try! CoreSetup.exportFile(bucket: "jarvis2-backup-ci", objects: served, setupKey: setupKey, setupKeySource: "interop", fetchedAt: exportAt)
struct ExportBack: Decodable { let format: String; let version: Int; let bucket: String; let fetchedAt: String; let setupKey: String; let objects: [CoreSetup.BackupObject] }
let back = try? JSONDecoder().decode(ExportBack.self, from: exported)
check(back?.format == "jarvis2-backup-export" && back?.version == 1 && back?.setupKey == setupKey && back?.objects.map { $0.key + $0.body } == served.map { $0.key + $0.body },
      "the file holds the objects exactly as served, with the setup key")
check(CoreSetup.exportName(exportAt).hasPrefix("jarvis2-backup-") && CoreSetup.exportName(exportAt).hasSuffix(".json"), "the file's name (\(CoreSetup.exportName(exportAt)))")
if let out = env["INTEROP_EXPORT_OUT"] { try! exported.write(to: URL(fileURLWithPath: out)) }

// ---- Recover: the claim, signed with the kit's master key ----
let phoneSigning = P256.Signing.PrivateKey(), phoneAgreement = P256.KeyAgreement.PrivateKey()
let phone = PublicKeys(signingKey: phoneSigning.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgreement.publicKey.x963Representation.base64EncodedString())
// R2: the app wraps every store itself to the core's signed store key (P + K), so the core never sees their plaintext
let (sks, skd) = call("/store-key", ["phone": phone.agreementKey])
let recoverStoreKey = (try? CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: phone.agreementKey)) ?? ""
check(sks == 200 && !recoverStoreKey.isEmpty, "an empty core signs the store key for this phone (HTTP \(sks))")
check(throwsErr { _ = try CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: coreKeys.agreementKey) }, "…and the app refuses one for another phone")
let bundle = try! CoreSetup.blobsBundle(stores, storeKey: recoverStoreKey)
check(!String(decoding: bundle, as: UTF8.self).contains("FLY_API_TOKEN"), "the blobs bundle carries no store's values in the clear (the Fly token goes as flyToken)")
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
check(rec?.kind == "claimed" && rec?.stores == 5, "the answer is the core's signed 'claimed' (5 stores, the core's own excluded)")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)).0 == 409, "a second claim is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: fresh, bundle: try! CoreSetup.blobsBundle([], storeKey: recoverStoreKey))).0 == 409, "…and a Reset's claim with a new key too")
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
check(l.map(\.name) == ["claude-login", "default", "github-deploy-keys", "gmail", "marked"], "the core lists every store but its own")
check(l.filter(\.sensitive).map(\.name) == ["github-deploy-keys", "gmail", "marked"], "sensitivity in the core's list")
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

// ---- an unlock for one session (a Start's challenge, a waiting session's cert): signed with what it is for, read
// only by that cert's pull, never shown as open to every session ----
let sdoc = try! CoreCrypto.decode(doc(call("/stores", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: StoresDoc.self, what: "stores")
check(sdoc.kind == "stores", "the core's signed store list")
let forN = String(repeating: "ab", count: 32)
let sb = try! CoreCrypto.decode(doc(call("/unlock/begin", ["store": "gmail", "for": forN]).1), by: coreKey, as: UnlockBegin.self, what: "unlock-begin for one session")
check(sb.kind == "unlock-begin" && sb.forNonce == forN, "unlock-begin names the one session it is for (signed)")
let (ss, sd) = call("/unlock/finish", ["pending": sb.pending, "share": try! CoreCrypto.sealShare(try! realShare(sb), to: sb.t)])
let su = try? CoreCrypto.decode(doc(sd), by: coreKey, as: KindDoc.self, what: "unlocked")
check(ss == 200 && su?.kind == "unlocked", "the core opens it for that session")
check(list().first { $0.name == "gmail" }?.unlocked == false, "…and the store list doesn't show it as open to every session")
let ul2 = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul2?.unlocked.first { $0.id == su?.id }?.forNonce == forN && ul2?.unlocked.first { $0.id == u?.id }.map { ($0.forNonce ?? "").isEmpty } == true, "the unlocked list says which unlock is for one session and which is standing")
let slk = try? CoreCrypto.decode(doc(call("/lock", ["id": su?.id ?? ""]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(slk?.kind == "locked", "an unlock for one session can be locked by hand too")
check(SignedAction.value(SignedAction.unlock(stores: ["gmail"], session: nil, scoped: true), "unlock-scope") == "This session only", "the review page says the unlock is for this session only")

// ---- approvals: the challenge before any machine ----
/// as the router asks: a new line carries its random salt (the core takes exact values, no defaults)
func challenge(_ body: [String: Any]) -> SignedDoc {
  var body = body
  if body["predecessor"] is NSNull { body["salt"] = CoreCrypto.nonce() }
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
struct CreatedDoc: Codable { let kind: String; let id: String }
/// start = one Fly create, then init reads the machine's keys (the router retries init; the fake Fly is up at once)
func start(_ image: String) -> (machine: StartedMachine, started: SignedDoc) {
  let created = try! CoreCrypto.decode(doc(call("/start", ["image": image, "region": "lhr", "size": "small"]).1), by: coreKey, as: CreatedDoc.self, what: "start")
  let d = doc(call("/init", ["machine": created.id]).1)
  return (try! CoreCrypto.decode(d, by: coreKey, as: StartedDoc.self, what: "init").machine, d)
}

// the core starts only the session image pinned by digest (core/vouch.go)
let img = "ghcr.io/de0ch/jarvis2-session:1@sha256:" + String(repeating: "1", count: 64)
let img2 = "ghcr.io/de0ch/jarvis2-session:2@sha256:" + String(repeating: "2", count: 64)

// a core that vouches for inputs carries the session's settings in the challenge; the page checks them and refuses
// a key it can't show
let conf = #"{"v":1,"label":"T","prompt":"do it","repos":["https://github.com/DE0CH/claude-env.git"],"oneShot":true}"#
let chC = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": conf], "image": img])
let rC = try! Checks.review(challenge: chC, coreKey: coreKey)
check((rC.config?["prompt"] as? String) == "do it", "the signed settings are read from the challenge")
let picked = Checks.Settings(label: "T", prompt: "do it", model: "", repos: ["https://github.com/DE0CH/claude-env.git"], oneShot: true, apiProxy: false)
check(!throwsErr { try Checks.matchesSettings(rC, picked) }, "the settings match what the page chose")
var other = picked; other.prompt = "exfiltrate"
check(throwsErr { try Checks.matchesSettings(rC, other) }, "refused when the signed prompt isn't the page's")
other = picked; other.repos = []
check(throwsErr { try Checks.matchesSettings(rC, other) }, "refused when the signed repos aren't the page's")
check(SignedAction.value(SignedAction.approval(rC), "prompt") == "do it" && SignedAction.value(SignedAction.approval(rC), "title") == "T", "what you sign shows the settings word for word")
// attachments: exactly the files this phone uploaded, by the hash and size of its own bytes, in order
let hA = String(repeating: "a", count: 64), hB = String(repeating: "b", count: 64)
let confA = #"{"v":1,"prompt":"look","attachments":[{"name":"photo.jpg","sha256":"\#(hA)","size":3},{"name":"b.png","sha256":"\#(hB)","size":5}]}"#
let rA = try! Checks.review(challenge: challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": confA], "image": img]), coreKey: coreKey)
var pickedA = Checks.Settings(label: "", prompt: "look", model: "", repos: [], oneShot: false, apiProxy: false,
                              attachments: [.init(name: "photo.jpg", sha256: hA, size: 3), .init(name: "b.png", sha256: hB, size: 5)])
check(!throwsErr { try Checks.matchesSettings(rA, pickedA) }, "the signed attachments are the ones this phone uploaded")
check(Checks.attachments(rA.config ?? [:]) == pickedA.attachments, "the approval page reads the signed attachments")
pickedA.attachments[0].sha256 = hB
check(throwsErr { try Checks.matchesSettings(rA, pickedA) }, "refused when a signed hash isn't of this phone's bytes")
pickedA.attachments = [pickedA.attachments[1]]
check(throwsErr { try Checks.matchesSettings(rA, pickedA) }, "refused when the router added an attachment")
check(throwsErr { try Checks.matchesSettings(rC, Checks.Settings(label: "T", prompt: "do it", model: "", repos: ["https://github.com/DE0CH/claude-env.git"], oneShot: true, apiProxy: false, attachments: [.init(name: "x.png", sha256: hA, size: 1)])) },
      "refused when the router dropped the attachments")
let chBadA = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": #"{"v":1,"attachments":[{"name":"x.png","sha256":"\#(hA)","size":1,"path":"/etc"}]}"#], "image": img])
check(throwsErr { _ = try Checks.review(challenge: chBadA, coreKey: coreKey) }, "an attachment with a field the app can't show is refused")
let chX = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": #"{"v":1,"evil":"x"}"#], "image": img])
check(throwsErr { _ = try Checks.review(challenge: chX, coreKey: coreKey) }, "a setting the app can't show is refused")

// new session
let ch1 = challenge(["predecessor": NSNull(), "stores": ["claude-login", "default"], "options": ["harness": "claude", "permissionMode": "bypass"], "image": img])
let r1 = try! Checks.review(challenge: ch1, coreKey: coreKey)
check(r1.kind == .newSession && r1.stores == ["claude-login", "default"] && r1.harness == "claude" && r1.image == img, "new-session challenge read from its own fields")
check(r1.permissionMode == "bypass", "the permission mode is read from the signed challenge (\(r1.permissionMode))")
check(!throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "matches what was picked plus the harness's store")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default", "gmail"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "refused when the stores differ")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "opencode", permissionMode: "bypass") }, "refused when the harness differs")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "auto") }, "refused when the permission mode differs")
check(call("/succession", ["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude"], "image": img, "salt": CoreCrypto.nonce()]).0 == 400, "the core refuses a request without a mode (the router fills it in)")
check(throwsErr { _ = try Checks.review(challenge: SignedDoc(payload: ch1.payload, sig: try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()), coreKey: coreKey) }, "a challenge not signed by the core is refused")
let forged = try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()
check(call("/approve/by-phone", ["challenge": docJSON(ch1), "signature": forged]).0 == 403, "the core refuses a signature by another key")
let (a1s, a1) = approve(ch1)
check(a1s == 200 && !throwsErr { try Checks.answerFor(r1, answer: a1!, coreKey: coreKey) }, "the phone's signature → the core's approval")
let m1run = start(img)
let m1 = m1run.machine
let (c1s, c1d) = call("/certify", ["approval": docJSON(a1!), "started": docJSON(m1run.started)])
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
let chT = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "task:hello", "permissionMode": "auto"], "image": img])
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
check(r2.kind == .addStore && r2.addedStore == "gmail" && list().first { $0.name == "gmail" }?.sensitive == true, "add-store challenge: one more store, marked sensitive in the core's store list")
let (a2s, a2) = approve(ch2)
check(a2s == 200 && !throwsErr { try Checks.answerFor(r2, answer: a2!, coreKey: coreKey) }, "adding a store answers with the machine's new succession cert")
check(throwsErr { try Checks.answerFor(r2, answer: a1!, coreKey: coreKey) }, "another answer is refused")

// resume on the latest image: approval first, then the machine
check(call("/kill", ["machine": m1.id]).0 == 200, "kill the machine (pause)")
let ch3 = challenge(["predecessor": docJSON(a2!), "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude", "permissionMode": "auto"], "image": img2])
let r3 = try! Checks.review(challenge: ch3, coreKey: coreKey)
check(r3.kind == .resumeUpgrade && r3.image == img2 && r3.permissionMode == "auto", "resume-upgrade challenge read from its own fields (mode \(r3.permissionMode))")
let (a3s, a3) = approve(ch3)
check(a3s == 200 && !throwsErr { try Checks.answerFor(r3, answer: a3!, coreKey: coreKey) }, "the phone approves the resume")
let m2 = start(img2)
check(call("/certify", ["approval": docJSON(a3!), "started": docJSON(m2.started)]).0 == 200, "…and the new machine is certified")

// a sensitive line: no standing rule
let ch4 = challenge(["predecessor": NSNull(), "stores": ["gmail"], "options": ["harness": "claude", "permissionMode": "auto"], "image": img])
let (a4s, a4) = approve(ch4)
let (c4s, c4d) = a4 == nil ? (0, Data()) : call("/certify", ["approval": docJSON(a4!), "started": docJSON(start(img).started)])
if a4s == 200, c4s == 200, let sc4 = try? Checks.cert(doc(c4d), coreKey: coreKey) {
  check(sc4.sensitive == true, "a session with a sensitive store has a sensitive cert")
  var r4 = rule; r4["session"] = sc4.line
  check(!review(r4, kind: "rule", until: end, cert: sc4), "…and the grant page refuses a standing rule for it")
} else { check(false, "a sensitive session certifies") }

// ---- deploy keys: a repo added and removed, each approved by the phone (the core's fake GitHub in CI) ----
/// the begin body the app sends (RouterClient.deployKeyBegin): the store and title it names, and for an add the key
/// pair it made, the private half's store wrapped to the store key
func keyBegin(_ action: String, _ repo: String, sensitive: Bool) -> ([String: Any], (publicKey: String, blob: StoreBlob)?) {
  let store = Checks.repoStore(repo), title = "jarvis2 " + store
  var body: [String: Any] = ["action": action, "repo": repo, "sensitive": sensitive, "store": store, "title": title]
  guard action == "add" else { return (body, nil) }
  let kp = try! OpenSSH.ed25519(comment: title)
  let blob = try! CoreCrypto.wrapStore(name: store, values: OpenSSH.storeValues(repo: repo, privateKeyFile: kp.privateKeyFile), storeKey: recoverStoreKey)
  body["publicKey"] = kp.publicKey
  body["blob"] = blob.json
  return (body, (publicKey: kp.publicKey, blob: blob))
}
func deployKey(_ action: String, _ repo: String, sensitive: Bool = false, signer: P256.Signing.PrivateKey? = nil, base: String = core, prefix: String = "/deploy-keys") -> (Int, DeployKeyBegin?, Data) {
  let (body, sent) = keyBegin(action, repo, sensitive: sensitive)
  let (bs, bd) = call(prefix + "/begin", body, base: base)
  guard bs == 200, let d = try? JSONDecoder().decode(SignedDoc.self, from: bd) else { return (bs, nil, bd) }
  guard let b = try? Checks.deployKeyBegin(d, coreKey: coreKey, action: action, repo: repo, sensitive: sensitive, sent: sent) else { return (0, nil, bd) }
  let sig = try! (signer ?? phoneSigning).signature(for: Data(d.payload.utf8)).derRepresentation.base64EncodedString()
  let x = try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
  let (fs, fd) = call(prefix + "/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(x, to: b.t)], base: base)
  return (fs, b, fd)
}
check(Checks.repoStore("DE0CH/china_train") == "github-china-train" && Checks.repoStore("someone/Thing.js") == "github-someone-thing-js" && Checks.repoStore("de0ch/Jarvis2") == "github-jarvis2", "the app's store names are the core's")
let (dk1s, dk1b, dk1d) = deployKey("add", "DE0CH/china-train")
let dk1 = dk1b.flatMap { try? Checks.deployKeyAnswer(doc(dk1d), coreKey: coreKey, begin: $0) }
check(dk1s == 200 && dk1?.kind == "deploy-key-added" && dk1?.store == "github-china-train" && dk1?.sensitive == false && dk1?.publicKey != nil && dk1?.publicKey == dk1b?.publicKey, "add a repo: the core adds the app's key, the store github-china-train (HTTP \(dk1s))")
check(list().first { $0.name == "github-china-train" }.map { !$0.sensitive && !$0.empty && !$0.unlocked } == true, "…the repo's store: not sensitive, with contents, locked")
check(list().first { $0.name == "github-deploy-keys" }?.unlocked == false, "…and the token store was opened for that call only")
// Jarvis 2's own repo: the app always asks for it sensitive (RepoKeyView) and refuses a begin that isn't (the core
// takes what is asked)
let (bjBody, bjSent) = keyBegin("add", "DE0CH/jarvis2", sensitive: true)
let (bjs, bjd) = call("/deploy-keys/begin", bjBody)
let bj = bjs == 200 ? try? Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "add", repo: "DE0CH/jarvis2", sensitive: true, sent: bjSent) : nil
check(bj?.sensitive == true && bj?.store == "github-jarvis2", "Jarvis 2's own repo asked for sensitive: the begin document says so before Face ID")
let (bnBody, bnSent) = keyBegin("add", "DE0CH/jarvis2", sensitive: false)
let (bns, bnd) = call("/deploy-keys/begin", bnBody)
check(bns == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bnd), coreKey: coreKey, action: "add", repo: "DE0CH/jarvis2", sensitive: false, sent: bnSent) }, "…and the app refuses a begin for it that isn't sensitive")
check(bjs == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "remove", repo: "DE0CH/jarvis2", sensitive: false) }, "the page refuses a begin for another action")
// the Inbox review's "What you sign (exact)" is rendered from this signed document
let bjFacts = bj.map(SignedAction.deployKey) ?? []
check(SignedAction.value(bjFacts, "repo") == "DE0CH/jarvis2" && SignedAction.value(bjFacts, "store") == "github-jarvis2" && SignedAction.value(bjFacts, "sensitive") == "Yes"
      && SignedAction.value(bjFacts, "token-store") == "github-deploy-keys", "the signed action renders from the core's begin document: \(bjFacts.map { "\($0.id)=\($0.value)" })")
check(bjs == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "add", repo: "DE0CH/claude-env", sensitive: false) }, "…or another repo")
check(deployKey("add", "DE0CH/x", signer: P256.Signing.PrivateKey()).0 == 403, "a signature by another key is refused")
let (nas, _, nad) = deployKey("add", "DE0CH/no-admin")
check(nas == 502 && String(decoding: nad, as: UTF8.self).contains("github: HTTP 403"), "a token GitHub refuses: the core says what GitHub said (HTTP \(nas))")
let (nrs, _, nrd) = deployKey("add", "DE0CH/no-admin", base: need("INTEROP_ROUTER"), prefix: "/api/repos/key")
check(nrs == 502 && String(decoding: nrd, as: UTF8.self).contains("Administration: read and write"), "…and the router names the permission it needs (HTTP \(nrs))")
let (rms, rmb, rmd) = deployKey("remove", "DE0CH/china-train")
check(rms == 200 && rmb.flatMap { try? Checks.deployKeyAnswer(doc(rmd), coreKey: coreKey, begin: $0) }?.kind == "deploy-key-removed", "remove: the key and the store go")
check(!list().contains { $0.name == "github-china-train" }, "…the store is gone from the core's list")
// through the router (Settings → Repos): the list follows the core's answer
// ---- R2: the app makes the key pair and wraps its store; the core adds that key and keeps that blob ----
struct SSHVector: Decodable { let seedHex: String; let checkint: String; let comment: String; let publicKey: String; let privateKeyFile: String; let storeValue: String }
if let vb = FileManager.default.contents(atPath: "testdata/openssh-ed25519.json"), let v = try? JSONDecoder().decode(SSHVector.self, from: vb) {
  let seed = Data(stride(from: 0, to: v.seedHex.count, by: 2).map { i in UInt8(v.seedHex[v.seedHex.index(v.seedHex.startIndex, offsetBy: i)..<v.seedHex.index(v.seedHex.startIndex, offsetBy: i + 2)], radix: 16)! })
  let kv = try? OpenSSH.ed25519(comment: v.comment, seed: seed, checkint: UInt32(v.checkint, radix: 16))
  check(kv?.publicKey == v.publicKey && kv?.privateKeyFile == v.privateKeyFile, "the app's OpenSSH key matches the core's vector")
  check(OpenSSH.storeValues(repo: "DE0CH/china-train", privateKeyFile: v.privateKeyFile)["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"] == v.storeValue, "…and its store value")
} else {
  check(false, "the OpenSSH vector (testdata/openssh-ed25519.json) is readable")
}
let kp = try! OpenSSH.ed25519(comment: "jarvis2 github-r2-app")
let skNow = try! CoreCrypto.storeKey(doc(call("/store-key", ["phone": phone.agreementKey]).1), coreKey: coreKey, phone: phone.agreementKey)
let appBlob = try! CoreCrypto.wrapStore(name: "github-r2-app", values: OpenSSH.storeValues(repo: "DE0CH/r2-app", privateKeyFile: kp.privateKeyFile), storeKey: skNow)
let (abStatus, abd) = call("/deploy-keys/begin", ["action": "add", "repo": "DE0CH/r2-app", "sensitive": false, "store": "github-r2-app",
                                             "title": "jarvis2 github-r2-app", "publicKey": kp.publicKey, "blob": appBlob.json])
let abeg = abStatus == 200 ? try? Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: (kp.publicKey, appBlob)) : nil
check(abeg != nil, "the core's begin names the app's public key and blob (HTTP \(abStatus))")
let otherBlob = try! CoreCrypto.wrapStore(name: "github-r2-app", values: ["X": "y"], storeKey: skNow)
check(abStatus == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: (kp.publicKey, otherBlob)) }, "…the page refuses a begin naming another blob")
if let b = abeg {
  let sig = try! phoneSigning.signature(for: Data(doc(abd).payload.utf8)).derRepresentation.base64EncodedString()
  let x = try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
  let (afs, afd) = call("/deploy-keys/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(x, to: b.t)])
  let a = try? Checks.deployKeyAnswer(doc(afd), coreKey: coreKey, begin: b)
  check(afs == 200 && a?.kind == "deploy-key-added" && a?.publicKey == kp.publicKey && a?.store == "github-r2-app", "the core added the app's key (HTTP \(afs))")
  check(unlock("github-r2-app", share: realShare).0 == 200, "…and the app-wrapped store opens with the phone's share")
}

let rbase = need("INTEROP_ROUTER")
struct ReposDTO: Decodable { struct R: Decodable { let name: String; let repo: String; let store: String; let sensitive: Bool? }; let repos: [R] }
let (ras, _, _) = deployKey("add", "DE0CH/claude-env", base: rbase, prefix: "/api/repos/key")
let rl = try? JSONDecoder().decode(ReposDTO.self, from: call("/api/repos", base: rbase).1)
check(ras == 200 && rl?.repos.map(\.repo) == ["DE0CH/claude-env"] && rl?.repos.first?.store == "github-claude-env", "through the router: the repo is on the list with its store")
_ = deployKey("remove", "DE0CH/claude-env", base: rbase, prefix: "/api/repos/key")
check((try? JSONDecoder().decode(ReposDTO.self, from: call("/api/repos", base: rbase).1))?.repos.isEmpty == true, "…and off it after remove")

// ---- the Inbox (router/inbox.go): a request filed through an intent endpoint opens the same review page ----
let (qs, qd) = call("/api/requests/repo/add", ["repo": "https://github.com/DE0CH/claude-env", "explanation": "for the skill"], base: rbase)
let qid = ((try? JSONSerialization.jsonObject(with: qd)) as? [String: Any])?["id"] as? String ?? ""
let (gs, gd) = call("/api/requests/" + qid, base: rbase)
let qi = (try? JSONSerialization.jsonObject(with: gd)) as? [String: Any] ?? [:]
let qopen = qi["open"] as? [String: Any] ?? [:], qopts = qopen["options"] as? [String: Any] ?? [:]
let qcall = qi["call"] as? [String: Any] ?? [:]
check(qs == 200 && gs == 200 && qopen["kind"] as? String == "repo-key" && qopts["repo"] as? String == "DE0CH/claude-env" && qopts["inboxId"] as? String == qid, "a filed request opens the repo-key page for that repo (HTTP \(qs) \(gs))")
check(SignedAction.mismatch(page: qopts.merging(["kind": "repo-key", "requestId": "x"]) { a, _ in a }, request: qopts) == "", "…its options match the page's")
check(SignedAction.mismatch(page: qopts.merging(["repo": "DE0CH/other"]) { _, b in b }, request: qopts) == "repo", "…a page for another repo shows the mismatch")
check(SignedAction.call(method: qcall["method"] as? String ?? "", path: qcall["path"] as? String ?? "", args: qcall["args"] as? [String: Any]) == #"POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}"#, "…the API call as the review shows it")
check(qi["explanation"] as? String == "for the skill" && (qi["callerText"] as? String ?? "") != "", "…with the caller's words and who called")
check(call("/api/requests/" + qid + "/done", [String: Any](), base: rbase).0 == 200 && call("/api/requests/" + qid, base: rbase).0 == 404, "…and done takes it out of the Inbox")

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
check(call("/identity").0 == 0, "…and the core process is gone (Kubernetes starts a new, empty one)")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
