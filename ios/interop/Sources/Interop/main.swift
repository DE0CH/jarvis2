// The app's CoreCrypto + CoreSetup + StoreRestore + SignedAction against the REAL secrets binary (core/cmd/secrets,
// fakefly build: an in-memory GitHub; a throwaway box key) and the backups as the router serves them (a router on the
// runner, SECRETS_URL the stand-in, reading a local S3 stand-in that infra/setup.py's own code seeded, ios/ci/standin.py):
// secrets' identity and signed state (empty, then set up), the recovery kit string (round trip, the old version
// refused), reading + checking + decrypting the backups with the kit's master key, Recover itself (the claim, naming the
// phone and root keys), the signed store list (sensitivity), create / mark sensitive, split-key unlock per store (open
// until locked), key backups laid over the whole-store backups (setup-written, router- and session-written as the
// router's word, deleted, older, restored), per-key writers on unlock (a setup-signed key written through the router
// unlocks; a key sealed under another name doesn't; a session's write is shown or refused), restore, deploy keys, the
// Inbox, and Reset's wipe at the end — and the refusals: a box signature by another key, a state not signed by secrets,
// a tampered backup, a wrong master key, a claim for another secrets or bundle or signed by another key, a second claim,
// a forged phone signature, a wrong share, a wipe by another key. The kernel's succession certs and grants (approvals,
// the root grant) are the Golden target's (core/kernel/testdata).
// Configuration (env): INTEROP_CORE (secrets), INTEROP_ROUTER (its /api/backups reads the stand-in bucket
// jarvis2-backup-ci), INTEROP_KEYS (the dir with box.pub + setup.pub), INTEROP_BACKUPS (standin.py's dump: {bucket:
// [{key, body}]}), INTEROP_MASTER_PEM (e2e/testdata/master-test.pem), INTEROP_EXPORT_OUT (optional: where the offline
// copy's file goes).
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
/// the setup session's private key (standin.py writes it next to keys/): signs the keys written as the setup session
let setupSigner = try! P256.Signing.PrivateKey(pemRepresentation: try! String(contentsOfFile: keysDir + "/../setup-key.pem", encoding: .utf8))
let phoneSigningForTests = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }

func call(_ path: String, _ body: Any? = nil, base: String = core, method: String = "POST") -> (Int, Data) {
  var r = URLRequest(url: URL(string: base + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = method; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
func docJSON(_ d: SignedDoc) -> [String: String] { ["payload": d.payload, "sig": d.sig] }

// ---- secrets' identity: box-signed keys, its own signed state ----
func identity() -> CoreSetup.Identity { try! JSONDecoder().decode(CoreSetup.Identity.self, from: call("/identity").1) }
func stateDoc() -> SignedDoc { doc(call("/state", [String: Any]()).1) }
let id0 = identity()
let checked = try? CoreSetup.check(id0, state: stateDoc(), boxKey: boxKey)
check(checked != nil && id0.role == "secrets", "secrets' keys are signed by the box key (as the secrets role) and its state by secrets")
let coreKeys = checked?.keys ?? PublicKeys(signingKey: "", agreementKey: "")
check(checked?.state.master == "" && checked?.state.phone == nil, "a new secrets is empty")
check(throwsErr { _ = try CoreSetup.check(id0, state: stateDoc(), boxKey: setupKey) }, "…not with another box key")
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(role: "secrets", signingKey: id0.agreementKey, agreementKey: id0.signingKey, boxSig: id0.boxSig), state: stateDoc(), boxKey: boxKey) }, "…not for other keys")
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(role: "notary", signingKey: id0.signingKey, agreementKey: id0.agreementKey, boxSig: id0.boxSig), state: stateDoc(), boxKey: boxKey) }, "…not as another part")
let otherSigner = P256.Signing.PrivateKey()
let st0 = stateDoc()
let forgedState = SignedDoc(payload: st0.payload, sig: try! otherSigner.signature(for: Data(st0.payload.utf8)).derRepresentation.base64EncodedString())
check(throwsErr { _ = try CoreSetup.check(id0, state: forgedState, boxKey: boxKey) }, "…not with a state secrets didn't sign")

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
check(nocore?.map(\.name) == ["default"] && (try? CoreSetup.keysBundle(nocore ?? [], storeKey: master.publicKey)) != nil, "backups without the core store still make a bundle (the token comes later)")

// ---- key backups (keys/<store>/<key>.json, router/storedocs.go) laid over the whole-store ones ----
let keyObjs = dumps["jarvis2-backup-keys"] ?? []
check(keyObjs.count == 7, "the stand-in key backups (\(keyObjs.map(\.key)))")
let merged: [RecoveredStore]
do { merged = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey, boxKey: boxKey) } catch { print("FAIL reading the key backups: \(error)"); exit(1) }
let mDefault = merged.first { $0.name == "default" }
check(mDefault?.values == ["OTHER": "y", "RESTORED": "r1", "SESSION_KEY": "from-a-session"], "a later key backup replaces its key, a deleted one removes it, an older one is ignored (\(mDefault?.values.keys.sorted() ?? []))")
check(mDefault?.sensitive == false, "…and the store keeps its whole-store backup's sensitivity")
check(merged.first { $0.name == "keyed-only" }.map { $0.values == ["API_KEY": "k1"] && $0.sensitive } == true, "a store only key backups name comes back, sensitive")
check(merged.first { $0.name == "claude" }?.values == ["CLAUDE_CREDENTIALS": "{}"], "a key the router wrote itself (the Claude login) comes back: its word")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey) }, "a restored key backup isn't taken without the box key to check its secrets")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey, boxKey: setupKey) }, "…nor with a secrets another key vouched for")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: fresh, setupKey: setupKey, boxKey: boxKey) }, "another master key doesn't open the key backups")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs + [keyObjs[0]], master: kitMaster, setupKey: setupKey, boxKey: boxKey) }, "a key backup served twice is refused")
/// one key backup's JSON, changed
func alter(_ o: CoreSetup.BackupObject, key: String? = nil, _ fn: (inout [String: Any]) -> Void) -> CoreSetup.BackupObject {
  var j = (try? JSONSerialization.jsonObject(with: Data(o.body.utf8))) as? [String: Any] ?? [:]
  fn(&j)
  return CoreSetup.BackupObject(key: key ?? o.key, body: String(decoding: try! JSONSerialization.data(withJSONObject: j), as: UTF8.self))
}
let setupObj = keyObjs.first { $0.key == "keys/default/OTHER.json" }!, machineObj = keyObjs.first { $0.key == "keys/default/SESSION_KEY.json" }!
let restoreObj = keyObjs.first { $0.key == "keys/default/RESTORED.json" }!
check(!throwsErr { _ = try CoreSetup.checkKeyBackup(setupObj, setupKey: setupKey, boxKey: boxKey) } && !throwsErr { _ = try CoreSetup.checkKeyBackup(machineObj, setupKey: setupKey, boxKey: boxKey) },
      "a setup-written and a session-written key backup check (the session's: the router's word)")
check(!throwsErr { _ = try CoreSetup.checkKeyBackup(restoreObj, setupKey: setupKey, boxKey: boxKey) }, "…and one a phone-approved restore put back (secrets' receipt)")
let refusals: [(String, CoreSetup.BackupObject)] = [
  ("moved to another key", CoreSetup.BackupObject(key: "keys/default/ELSEWHERE.json", body: setupObj.body)),
  ("moved to another store", CoreSetup.BackupObject(key: "keys/gmail/OTHER.json", body: setupObj.body)),
  ("naming another key", alter(setupObj) { $0["key"] = "ELSEWHERE" }),
  ("another sealed value", alter(setupObj) { $0["sealed"] = (try? JSONSerialization.jsonObject(with: Data(machineObj.body.utf8)) as? [String: Any])?["sealed"] }),
  ("its hash changed", alter(setupObj) { $0["backupSha256"] = String(repeating: "0", count: 64) }),
  ("signed by another key", alter(setupObj) { $0["writer"] = ["by": "setup", "sig": (try! P256.Signing.PrivateKey().signature(for: Data("x".utf8))).derRepresentation.base64EncodedString()] }),
  ("a session's write naming no machine", alter(machineObj) { $0["writer"] = ["by": "machine", "sig": "", "machine": ""] }),
  ("a restore receipt of a secrets another key vouched for", alter(restoreObj) { var c = $0["secrets"] as! [String: Any]; c["signingKey"] = phoneSigningForTests; $0["secrets"] = c }),
  ("a restore receipt naming another value", alter(restoreObj) { $0["e"] = (try? JSONSerialization.jsonObject(with: Data(setupObj.body.utf8)) as? [String: Any])?["e"] }),
  ("a restore receipt passed off as a delete", alter(restoreObj) { $0["deleted"] = true; $0["sealed"] = NSNull(); $0["e"] = ""; $0["dataSha256"] = ""; $0["backupSha256"] = "" }),
  ("an unknown writer", alter(setupObj) { var w = $0["writer"] as! [String: Any]; w["by"] = "core"; $0["writer"] = w }),
  ("a delete that carries a value", alter(setupObj) { $0["deleted"] = true }),
]
for (what, o) in refusals {
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey) }, "a key backup \(what) is refused")
}
let movedOpen: Bool = {
  // the sealed value of OTHER under SESSION_KEY's name (re-signed would still fail: the associated data is the name)
  do { _ = try CoreCrypto.open((try JSONSerialization.jsonObject(with: Data(setupObj.body.utf8)) as! [String: Any])["sealed"] as! [String: String], with: kitMaster.agreement, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: "default", key: "SESSION_KEY")); return true } catch { return false }
}()
check(!movedOpen, "a key's sealed value doesn't open under another key's name")
let keyChecks = CoreSetup.checkSignatures(served + keyObjs, setupKey: setupKey, boxKey: boxKey)
check(keyChecks.allSatisfy { $0.problem == nil }, "the offline copy checks key backups too (\(keyChecks.filter { $0.problem != nil }.map { "\($0.key): \($0.problem!)" }))")

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
// the app wraps every store itself to secrets' signed store key (P + K), so secrets never sees their plaintext
let (sks, skd) = call("/store-key", ["phone": phone.agreementKey])
let recoverStoreKey = (try? CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: phone.agreementKey)) ?? ""
check(sks == 200 && !recoverStoreKey.isEmpty, "an empty secrets signs the store key for this phone (HTTP \(sks))")
check(throwsErr { _ = try CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: coreKeys.agreementKey) }, "…and the app refuses one for another phone")
check((try? CoreCrypto.decode(stateDoc(), by: coreKeys.signingKey, as: [String: String?].self, what: "state"))?["bundle"] == "keys", "secrets' state says it takes stores of keys")
let bundle = try! CoreSetup.keysBundle(merged, storeKey: recoverStoreKey)
let bundleText = String(decoding: bundle, as: UTF8.self)
check(!bundleText.contains("FLY_API_TOKEN") && !bundleText.contains("ci-dummy") && !bundleText.contains("from-a-session") && !bundleText.contains("flyToken") && bundleText.contains(#""format":"keys""#),
      "the keys bundle carries no value in the clear, and no Fly token (the spawner's, from the setup session)")
check(call("/claim", try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: Data(#"{"format":"blobs"}"#.utf8))).0 == 400, "secrets refuses a bundle in another format")
let rootPub = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
let stRoot = try! CoreSetup.statement(master: kitMaster.publicKey, core: coreKeys, phone: phone, bundle: bundle, root: rootPub, device: phoneSigningForTests)
check((try? JSONSerialization.jsonObject(with: Data(stRoot.utf8)) as? [String: Any])?["root"] as? String == rootPub, "the claim statement names the root key (master-signed, for the roster)")
func claim(_ body: [String: Any]) -> (Int, Data) { call("/claim", body) }
var bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)
bad["masterSig"] = try! fresh.sign(bad["statement"] as! String)
check(claim(bad).0 == 403, "a claim signed by another key than the master key it names is refused")
bad = try! CoreSetup.claim(core: phone, phone: phone, master: kitMaster, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle, to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a claim naming another secrets is refused")
bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)
bad["bundle"] = try! CoreCrypto.seal(bundle + Data(" ".utf8), to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a bundle other than the signed one is refused")
check(call("/wipe", try! CoreSetup.wipe(core: coreKeys, master: kitMaster)).0 == 409, "an empty secrets can't be wiped")
let (rs, rb) = claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, root: rootPub))
check(rs == 200, "secrets is set up (HTTP \(rs) \(String(decoding: rb.prefix(200), as: UTF8.self)))")
let rec = try? CoreCrypto.decode(doc(rb), by: coreKeys.signingKey, as: KindDoc.self, what: "claimed")
check(rec?.kind == "claimed" && rec?.stores == 7, "the answer is secrets' signed 'claimed' (7 stores, the core store excluded)")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)).0 == 409, "a second claim is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: fresh, bundle: try! CoreSetup.keysBundle([], storeKey: recoverStoreKey))).0 == 409, "…and a Reset's claim with a new key too")
let st1 = (try? CoreSetup.check(identity(), state: stateDoc(), boxKey: boxKey))?.state
check(st1 != nil && CoreSetup.status(st1!, myMaster: kitMaster.publicKey, myPhone: phone) == .mine, "secrets' state now names this master key and this phone (mine)")
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
check(l.map(\.name) == ["claude", "claude-login", "default", "github-deploy-keys", "gmail", "keyed-only", "marked"], "secrets lists every store but the core store")
check(l.filter(\.sensitive).map(\.name) == ["claude", "github-deploy-keys", "gmail", "keyed-only", "marked"], "sensitivity in secrets' list")
check(throwsErr { _ = try CoreCrypto.verified(SignedDoc(payload: "{}", sig: doc(call("/stores", ["nonce": "x"]).1).sig), by: coreKey, what: "x") }, "an altered payload is refused")
check(call("/stores/create", ["name": "notes"]).0 == 200, "create a store")
check(call("/stores/create", ["name": "notes"]).0 == 409, "…once")
l = list()
check(l.first { $0.name == "notes" }.map { !$0.sensitive && $0.empty } == true, "a created store is empty and not sensitive")
let mk = try? CoreCrypto.decode(doc(call("/stores/mark-sensitive", ["name": "notes"]).1), by: coreKey, as: KindDoc.self, what: "mark")
check(mk?.kind == "marked-sensitive" && mk?.name == "notes", "mark sensitive")
check(call("/stores/mark-sensitive", ["name": "notes"]).0 == 409, "…one way")

// ---- split-key unlock: one share per key, each key's writer checked ----
func begin(_ store: String) -> (Int, UnlockBegin?) {
  let (s, d) = call("/unlock/begin", ["store": store])
  return (s, s == 200 ? try? CoreCrypto.decode(doc(d), by: coreKey, as: UnlockBegin.self, what: "unlock-begin") : nil)
}
func shareOf(_ e: String) -> Data {
  try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: e)!)).withUnsafeBytes { Data($0) }
}
/// unlock_finish as RouterClient.unlockFinish sends it: {pending, shares: {KEY: share sealed to T}}
func finish(_ b: UnlockBegin, share: (String) -> Data = shareOf) -> (Int, Data) {
  var m: [String: Any] = [:]
  for k in b.keys { m[k.key] = try! CoreCrypto.sealShare(share(k.e), to: b.t) }
  return call("/unlock/finish", ["pending": b.pending, "shares": m])
}
func unlock(_ store: String, share: @escaping (String) -> Data = shareOf) -> (Int, Data) {
  let (s, b) = begin(store)
  guard let b else { return (s, Data()) }
  check(b.kind == "unlock-begin" && b.store == store && !b.keys.isEmpty, "unlock-begin for \(store) is signed and names its keys (\(b.keys.map(\.key)))")
  return finish(b, share: share)
}
let (dbs, db) = begin("default")
check(dbs == 200 && db?.keys.map(\.key) == ["OTHER", "RESTORED", "SESSION_KEY"] && db?.keys.allSatisfy { $0.writer.by == "core" } == true && db?.version?.isEmpty == false,
      "a recovered store's keys are secrets' to vouch for (\(db?.keys.map { "\($0.key):\($0.writer.by)" } ?? []))")
check(db.map { x in !throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…and the app takes them")
let (us, ub) = db.map { finish($0) } ?? (0, Data())
check(us == 200, "secrets opens every key of the recovered store with the phone's sealed shares (HTTP \(us) \(String(decoding: ub.prefix(160), as: UTF8.self)))")
let u = try? CoreCrypto.decode(doc(ub), by: coreKey, as: KindDoc.self, what: "unlocked")
check(u?.kind == "unlocked" && u?.store == "default", "unlocked answer is signed")
check(unlock("gmail") { _ in Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }.0 != 200, "a wrong share doesn't open a store")
check(begin("notes").0 == 404, "an empty store can't be unlocked")
if let gb = begin("gmail").1 {
  check(call("/unlock/finish", ["pending": gb.pending, "shares": [String: Any]()]).0 == 400, "an unlock without a share for each key is refused")
}

// a key written as the setup session through the router (infra/setup.py write): the backup first, then the core; the
// phone checks the setup key's signature over the writer text before it gives its share
let sk0 = recoverStoreKey
func setupWrite(_ store: String, _ key: String, _ value: String, signer: P256.Signing.PrivateKey = setupSigner) -> [String: Any] {
  let x = try! CoreCrypto.wrapKey(store: store, key: key, value: Data(value.utf8), storeKey: sk0)
  let bk = try! CoreCrypto.seal(Data(value.utf8), to: kitMaster.publicKey, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: store, key: key))
  let bsha = CoreCrypto.sha256hex(Data("\(bk["e"]!)\n\(bk["data"]!)".utf8))
  let text = Checks.writerText(store: store, key: key, e: x.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data(x.data.utf8)), backupSha256: bsha)
  let live = try! CoreCrypto.seal(Data(value.utf8), to: coreKeys.agreementKey, info: "jarvis2/live-key\n\(store)\n\(key)")
  return ["wrapped": ["e": x.wrapped.e, "wrapped": x.wrapped.wrapped], "data": x.data, "backup": bk, "backupSha256": bsha, "live": live,
          "sig": try! signer.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString(), "explanation": "what \(key) is for"]
}
let rbaseW = need("INTEROP_ROUTER")
let (ws0, wd0) = call("/setup/stores/default/keys/WRITTEN", setupWrite("default", "WRITTEN", "w1"), base: rbaseW)
check(ws0 == 200, "the setup session writes one key through the router (HTTP \(ws0) \(String(decoding: wd0.prefix(200), as: UTF8.self)))")
let (wbs, wb) = begin("default")
let wk = wb?.keys.first { $0.key == "WRITTEN" }
check(wbs == 200 && wk?.writer.by == "setup" && wk?.writer.sig != nil && wk?.backupSha256.count == 64 && wb?.keys.count == 4,
      "unlock-begin names the written key, its setup writer with the signature and its backup hash")
check(wb.map { x in !throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…the app checks the setup key's signature over it")
check(wb.map { x in throwsErr { try Checks.unlockKeys(x, setupKey: phoneSigningForTests) } } == true, "…and refuses it against another key")
check(wb.map { finish($0).0 } == 200, "…and the store opens with it")
struct ServedRows: Decodable { struct R: Decodable { let name: String; let about: String?; let keyInfo: [K]? }; struct K: Decodable { let name: String; let explanation: String?; let writer: W? }; struct W: Decodable { let by: String }; let stores: [R] }
let rows = try? JSONDecoder().decode(ServedRows.self, from: call("/api/stores", base: rbaseW).1)
let rdef = rows?.stores.first { $0.name == "default" }
check(rdef?.keyInfo?.first { $0.name == "WRITTEN" }.map { $0.explanation == "what WRITTEN is for" && $0.writer?.by == "setup" } == true,
      "GET /api/stores lists the key with its explanation and writer")
let docsStatus = call("/api/stores/default/docs", ["about": "everyday keys", "keys": ["WRITTEN": "", "OTHER": "the other one"]], base: rbaseW, method: "PUT").0
let rdef2 = (try? JSONDecoder().decode(ServedRows.self, from: call("/api/stores", base: rbaseW).1))?.stores.first { $0.name == "default" }
check(docsStatus == 200 && rdef2?.about == "everyday keys" && rdef2?.keyInfo?.first { $0.name == "OTHER" }?.explanation == "the other one"
      && (rdef2?.keyInfo?.first { $0.name == "WRITTEN" }?.explanation ?? "") == "", "PUT /api/stores/{store}/docs sets the about text and an explanation; \"\" removes one")
// its backup is in the bucket, and a Recover would lay it over the store
struct ServedAgain: Decodable { let objects: [CoreSetup.BackupObject] }
let servedNow = (try? JSONDecoder().decode(ServedAgain.self, from: call("/api/backups", base: rbaseW).1))?.objects ?? []
let wObj = servedNow.first { $0.key == "keys/default/WRITTEN.json" }
check(wObj.map { x in !throwsErr { _ = try CoreSetup.checkKeyBackup(x, setupKey: setupKey, boxKey: boxKey) } } == true, "the router wrote the key's backup first (keys/default/WRITTEN.json) and it checks")
check((try? CoreSetup.readBackups(servedNow, master: kitMaster, setupKey: setupKey, boxKey: boxKey))?.first { $0.name == "default" }?.values["WRITTEN"] == "w1",
      "…and opens with the kit, laid over the store's whole-store backup")

// ---- restore: a store put back to an earlier version (secrets/history.go, router/storerestore.go): the phone signs
// secrets' begin document and shares the keys put back; no kit. Secrets' backups (writer "restore") check at Recover.
func setupDelete(_ store: String, _ key: String) -> [String: Any] {
  let text = Checks.writerText(store: store, key: key, e: "", dataSha256: "", backupSha256: "")
  return ["delete": true, "sig": try! setupSigner.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()]
}
func versionsOf(_ store: String) -> StoreVersionsDoc? {
  try? CoreCrypto.decode(doc(call("/api/secrets/stores/versions", ["store": store, "nonce": "n-v"], base: rbaseW).1), by: coreKey, as: StoreVersionsDoc.self, what: "versions")
}
func restoreBeginDoc(_ store: String, _ seq: Int) -> (SignedDoc, RestoreBegin?) {
  let (s, d) = call("/api/secrets/stores/restore/begin", ["store": store, "seq": seq], base: rbaseW)
  guard s == 200 else { return (SignedDoc(payload: "", sig: ""), nil) }
  let sd = doc(d)
  return (sd, try? CoreCrypto.decode(sd, by: coreKey, as: RestoreBegin.self, what: "restore begin"))
}
func restoreFinish(_ b: RestoreBegin, _ d: SignedDoc, signer: P256.Signing.PrivateKey) -> (Int, Data) {
  var m: [String: Any] = [:]
  for p in b.put { m[p.key] = try! CoreCrypto.sealShare(shareOf(p.e), to: b.t) }
  return call("/api/stores/restore/finish", ["pending": b.pending, "signature": try! signer.signature(for: Data(d.payload.utf8)).derRepresentation.base64EncodedString(),
                                             "shares": m], base: rbaseW)
}
let v0 = versionsOf("default"), withWritten = v0?.versions.first
check(withWritten?.cause.kind == "write" && withWritten?.cause.key == "WRITTEN" && withWritten?.version == v0?.current && (v0?.versions.count ?? 0) >= 2,
      "secrets' signed versions of a store, newest first (the write of WRITTEN is current)")
let wseq = withWritten?.seq ?? 0
check(call("/setup/stores/default/keys/WRITTEN", setupDelete("default", "WRITTEN"), base: rbaseW).0 == 200, "WRITTEN deleted as the setup session")
var (rsdoc, rsb) = restoreBeginDoc("default", wseq)
check(rsb?.put.map(\.key) == ["WRITTEN"] && rsb?.remove == [] && rsb?.put.first?.writer.by == "setup"
      && rsb.map { x in !throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq, setupKey: setupKey) } } == true,
      "restore-begin names exactly the key put back; the app checks its setup writer")
check(rsb.map { x in throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq, setupKey: phoneSigningForTests) } } == true, "…and refuses it against another setup key")
check(rsb.map { x in throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq + 1, setupKey: setupKey) } } == true, "…and a begin for another version")
check(rsb.map { restoreFinish($0, rsdoc, signer: P256.Signing.PrivateKey()).0 } != 200, "a restore signed by another key is refused")
check(rsb.map { restoreFinish($0, rsdoc, signer: phoneSigning).0 } != 200, "…and its begin is spent")
check(begin("default").1?.keys.contains { $0.key == "WRITTEN" } == false, "…so nothing was restored")
(rsdoc, rsb) = restoreBeginDoc("default", wseq)
let (rfs, rfd) = rsb.map { restoreFinish($0, rsdoc, signer: phoneSigning) } ?? (0, Data())
struct RestoredOut: Decodable { let restored: SignedDoc }
let rdone = (try? JSONDecoder().decode(RestoredOut.self, from: rfd)).flatMap { try? CoreCrypto.decode($0.restored, by: coreKey, as: RestoreDone.self, what: "restored") }
check(rfs == 200 && rdone != nil && rsb.map { x in !throwsErr { try Checks.restoreDone(rdone!, begin: x) } } == true,
      "the phone's signature and shares put the version back; the committed answer is this restore's (HTTP \(rfs) \(String(decoding: rfd.prefix(160), as: UTF8.self)))")
check(versionsOf("default")?.current == withWritten?.version && versionsOf("default")?.versions.first?.cause.kind == "restore", "…the store is that version again, as a new version")
let (rws, rwb) = begin("default")
check(rws == 200 && rwb?.keys.first { $0.key == "WRITTEN" }?.writer.by == "setup" && rwb.map { finish($0).0 } == 200, "…WRITTEN is back with its own writer, and the store opens")
let servedRestored = (try? JSONDecoder().decode(ServedAgain.self, from: call("/api/backups", base: rbaseW).1))?.objects ?? []
let rsObj = servedRestored.first { $0.key == "keys/default/WRITTEN.json" }
check(rsObj.map { x in !throwsErr { _ = try CoreSetup.checkKeyBackup(x, setupKey: setupKey, boxKey: boxKey) } } == true && rsObj?.body.contains("\"restore\"") == true,
      "the router wrote secrets' backup of WRITTEN (writer restore) and the app checks it")
check((try? CoreSetup.readBackups(servedRestored, master: kitMaster, setupKey: setupKey, boxKey: boxKey))?.first { $0.name == "default" }?.values["WRITTEN"] == "w1",
      "…and a Recover brings WRITTEN back with the kit")
if let rsObj {
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(rsObj, setupKey: setupKey, boxKey: setupKey) }, "…not with a secrets another key vouched for")
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(alter(rsObj) { $0["backupSha256"] = String(repeating: "0", count: 64) }, setupKey: setupKey, boxKey: boxKey) },
        "…nor with another value than its receipt names")
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(alter(rsObj, key: "keys/default/OTHER.json") { $0["key"] = "OTHER" }, setupKey: setupKey, boxKey: boxKey) },
        "…nor moved to a key its receipt doesn't put back")
}

// a key sealed under another name (store or key) doesn't decrypt: secrets refuses the whole unlock
func coreWrite(_ store: String, _ key: String, sealedAs: (String, String), signer: P256.Signing.PrivateKey = setupSigner) -> Int {
  let x = try! CoreCrypto.wrapKey(store: sealedAs.0, key: sealedAs.1, value: Data("v".utf8), storeKey: sk0)
  let text = Checks.writerText(store: store, key: key, e: x.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data(x.data.utf8)), backupSha256: "")
  let live = try! CoreCrypto.seal(Data("v".utf8), to: coreKeys.agreementKey, info: "jarvis2/live-key\n\(store)\n\(key)")
  return call("/stores/write-key", ["store": store, "key": key, "wrapped": ["e": x.wrapped.e, "wrapped": x.wrapped.wrapped], "data": x.data, "live": live,
                                    "writer": "setup", "sig": try! signer.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()]).0
}
check(coreWrite("moved", "A", sealedAs: ("moved", "B")) == 200 && unlock("moved").0 == 403, "a key sealed under another key's name doesn't decrypt")
check(coreWrite("moved2", "A", sealedAs: ("default", "A")) == 200 && unlock("moved2").0 == 403, "…nor one sealed under another store's name")
check(coreWrite("forged", "A", sealedAs: ("forged", "A"), signer: P256.Signing.PrivateKey()) == 200, "secrets passes on a setup writer's signature unchecked")
check(begin("forged").1.map { x in throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…and the app refuses a key the setup key didn't sign")

// a key a session's machine wrote (the router's word): shown on the page or refused before Face ID
func synthetic(_ w: StoreWriter, key: String = "S") -> UnlockBegin {
  UnlockBegin(kind: "unlock-begin", pending: "p", store: "default", t: "", keys: [KeyBegin(key: key, e: "E", writer: w, dataSha256: "d")])
}
let mb = synthetic(StoreWriter(by: "machine", machine: "fake000042"))
check(!throwsErr { try Checks.unlockKeys(mb, setupKey: nil) }, "a key a session's machine wrote is taken (the router's word)…")
check(Checks.unseen([mb], shown: []) == [SessionWrite(store: "default", key: "S", machine: "fake000042")], "…but one the page didn't show is refused")
check(Checks.unseen([mb], shown: [SessionWrite(store: "default", key: "S", machine: "fake000042", label: "T")]).isEmpty, "…and one it showed goes through")
check(!Checks.unseen([mb], shown: [SessionWrite(store: "default", key: "S", machine: "other0000")]).isEmpty, "…not when the page named another session's machine")
check(throwsErr { try Checks.unlockKeys(synthetic(StoreWriter(by: "machine")), setupKey: nil) }, "a machine writer naming no machine is refused")
check(!throwsErr { try Checks.unlockKeys(synthetic(StoreWriter(by: "router")), setupKey: nil) }, "a key the router wrote itself (the Claude login) is taken")
check(throwsErr { try Checks.unlockKeys(synthetic(StoreWriter(by: "nobody")), setupKey: nil) }, "an unknown writer is refused")
check(throwsErr { try Checks.unlockKeys(UnlockBegin(kind: "unlock-begin", pending: "p", store: "x", t: "", keys: []), setupKey: nil) }, "an unlock of no keys is refused")

let n2 = CoreCrypto.nonce()
let ul = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": n2]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul?.nonce == n2 && ul?.unlocked.allSatisfy({ $0.store == "default" }) == true && ul?.unlocked.contains { $0.id == u?.id } == true, "unlocked list is signed, fresh and complete")

// ---- unlocks are per store and open until locked (no session, no timer): the store list and the unlocked list say so ----
let sdoc = try! CoreCrypto.decode(doc(call("/stores", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: StoresDoc.self, what: "stores")
check(sdoc.kind == "stores", "secrets' signed store list")
let sb = begin("gmail").1!
let (ss, sd) = finish(sb)
let su = try? CoreCrypto.decode(doc(sd), by: coreKey, as: KindDoc.self, what: "unlocked")
check(ss == 200 && su?.kind == "unlocked" && list().first { $0.name == "gmail" }?.unlocked == true, "an unlock opens the store, and the signed list shows it open")
let ul2 = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul2?.unlocked.contains { $0.id == su?.id && $0.store == "gmail" } == true, "…and the unlocked list names it with its store")
let slk = try? CoreCrypto.decode(doc(call("/lock", ["id": su?.id ?? ""]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(slk?.kind == "locked" && list().first { $0.name == "gmail" }?.unlocked == false, "a lock ends it")
check(SignedAction.value(SignedAction.unlock(stores: ["gmail"], session: nil), "relock") == "When you lock it", "the review page says the unlock lasts until locked")

// ---- deploy keys: a repo added and removed, each approved by the phone (secrets' fake GitHub in CI) ----
/// the begin body the app sends (RouterClient.deployKeyBegin): the store and title it names, and for an add the key
/// pair it made, the private half's store wrapped to the store key
func keyBegin(_ action: String, _ repo: String, sensitive: Bool) -> ([String: Any], DeployKeySent?) {
  let store = Checks.repoStore(repo), title = "jarvis2 " + store
  var body: [String: Any] = ["action": action, "repo": repo, "sensitive": sensitive, "store": store, "title": title]
  guard action == "add" else { return (body, nil) }
  let kp = try! OpenSSH.ed25519(comment: title)
  let keys = try! CoreCrypto.wrapKeys(store: store, values: OpenSSH.storeValues(repo: repo, privateKeyFile: kp.privateKeyFile), storeKey: recoverStoreKey)
  body["publicKey"] = kp.publicKey
  body["keys"] = keys.map(\.json)
  return (body, DeployKeySent(publicKey: kp.publicKey, keys: keys))
}
/// the token key's writer, as RouterClient checks it
func tokenWriterOK(_ b: DeployKeyBegin) -> Bool {
  guard let k = b.tokenKey, let w = b.tokenWriter, w.by == "setup" || w.by == "core" else { return false }
  return !throwsErr { try Checks.keyWriter(w, store: b.tokenStore, key: k, e: b.e, dataSha256: b.tokenDataSha256 ?? "", backupSha256: b.tokenBackupSha256 ?? "", setupKey: setupKey) }
}
func deployKey(_ action: String, _ repo: String, sensitive: Bool = false, signer: P256.Signing.PrivateKey? = nil, base: String = core, prefix: String = "/deploy-keys") -> (Int, DeployKeyBegin?, Data) {
  let (body, sent) = keyBegin(action, repo, sensitive: sensitive)
  let (bs, bd) = call(prefix + "/begin", body, base: base)
  guard bs == 200, let d = try? JSONDecoder().decode(SignedDoc.self, from: bd) else { return (bs, nil, bd) }
  guard let b = try? Checks.deployKeyBegin(d, coreKey: coreKey, action: action, repo: repo, sensitive: sensitive, sent: sent), tokenWriterOK(b) else { return (0, nil, bd) }
  let sig = try! (signer ?? phoneSigning).signature(for: Data(d.payload.utf8)).derRepresentation.base64EncodedString()
  let x = try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
  let (fs, fd) = call(prefix + "/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(x, to: b.t)], base: base)
  return (fs, b, fd)
}
check(Checks.repoStore("DE0CH/china_train") == "github-china-train" && Checks.repoStore("someone/Thing.js") == "github-someone-thing-js" && Checks.repoStore("de0ch/Jarvis2") == "github-jarvis2", "the app's store names are secrets'")
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
let appKeys = try! CoreCrypto.wrapKeys(store: "github-r2-app", values: OpenSSH.storeValues(repo: "DE0CH/r2-app", privateKeyFile: kp.privateKeyFile), storeKey: skNow)
check(appKeys.map(\.key) == ["GITHUB_DEPLOY_KEY_DE0CH_R2_APP", "GITHUB_DEPLOY_REPO_DE0CH_R2_APP"], "a repo's store is two keys, each sealed on its own")
let (abStatus, abd) = call("/deploy-keys/begin", ["action": "add", "repo": "DE0CH/r2-app", "sensitive": false, "store": "github-r2-app",
                                             "title": "jarvis2 github-r2-app", "publicKey": kp.publicKey, "keys": appKeys.map(\.json)])
let abeg = abStatus == 200 ? try? Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: appKeys)) : nil
check(abeg != nil && abeg?.keys?.count == 2 && abeg?.tokenKey == "GITHUB_DEPLOY_KEYS_TOKEN", "the core's begin names the app's public key and each key it sent (HTTP \(abStatus))")
check(abeg.map(tokenWriterOK) == true && abeg?.tokenWriter?.by == "core", "…and who wrote the GitHub token (the core: a Recover's key)")
let otherKeys = try! CoreCrypto.wrapKeys(store: "github-r2-app", values: ["X": "y"], storeKey: skNow)
check(abStatus == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: otherKeys)) }, "…the page refuses a begin naming other keys")
let movedKeys = [appKeys[0], KeyEntry(store: "github-r2-app", key: "GITHUB_DEPLOY_REPO_DE0CH_R2_APP", wrapped: appKeys[0].wrapped, data: appKeys[0].data)]
check(abStatus == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: movedKeys)) }, "…or a key under another name")
if let b = abeg {
  let sig = try! phoneSigning.signature(for: Data(doc(abd).payload.utf8)).derRepresentation.base64EncodedString()
  let (afs, afd) = call("/deploy-keys/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(shareOf(b.e), to: b.t)])
  let a = try? Checks.deployKeyAnswer(doc(afd), coreKey: coreKey, begin: b)
  check(afs == 200 && a?.kind == "deploy-key-added" && a?.publicKey == kp.publicKey && a?.store == "github-r2-app", "the core added the app's key (HTTP \(afs))")
  check(unlock("github-r2-app").0 == 200, "…and the app-wrapped keys open with the phone's shares")
}
// the store's keys sealed under another key's name: the core keeps them as sent, and they don't open
let swapped = [KeyEntry(store: "github-r2-swap", key: "GITHUB_DEPLOY_KEY_DE0CH_R2_SWAP", wrapped: appKeys[1].wrapped, data: appKeys[1].data),
               KeyEntry(store: "github-r2-swap", key: "GITHUB_DEPLOY_REPO_DE0CH_R2_SWAP", wrapped: appKeys[0].wrapped, data: appKeys[0].data)]
let kp2 = try! OpenSSH.ed25519(comment: "jarvis2 github-r2-swap")
let (sws, swd) = call("/deploy-keys/begin", ["action": "add", "repo": "DE0CH/r2-swap", "sensitive": false, "store": "github-r2-swap",
                                       "title": "jarvis2 github-r2-swap", "publicKey": kp2.publicKey, "keys": swapped.map(\.json)])
if sws == 200, let b = try? Checks.deployKeyBegin(doc(swd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-swap", sensitive: false, sent: DeployKeySent(publicKey: kp2.publicKey, keys: swapped)) {
  let sig = try! phoneSigning.signature(for: Data(doc(swd).payload.utf8)).derRepresentation.base64EncodedString()
  _ = call("/deploy-keys/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(shareOf(b.e), to: b.t)])
  check(unlock("github-r2-swap").0 == 403, "a deploy key's values moved to another store or key don't decrypt")
} else { check(false, "a deploy key's values moved to another store or key don't decrypt (begin HTTP \(sws))") }

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

// ---- Reset on a set-up secrets: only the master key it was set up with ends it ----
check(call("/wipe", try! CoreSetup.wipe(core: coreKeys, master: fresh)).0 == 403, "a wipe signed by another key is refused")
var w2 = try! CoreSetup.wipe(core: phone, master: kitMaster)
check(call("/wipe", w2).0 == 403, "a wipe naming another secrets is refused")
w2 = try! CoreSetup.wipe(core: coreKeys, master: kitMaster)
let (ws, wd) = call("/wipe", w2)
let wiping = try? CoreCrypto.decode(doc(wd), by: coreKey, as: KindDoc.self, what: "wiping")
check(ws == 200 && wiping?.kind == "wiping" && wiping?.core == coreKey, "the master key ends secrets (a signed 'wiping')")
sleep(3)
let after = call("/identity")
check(after.0 == 0 || (try? JSONDecoder().decode(CoreSetup.Identity.self, from: after.1))?.signingKey != coreKey, "…and that secrets is gone (a new, empty one takes its place)")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
