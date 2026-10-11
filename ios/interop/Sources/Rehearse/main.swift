// Rehearse: the app's side of a Recover rehearsal against a REAL throwaway box (infra/rehearse-recover.sh), with the
// shell's own CoreSetup + CoreCrypto (symlinked in, as for Interop) and a software phone. It speaks to the box's
// router through its Cloudflare tunnel, as the app does, with the rehearsal's Access service token.
//   rehearse reset              the test kit sets up an empty core with no stores (the app's Reset, kit = the
//                               public TEST master key, e2e/testdata)
//   rehearse wait-empty [OLD]   until the router answers with an empty core (other signing key than OLD, if given)
//   rehearse wipe               the kit ends the set-up core (the app's "Restart and recover"); waits for the new one
//   rehearse recover EXPECT     the app's Recover: the backups through the router, checked with keys/setup.pub and
//                               opened with the kit, the claim; then the core's signed store list must match EXPECT
//                               ({"stores": {name: {"sensitive": bool, "values": {K: V}}}}, the core store excluded)
//   rehearse session STORE…     unlock the session's stores (split key), New session (harness claude), the phone
//                               checks and signs the challenge; waits until started. Prints SESSION and MACHINE.
//   rehearse stuck STORE        a session with STORE left LOCKED (its machine loops on "store is locked" at boot),
//                               then destroy: it must end within 90 s, not wait out the snapshot wait (10 min)
//   rehearse destroy SESSION    and waits until it is in the records
// Env: REHEARSE_BASE (https://<host>/), REHEARSE_ACCESS_ID/SECRET, REHEARSE_KEYS (box.pub, setup.pub),
//      REHEARSE_MASTER_PEM, REHEARSE_PHONE (the software phone's keys, made on first use; test keys only).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

setvbuf(stdout, nil, _IOLBF, 0)
let env = ProcessInfo.processInfo.environment
func need(_ k: String) -> String { guard let v = env[k], !v.isEmpty else { fail("missing \(k)") }; return v }
func fail(_ s: String) -> Never { print("FAIL " + s); exit(1) }
func ok(_ s: String) { print("ok   " + s) }
func say(_ s: String) { print("==   " + s) }

let base = need("REHEARSE_BASE").hasSuffix("/") ? need("REHEARSE_BASE") : need("REHEARSE_BASE") + "/"
func keyFile(_ n: String) -> String {
  guard let s = try? String(contentsOfFile: need("REHEARSE_KEYS") + "/" + n, encoding: .utf8) else { fail("no \(n)") }
  return s.trimmingCharacters(in: .whitespacesAndNewlines)
}
let boxKey = keyFile("box.pub"), setupKey = keyFile("setup.pub")

// ---- the router, as RouterClient talks to it (plus the rehearsal's Access service token) ----
func call(_ method: String, _ path: String, _ body: Any? = nil) -> (Int, Data) {
  var r = URLRequest(url: URL(string: base + path)!, timeoutInterval: 120)
  r.httpMethod = method
  r.setValue(need("REHEARSE_ACCESS_ID"), forHTTPHeaderField: "CF-Access-Client-Id")
  r.setValue(need("REHEARSE_ACCESS_SECRET"), forHTTPHeaderField: "CF-Access-Client-Secret")
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func json<T: Decodable>(_ method: String, _ path: String, _ body: Any? = nil, as: T.Type) -> T {
  let (s, d) = call(method, path, body)
  guard s == 200, let v = try? JSONDecoder().decode(T.self, from: d) else { fail("\(method) \(path): HTTP \(s) \(String(decoding: d.prefix(300), as: UTF8.self))") }
  return v
}

// ---- the kit and the software phone ----
let kitString = RecoveryKit(master: MasterKey(signing: try! P256.Signing.PrivateKey(pemRepresentation: String(contentsOfFile: need("REHEARSE_MASTER_PEM"), encoding: .utf8)))).string
guard let parsedKit = try? RecoveryKit.parse(kitString) else { fail("the test kit doesn't parse") }
let master = parsedKit.master
struct PhoneFile: Codable { let signing: String; let agreement: String }
let phonePath = need("REHEARSE_PHONE")
let phoneFile: PhoneFile = {
  if let d = FileManager.default.contents(atPath: phonePath), let p = try? JSONDecoder().decode(PhoneFile.self, from: d) { return p }
  let p = PhoneFile(signing: P256.Signing.PrivateKey().rawRepresentation.base64EncodedString(), agreement: P256.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString())
  _ = FileManager.default.createFile(atPath: phonePath, contents: try! JSONEncoder().encode(p), attributes: [.posixPermissions: 0o600])
  return p
}()
let phoneSigning = try! P256.Signing.PrivateKey(rawRepresentation: Data(base64Encoded: phoneFile.signing)!)
let phoneAgreement = try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data(base64Encoded: phoneFile.agreement)!)
let phone = PublicKeys(signingKey: phoneSigning.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgreement.publicKey.x963Representation.base64EncodedString())

// ---- the core ----
/// RouterClient.identity + CoreSetup.check; nil while there is no core to ask (503/502/504, or a 530 from the edge)
func coreNow() -> (keys: PublicKeys, state: CoreSetup.State)? {
  let (s, d) = call("GET", "api/core/identity")
  if [0, 502, 503, 504, 530].contains(s) { return nil }
  guard s == 200, let id = try? JSONDecoder().decode(CoreSetup.Identity.self, from: d) else { fail("api/core/identity: HTTP \(s) \(String(decoding: d.prefix(200), as: UTF8.self))") }
  do { return try CoreSetup.check(id, boxKey: boxKey) } catch { fail("the core's identity doesn't check against box.pub: \(error)") }
}
func waitEmpty(notKey old: String?, minutes: Int = 15) -> (keys: PublicKeys, state: CoreSetup.State) {
  let end = Date().addingTimeInterval(Double(minutes) * 60)
  var last = ""
  while Date() < end {
    if let c = coreNow() {
      let st = CoreSetup.status(c.state, myMaster: master.publicKey, myPhone: phone)
      if st == .empty && c.keys.signingKey != old { return c }
      if "\(st)" != last { say("core \(c.keys.signingKey.prefix(12))…: \(st)"); last = "\(st)" }
    } else if last != "down" { say("no core answering yet"); last = "down" }
    sleep(5)
  }
  fail("no new, empty core within \(minutes) minutes")
}
func claim(_ c: PublicKeys, _ stores: [RecoveredStore]) -> Int {
  let body = try! CoreSetup.claim(core: c, phone: phone, master: master, bundle: try! CoreSetup.bundle(stores))
  let d = try! CoreCrypto.decode(json("POST", "api/core/claim", body, as: SignedDoc.self), by: c.signingKey, as: KindDoc.self, what: "the core's answer")
  guard d.kind == "claimed" else { fail("the claim's answer is \(d.kind)") }
  return d.stores ?? 0
}
func mine() -> PublicKeys {
  guard let c = coreNow() else { fail("no core") }
  guard CoreSetup.status(c.state, myMaster: master.publicKey, myPhone: phone) == .mine else { fail("the core isn't set up with this kit and phone") }
  return c.keys
}
func storeList(_ core: String) -> [StoreView] {
  let n = CoreCrypto.nonce()
  let d = try! CoreCrypto.decode(json("POST", "api/core/stores", ["nonce": n], as: SignedDoc.self), by: core, as: StoresDoc.self, what: "the store list")
  guard d.kind == "stores", d.nonce == n else { fail("a stale store list") }
  return d.stores
}

// ---- sessions: New session as the app does it (unlock, create, the phone checks and signs the challenge) ----
struct ApprovalDTO: Decodable { let id: String; let kind: String; let session: String?; let label: String?; let challenge: SignedDoc }
struct SessionDTO: Decodable { let id: String; let state: String; let label: String?; let machineId: String?; let error: String?; let waiting: String? }
struct StateDTO: Decodable { let sessions: [SessionDTO]; let approvals: [ApprovalDTO] }
struct RecordsDTO: Decodable { struct Rec: Decodable { let id: String? }; let records: [Rec] }
func sessionNow(_ id: String) -> SessionDTO? { json("GET", "api/state", as: StateDTO.self).sessions.first { $0.id == id } }
func unlock(_ store: String, core: String) {
  let b = try! CoreCrypto.decode(json("POST", "api/core/unlock/begin", ["store": store], as: SignedDoc.self), by: core, as: UnlockBegin.self, what: "the unlock")
  guard b.kind == "unlock-begin", b.store == store else { fail("unlock-begin for \(store)") }
  let x = try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
  let u = try! CoreCrypto.decode(json("POST", "api/core/unlock/finish", ["pending": b.pending, "share": try! CoreCrypto.sealShare(x, to: b.t)], as: SignedDoc.self), by: core, as: KindDoc.self, what: "the unlocked answer")
  guard u.kind == "unlocked", u.store == store else { fail("unlock \(store): \(u.kind)") }
  ok("unlocked \(store) with the phone's share")
}
/// a new session with `picked` (+ the harness's stores); every store unlocked first except `locked`
func newSession(_ picked: [String], leaveLocked locked: Set<String> = []) -> String {
  let core = mine().signingKey
  struct PolicyDTO: Decodable { struct H: Decodable { let stores: [String]? }; let harnesses: [String: H] }
  let harnessStores = json("GET", "api/policy", as: PolicyDTO.self).harnesses["claude"]?.stores ?? []
  for store in Set(picked + harnessStores).subtracting(locked).sorted() { unlock(store, core: core) }
  let label = "rehearsal \(Int(Date().timeIntervalSince1970))"
  _ = call("POST", "api/sessions", ["label": label, "stores": picked, "size": "small", "harness": "claude"])
  var approval: ApprovalDTO?
  for _ in 0..<60 {
    approval = json("GET", "api/state", as: StateDTO.self).approvals.first { $0.kind == "new-session" && $0.label == label }
    if approval != nil { break }
    sleep(3)
  }
  guard let a = approval else { fail("no new-session approval for \(label)") }
  let r = try! Checks.review(challenge: a.challenge, coreKey: core)
  do { try Checks.matchesPicked(r, stores: picked, harnessStores: harnessStores, harness: "claude", permissionMode: "auto") } catch { fail("the challenge doesn't match what was picked: \(error)") }
  ok("the challenge is the core's and names \(r.stores) (sensitive \(r.sensitive)), harness \(r.harness)")
  struct RespondDTO: Decodable { let answer: SignedDoc; let session: String }
  let resp = json("POST", "api/approvals/\(a.id)/respond", ["signature": try! phoneSigning.signature(for: Data(a.challenge.payload.utf8)).derRepresentation.base64EncodedString()], as: RespondDTO.self)
  do { try Checks.answerFor(r, answer: resp.answer, coreKey: core) } catch { fail("the answer: \(error)") }
  ok("the phone approved; session \(resp.session)")
  return resp.session
}
func destroyAndWait(_ id: String, within: TimeInterval) -> TimeInterval {
  let t0 = Date()
  let (s, d) = call("POST", "api/sessions/\(id)/destroy")
  guard s == 200 else { fail("destroy: HTTP \(s) \(String(decoding: d.prefix(200), as: UTF8.self))") }
  var lastWaiting = ""
  while Date().timeIntervalSince(t0) < within {
    if let w = sessionNow(id)?.waiting, !w.isEmpty, w != lastWaiting { say("\(id): destroying: \(w)"); lastWaiting = w }
    if json("GET", "api/records", as: RecordsDTO.self).records.contains(where: { $0.id == id }) { return Date().timeIntervalSince(t0) }
    sleep(3)
  }
  fail("session \(id) wasn't destroyed within \(Int(within)) s")
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first ?? "" {
case "reset":
  guard let c = coreNow() else { fail("no core") }
  guard CoreSetup.status(c.state, myMaster: master.publicKey, myPhone: phone) == .empty else { fail("the core isn't empty") }
  _ = claim(c.keys, [])
  _ = mine()
  ok("Reset: core \(c.keys.signingKey.prefix(16))… is set up with the test kit, no stores")

case "wait-empty":
  let c = waitEmpty(notKey: args.count > 1 ? args[1] : nil)
  ok("an empty core: \(c.keys.signingKey)")
  print("CORE \(c.keys.signingKey)")

case "wipe":
  let c = mine()
  let d = try! CoreCrypto.decode(json("POST", "api/core/wipe", try! CoreSetup.wipe(core: c, master: master), as: SignedDoc.self), by: c.signingKey, as: KindDoc.self, what: "the core's answer")
  guard d.kind == "wiping", d.core == c.signingKey else { fail("the wipe's answer is \(d.kind)") }
  ok("the kit ended core \(c.signingKey.prefix(16))…")
  let n = waitEmpty(notKey: c.signingKey, minutes: 5)
  ok("Kubernetes started a new, empty core \(n.keys.signingKey.prefix(16))…")

case "recover":
  guard args.count > 1, let ed = FileManager.default.contents(atPath: args[1]) else { fail("usage: recover EXPECT.json") }
  struct Want: Decodable { let sensitive: Bool; let values: [String: String] }
  struct Expect: Decodable { let stores: [String: Want] }
  let want = try! JSONDecoder().decode(Expect.self, from: ed).stores
  guard let c = coreNow() else { fail("no core") }
  guard CoreSetup.status(c.state, myMaster: master.publicKey, myPhone: phone) == .empty else { fail("the core isn't empty") }
  struct B: Decodable { let bucket: String?; let objects: [CoreSetup.BackupObject] }
  let served = json("GET", "api/backups", as: B.self)
  say("the router serves \(served.objects.count) backup objects from \(served.bucket ?? "?")")
  let stores: [RecoveredStore]
  do { stores = try CoreSetup.readBackups(served.objects, master: master, setupKey: setupKey) } catch { fail("the backups: \(error)") }
  let got = Dictionary(uniqueKeysWithValues: stores.map { ($0.name, $0) })
  guard Set(got.keys) == Set(want.keys).union(["core"]) else { fail("backups hold \(got.keys.sorted()), want \(want.keys.sorted()) + core") }
  for (n, w) in want {
    guard got[n]!.values == w.values else { fail("store \(n): its values differ from what was written") }
    guard got[n]!.sensitive == w.sensitive else { fail("store \(n): sensitive \(got[n]!.sensitive) in the backups, want \(w.sensitive)") }
  }
  guard got["core"]!.values["FLY_API_TOKEN"]?.isEmpty == false else { fail("the core store has no Fly token") }
  ok("every backup checks (setup key) and opens (kit): \(stores.map(\.name)), values and sensitivity as written")
  let n = claim(c.keys, stores)
  guard n == want.count else { fail("the core says \(n) stores, want \(want.count)") }
  let k = mine()
  ok("Recover: core \(k.signingKey.prefix(16))… is set up with the kit and this phone (\(n) stores)")
  let l = storeList(k.signingKey)
  let listed = Dictionary(uniqueKeysWithValues: l.map { ($0.name, $0.sensitive) })
  guard Set(listed.keys) == Set(want.keys) else { fail("the core lists \(listed.keys.sorted()), want \(want.keys.sorted())") }
  for (n, w) in want where listed[n] != w.sensitive { fail("store \(n): the core says sensitive=\(listed[n]!), want \(w.sensitive)") }
  ok("the core's signed list: \(l.map { "\($0.name)\($0.sensitive ? " (sensitive)" : "")" }.joined(separator: ", "))")

case "session":
  let id = newSession(Array(args.dropFirst()))
  let end = Date().addingTimeInterval(10 * 60)
  var last = ""
  while Date() < end {
    if let s = sessionNow(id) {
      if s.state != last { say("\(s.id): \(s.state) \(s.error ?? "")"); last = s.state }
      if s.state == "started", let m = s.machineId { ok("started on machine \(m)"); print("SESSION \(s.id)"); print("MACHINE \(m)"); exit(0) }
      if s.state == "failed" { fail("the session failed: \(s.error ?? "")") }
    }
    sleep(4)
  }
  fail("the session didn't start in 10 minutes")

case "stuck":
  guard args.count > 1 else { fail("usage: stuck STORE") }
  let id = newSession([args[1]], leaveLocked: [args[1]])
  // the machine boots and loops on the locked store ("pull secrets: HTTP 423"): the session never starts
  let t0 = Date()
  var m = ""
  while Date().timeIntervalSince(t0) < 240 {
    guard let s = sessionNow(id) else { fail("the session went away") }
    if s.state == "started" { fail("a session with a locked store started") }
    if s.state == "failed" { fail("the session failed: \(s.error ?? "")") }
    m = s.machineId ?? ""
    if !m.isEmpty && Date().timeIntervalSince(t0) > 150 { break }   // its machine has been up and looping for a while
    sleep(5)
  }
  ok("session \(id) is stuck at boot on machine \(m) (\(args[1]) locked)")
  print("STUCK \(m)")
  let took = destroyAndWait(id, within: 90)
  ok("destroyed in \(Int(took)) s, not after the 10-minute snapshot wait")

case "destroy":
  guard args.count > 1 else { fail("usage: destroy SESSION") }
  let took = destroyAndWait(args[1], within: 15 * 60)
  ok("session \(args[1]) destroyed in \(Int(took)) s (in the records)")

default:
  print("usage: rehearse reset | wait-empty [OLD] | wipe | recover EXPECT.json | session STORE… | stuck STORE | destroy SESSION"); exit(2)
}
