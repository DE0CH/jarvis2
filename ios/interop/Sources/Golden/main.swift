// The app's reading, checking, rendering and signing of the kernel's documents against the kernel's golden vectors
// (core/kernel/testdata, made by core/kernel/golden_test.go with TEST keys derived from a public seed): sets and pairs
// (the algebra), objects (valid and refused), succession certs (strict reading, each signer's signature, notarized
// certs), root's ⊤ on the sink (the exact payload the app signs, the vector's signature), grants by the mover and the
// merger; then the approval checks of ApprovalChecks.swift on certs made here with the same test keys (a new session,
// each add-on, and every refusal), the spawner binding of an add-on's machine, the rendering of known strings, JSON
// and raw text, and the app's signatures in the form the kernel takes (`GOLDEN_OUT`: the phone-signed draft and the
// root grant are written for the kernel's Go code to open, ios/ci/golden-verify).
// Usage: swift run Golden [<path to core/kernel/testdata>]   (default: ../../core/kernel/testdata from ios/interop)
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

let args = CommandLine.arguments
let dir = args.count > 1 ? args[1] : FileManager.default.currentDirectoryPath + "/../../core/kernel/testdata"
var failures = 0
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func refuses(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }
func load(_ name: String) -> Any { try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: dir + "/" + name))) }
func doc(_ v: Any?) -> SignedDoc { let d = v as! [String: Any]; return SignedDoc(payload: d["payload"] as! String, sig: d["sig"] as! String) }
func notarized(_ v: Any?) -> KNotarized { let d = v as! [String: Any]; return KNotarized(cert: doc(d["cert"]), challenge: doc(d["challenge"]), notarization: doc(d["notarization"])) }

// ---- the test keys ----
let keyFile = load("keys.json") as! [String: Any]
let roles = keyFile["roles"] as! [String: [String: String]]
func pub(_ r: String) -> String { roles[r]!["public"]! }
func priv(_ r: String) -> P256.Signing.PrivateKey {
  let hex = roles[r]!["scalar"]!
  let bytes = stride(from: 0, to: hex.count, by: 2).map { UInt8(hex[hex.index(hex.startIndex, offsetBy: $0)..<hex.index(hex.startIndex, offsetBy: $0 + 2)], radix: 16)! }
  return try! P256.Signing.PrivateKey(rawRepresentation: Data(bytes))
}
for r in roles.keys.sorted() { check(priv(r).publicKey.x963Representation.base64EncodedString() == pub(r), "test key \(r): scalar and public half agree") }
var roster = KRoster()
for r in KRoster.parts { roster.keys[r] = pub(r) }
let machineObj = try! KObject.parse(keyFile["machine"])
check(machineObj.kind == .machine, "keys.json's machine is a machine object")
func sign(_ payload: String, _ r: String) -> SignedDoc { SignedDoc(payload: payload, sig: try! priv(r).signature(for: Data(payload.utf8)).derRepresentation.base64EncodedString()) }

// ---- sets and pairs ----
for (i, c) in (load("sets.json") as! [[String: Any]]).enumerated() {
  let a = try! KSet.parse(c["a"]), b = try! KSet.parse(c["b"])
  let ok = a.subset(of: b) == (c["subset"] as! Bool) && (a == b) == (c["equal"] as! Bool)
    && a.intersect(b) == (try! KSet.parse(c["intersection"])) && a.union(b) == (try! KSet.parse(c["union"]))
  if !ok { check(false, "sets.json #\(i): \(a) vs \(b)") }
}
check(true, "sets.json: subset, equality, intersection and union of \((load("sets.json") as! [Any]).count) pairs of sets")
for (i, c) in (load("pairs.json") as! [[String: Any]]).enumerated() {
  func pair(_ v: Any?) -> KPair { let d = v as! [String: Any]; return KPair(allowed: try! KSet.parse(d["allowed"]), conditions: try! Kernel.strings(d["conditions"])) }
  let p = pair(c["p"]), q = pair(c["q"])
  if p.leq(q) != (c["leq"] as! Bool) || p.meet(q) != pair(c["meet"]) { check(false, "pairs.json #\(i)") }
}
check(true, "pairs.json: ≤ and ⊓ of \((load("pairs.json") as! [Any]).count) pairs")
check(refuses { _ = try KSet.parse(["only": ["b", "a"]]) }, "a set out of byte order is refused")
check(refuses { _ = try KSet.parse(["only": ["a", "a"]]) }, "a set with a string twice is refused")
check(refuses { _ = try KSet.parse(["only": [""]]) }, "a set with an empty string is refused")
check(refuses { _ = try KSet.parse(["only": [String(repeating: "x", count: 1025)]]) }, "a set with a 1025-byte string is refused")
check(refuses { _ = try KSet.parse(["only": [], "except": []]) }, "a set with both keys is refused")
check(KSet.everything.contains("anything") && !KSet.only(["a"]).contains("b") && !(try! KSet.parse(["except": ["shell"]])).contains("shell"), "membership of finite and cofinite sets")

// ---- objects ----
let objects = load("objects.json") as! [String: Any]
for o in objects["valid"] as! [Any] { check(!refuses { _ = try KObject.parse(o) }, "valid object \(Kernel.pretty(o).replacingOccurrences(of: "\n", with: " ").prefix(60))") }
for o in objects["invalid"] as! [Any] { check(refuses { _ = try KObject.parse(o) }, "refused object \(Kernel.pretty(o).replacingOccurrences(of: "\n", with: " ").prefix(60))") }

// ---- succession certs ----
for c in load("succession.json") as! [[String: Any]] {
  let name = c["name"] as! String, cert = doc(c["cert"])
  guard let s = try? KSuccession.parse(cert.payload) else { check(false, "\(name): reads strictly"); continue }
  let byItsSigner = CoreCrypto.valid(Data(cert.payload.utf8), sig: cert.sig, by: pub(s.signer))
  if c["notarization"] != nil, !(c["notarization"] is NSNull) {
    let signer = s.signer == "phone" || s.signer == "root" ? pub(s.signer) : nil
    check(byItsSigner && !refuses { _ = try Kernel.openNotarized(notarized(c), roster: roster, signerKey: signer) }, "\(name): signed by the \(s.signer) key, notarized")
  } else if name.contains("signed by the gullible key") {
    check(!byItsSigner, "\(name): not signed by the key it names")
  } else {
    check(byItsSigner, "\(name): read, signed by the \(s.signer) key (the notarizer refuses its shape: \((c["refused"] as? String) ?? "yes"))")
  }
}
let firstCert = (load("succession.json") as! [[String: Any]])[0]
var tampered = notarized(firstCert)
tampered = KNotarized(cert: tampered.cert, challenge: sign(tampered.challenge.payload, "gullible"), notarization: tampered.notarization)
check(refuses { _ = try Kernel.openNotarized(tampered, roster: roster, signerKey: pub("phone")) }, "a notarized cert whose challenge isn't the notary's is refused")
check(refuses { _ = try KSuccession.parse(#"{"kind":"succession","signer":"phone","predecessor":{"id":"sink"},"successor":{"id":"sink"},"allowed":{"except":[]},"conditions":[],"extra":1}"#) },
      "a cert with an unknown field is refused")
check(refuses { _ = try KSuccession.parse(#"{"kind":"succession","signer":"router","predecessor":{"id":"sink"},"successor":{"id":"sink"},"allowed":{"except":[]},"conditions":[]}"#) },
      "a cert naming an unknown signer is refused")
for c in (load("challenge.json") as! [String: Any])["invalid"] as! [Any] {
  let d = doc(c)
  let readable = (try? KChallenge.parse(d.payload)) != nil
  check(!readable || !CoreCrypto.valid(Data(d.payload.utf8), sig: d.sig, by: pub("notary")), "challenge.json invalid vector refused")
}
for c in (load("challenge.json") as! [String: Any])["valid"] as! [Any] {
  let d = doc(c)
  check((try? KChallenge.parse(d.payload)) != nil && CoreCrypto.valid(Data(d.payload.utf8), sig: d.sig, by: pub("notary")), "challenge.json valid vector reads and is the notary's")
}

// ---- grants and root's ⊤ ----
let grants = load("grants.json") as! [String: Any]
let rootDoc = doc(grants["root"])
check(rootDoc.payload == Kernel.rootGrantPayload, "root's ⊤ on the sink: the app's payload is the vector's, byte for byte")
check(CoreCrypto.valid(Data(rootDoc.payload.utf8), sig: rootDoc.sig, by: pub("root")), "the vector's root grant verifies with the root key")
let rootG = try? KGrant.parse(Kernel.rootGrantPayload)
check(rootG?.by == "root" && rootG?.machine == .sink && rootG?.pair.isTop == true && rootG?.from == [], "the root payload reads as ⊤ on the sink by root")
let mySig = try! priv("root").signature(for: Data(Kernel.rootGrantPayload.utf8)).derRepresentation.base64EncodedString()
check(CoreCrypto.valid(Data(Kernel.rootGrantPayload.utf8), sig: mySig, by: pub("root")), "the app's root signature (DER, base64) verifies")
for c in grants["cases"] as! [[String: Any]] {
  guard let result = c["result"] else { continue }
  let g = doc(result)
  check(!refuses { _ = try Kernel.openGrant(g, roster: roster) }, "grants.json \(c["name"] as! String): the \((try? KGrant.parse(g.payload))?.by ?? "?")'s grant reads and verifies")
}
check(refuses { _ = try Kernel.openGrant(sign(doc((grants["cases"] as! [[String: Any]])[0]["result"]).payload, "gullible"), roster: roster) }, "a mover's grant signed with another key is refused")

// ---- approvals: certs drafted as the router drafts them, checked as the app checks them ----
let now = Kernel.untilDate("2026-10-14T12:00:00Z")!
let sid = "s4f0000000000000a"
func challengeFor(_ payload: String, _ seq: Int = 0) -> SignedDoc {
  let p = #"{"kind":"challenge","seq":\#(seq),"prev":"","at":"2026-10-14T12:00:00.000000001Z","subject":"\#(CoreCrypto.sha256hex(Data(payload.utf8)))","about":"succession","nonce":"0000000000000000000000000000000a"}"#
  return sign(p, "notary")
}
func json(_ v: Any) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self) }
/// the router's draftPayload: Go's json.Marshal of kernel.Succession (field order kind, signer, predecessor, successor, allowed, conditions)
func objJSON(_ o: KObject) -> String {
  var parts = [#""id":\#(json([o.id]).dropFirst().dropLast())"#]
  for (k, v) in [("image", o.image), ("settings", o.settings), ("snapshot", o.snapshot), ("signingKey", o.signingKey), ("encryptionKey", o.encryptionKey)] where !v.isEmpty {
    parts.append("\"\(k)\":" + json([v]).dropFirst().dropLast())
  }
  return "{" + parts.joined(separator: ",") + "}"
}
func draft(_ pred: KObject, _ succ: KObject, _ allowed: KSet, _ conds: [String]) -> String {
  #"{"kind":"succession","signer":"phone","predecessor":\#(objJSON(pred)),"successor":\#(objJSON(succ)),"allowed":\#(json(allowed.json)),"conditions":\#(json(conds))}"#
}
func dto(_ kind: String, _ payloads: [String], cmd: String? = nil, store: String? = nil, session: String = sid) -> ApprovalDTO {
  ApprovalDTO(id: "a1", kind: kind, session: session, drafts: payloads.enumerated().map { .init(payload: $0.element, challenge: challengeFor($0.element, $0.offset)) }, cmd: cmd, store: store)
}
let image = "ghcr.io/de0ch/jarvis2-session:1@sha256:" + String(repeating: "1", count: 64)
let settingsText = json(["v": 1, "session": sid, "harness": "claude", "permissionMode": "auto", "title": "t", "prompt": "hi", "model": "claude-opus-5-5"])
let srcX = KObject(id: "source-" + String(repeating: "0", count: 31) + "1", image: image, settings: settingsText)
let newSession = draft(.sink, srcX, .only(["store:claude", "store:default"]), ["session:" + sid])
let ns = try? Checks.review(dto("new-session", [newSession]), notaryKey: pub("notary"), now: now)
check(ns != nil && ns?.stores == ["claude", "default"] && ns?.harness == "claude" && ns?.title == "t", "new session: read, its stores and settings")
check(!refuses { try Checks.matchesPicked(ns!, stores: ["default"], harnessStores: ["claude"], harness: "claude", permissionMode: "auto",
                                            settings: .init(label: "t", prompt: "hi", model: "claude-opus-5-5", repos: [], oneShot: false, apiProxy: false)) },
      "new session: exactly what the page picked")
check(refuses { try Checks.matchesPicked(ns!, stores: ["default"], harnessStores: ["claude"], harness: "claude", permissionMode: "bypass",
                                           settings: .init(label: "t", prompt: "hi", model: "", repos: [], oneShot: false, apiProxy: false)) },
      "new session: another permission mode is refused")
check(refuses { try Checks.matchesPicked(ns!, stores: ["default"], harnessStores: ["claude"], harness: "claude", permissionMode: "auto",
                                           settings: .init(label: "t", prompt: "other", model: "", repos: [], oneShot: false, apiProxy: false)) },
      "new session: another first prompt is refused")
check(refuses { _ = try Checks.onlyHarnessExtras(ns!, picked: ["default"], pinnedHarness: []) }, "new session: a store neither picked nor the harness's (pinned) is refused")
check(refuses { _ = try Checks.review(dto("new-session", [newSession], session: "s0ther"), notaryKey: pub("notary"), now: now) }, "new session: settings naming another session are refused")
check(refuses { _ = try Checks.review(dto("new-session", [draft(.sink, srcX, .everything, ["session:" + sid])]), notaryKey: pub("notary"), now: now) }, "new session: everything instead of stores is refused")
check(refuses { _ = try Checks.review(dto("new-session", [draft(.sink, srcX, .only(["store:default", "shell"]), ["session:" + sid])]), notaryKey: pub("notary"), now: now) }, "new session: a shell beside the stores is refused")
var badCh = dto("new-session", [newSession]); badCh = ApprovalDTO(id: "a1", kind: "new-session", session: sid, drafts: [.init(payload: newSession, challenge: challengeFor(newSession + " "))])
check(refuses { _ = try Checks.review(badCh, notaryKey: pub("notary"), now: now) }, "a draft whose challenge is over another payload is refused")
let notPhone = newSession.replacingOccurrences(of: #""signer":"phone""#, with: #""signer":"root""#)
check(refuses { _ = try Checks.review(dto("new-session", [notPhone]), notaryKey: pub("notary"), now: now) }, "a draft for the root key to sign is refused on an approval")
check(refuses { _ = try Checks.review(dto("grant", [newSession]), notaryKey: pub("notary"), now: now) }, "an approval kind the app doesn't know is refused")
let snapX = KObject(id: srcX.id, image: image, settings: settingsText, snapshot: String(repeating: "ab", count: 32))
check(!refuses { _ = try Checks.review(dto("resume-upgrade", [draft(.sink, snapX, .only(["store:default"]), ["session:" + sid])]), notaryKey: pub("notary"), now: now) }, "resume-upgrade: a source from the snapshot")
check(refuses { _ = try Checks.review(dto("resume-upgrade", [newSession]), notaryKey: pub("notary"), now: now) }, "resume-upgrade: a source with no snapshot is refused")

// add-ons: (sink, source-a, P_add) and (source-a, M, ⊤)
let srcA = KObject(id: "source-" + String(repeating: "a", count: 32))
let until = "until:2026-10-14T12:10:00Z"
let term1 = draft(.sink, srcA, .only(["shell"]), ["session:" + sid, until]), term2 = draft(srcA, machineObj, .everything, [])
let term = try? Checks.review(dto("terminal", [term1, term2]), notaryKey: pub("notary"), now: now)
check(term?.machine == machineObj && term?.until == Kernel.untilDate("2026-10-14T12:10:00Z"), "terminal: read, its machine and until")
check(refuses { _ = try Checks.review(dto("terminal", [draft(.sink, srcA, .only(["shell"]), ["session:" + sid, "until:2026-10-14T13:00:00Z"]), term2]), notaryKey: pub("notary"), now: now) },
      "terminal: an hour is refused (at most 10 minutes)")
check(refuses { _ = try Checks.review(dto("terminal", [draft(.sink, srcA, .everything, ["session:" + sid, until]), term2]), notaryKey: pub("notary"), now: now) }, "terminal: everything instead of a shell is refused")
check(refuses { _ = try Checks.review(dto("terminal", [term1, draft(KObject(id: "source-" + String(repeating: "b", count: 32)), machineObj, .everything, [])]), notaryKey: pub("notary"), now: now) },
      "terminal: a second cert from another source is refused")
check(refuses { _ = try Checks.review(dto("terminal", [term1, draft(srcA, machineObj, .only(["shell"]), [])]), notaryKey: pub("notary"), now: now) }, "terminal: a second cert that isn't ⊤ is refused")
check(refuses { _ = try Checks.review(dto("terminal", [draft(.sink, srcA, .only(["shell"]), ["session:s0ther", until]), term2]), notaryKey: pub("notary"), now: now) }, "terminal: another session's condition is refused")
let cmd = "git -C ~/workspace/x status"
let cmdConds = ["cmd:" + CoreCrypto.sha256hex(Data(cmd.utf8)), "once:" + String(repeating: "c", count: 32), "session:" + sid, until].sorted(by: Kernel.byteLess)
let cmd1 = draft(.sink, srcA, .only(["shell"]), cmdConds)
check(!refuses { _ = try Checks.review(dto("command", [cmd1, term2], cmd: cmd), notaryKey: pub("notary"), now: now) }, "command: this command, once, this session, until")
check(refuses { _ = try Checks.review(dto("command", [cmd1, term2], cmd: "rm -rf ~"), notaryKey: pub("notary"), now: now) }, "command: a draft for another command than the one shown is refused")
let add1 = draft(.sink, srcA, .only(["store:gmail"]), ["session:" + sid])
check(!refuses { _ = try Checks.review(dto("add-store", [add1, term2], store: "gmail"), notaryKey: pub("notary"), now: now) }, "add-store: this store on this session")
check(refuses { _ = try Checks.review(dto("add-store", [add1, term2], store: "default"), notaryKey: pub("notary"), now: now) }, "add-store: another store than the one shown is refused")

// the machine an add-on reaches: the spawner's notarized spawn cert, out of this session's source
func notarize(_ cert: SignedDoc) -> KNotarized {
  let ch = challengeFor(cert.payload)
  let n = sign(#"{"kind":"notarization","cert":"\#(Kernel.id(cert))","challenge":"\#(Kernel.id(ch))"}"#, "notarizer")
  return KNotarized(cert: cert, challenge: ch, notarization: n)
}
func spawnCert(_ src: KObject, _ m: KObject) -> KNotarized {
  let p = #"{"kind":"succession","signer":"spawner","predecessor":\#(objJSON(src)),"successor":\#(objJSON(m)),"allowed":{"except":[]},"conditions":[]}"#
  return notarize(sign(p, "spawner"))
}
let spawned = try? Checks.machineOf(term!, spawn: spawnCert(srcX, machineObj), roster: roster)
check(spawned?["title"] as? String == "t", "add-on: the machine is the session's (the spawner's notarized spawn cert), titled from its source")
let otherSettings = json(["v": 1, "session": "s0ther", "harness": "claude", "permissionMode": "auto"])
check(refuses { _ = try Checks.machineOf(term!, spawn: spawnCert(KObject(id: srcX.id, image: image, settings: otherSettings), machineObj), roster: roster) }, "add-on: a machine of another session is refused")
var forged = spawnCert(srcX, machineObj); forged = KNotarized(cert: sign(forged.cert.payload, "gullible"), challenge: forged.challenge, notarization: forged.notarization)
check(refuses { _ = try Checks.machineOf(term!, spawn: forged, roster: roster) }, "add-on: a spawn cert not signed by the spawner is refused")

// ---- rendering: known strings readably, unknown JSON pretty-printed, anything else raw ----
let facts = SignedAction.approval(term!)
check(SignedAction.value(facts, "action") == "Open a terminal", "rendered: the action")
check(facts.contains { $0.label == "Allows shell" } && facts.contains { $0.label == "If session" && $0.value == sid }, "rendered: the shell and the session condition")
check(facts.contains { $0.label == "If until" }, "rendered: until as a date")
check(SignedAction.value(facts, "d2-to") == "Machine " + machineObj.id && SignedAction.value(facts, "d2-to-signing") == machineObj.signingKey, "rendered: the machine object with its keys")
let cmdFacts = SignedAction.approval(try! Checks.review(dto("command", [cmd1, term2], cmd: cmd), notaryKey: nil, now: now), cmd: cmd)
check(cmdFacts.contains { $0.label == "If command" && $0.value == cmd }, "rendered: a command condition as the command whose sha256 it names")
check(SignedAction.element("store:default").label == "Store" && SignedAction.element("store:default").value == "default", "rendered: store:x")
check(SignedAction.element(#"{"b":1,"a":[2]}"#).label == "JSON" && SignedAction.element(#"{"b":1,"a":[2]}"#).value.contains("\n"), "rendered: unknown JSON pretty-printed")
check(SignedAction.element("weird:thing").value == "weird:thing" && SignedAction.element("weird:thing").label == "String", "rendered: anything else exactly as it is")
let nsFacts = SignedAction.approval(ns!)
check(SignedAction.value(nsFacts, "d1-to-settings-title") == "t" && SignedAction.value(nsFacts, "d1-to-settings-mode") == "auto" && SignedAction.value(nsFacts, "d1-to-image") == image,
      "rendered: a new source's image and settings")
let oddSettings = json(["v": 1, "session": sid, "harness": "claude", "permissionMode": "auto", "future": ["x": 1]])
let oddFacts = SignedAction.settings(oddSettings, id: "s")
check(oddFacts.contains { $0.id == "s-other" && $0.value.contains("\"future\"") }, "rendered: settings the app doesn't know, pretty-printed")
check(SignedAction.settings("not json", id: "s").first?.value == "not json", "rendered: settings that aren't JSON, exactly as they are")
check(SignedAction.value(SignedAction.rootGrant(), "payload") == Kernel.rootGrantPayload, "rendered: the root grant's exact text")

// ---- signatures in the kernel's form: written for the kernel's Go code to open (ios/ci/golden-verify) ----
if let out = ProcessInfo.processInfo.environment["GOLDEN_OUT"] {
  let phoneSigned = sign(newSession, "phone")
  let root = SignedDoc(payload: Kernel.rootGrantPayload, sig: mySig)
  let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  try! enc.encode(["draft": phoneSigned, "root": root]).write(to: URL(fileURLWithPath: out))
  print("wrote \(out)")
}

print(failures == 0 ? "all golden checks passed" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
