import XCTest

/// Walks Jarvis 2 on a simulator against the REAL core (built with -tags fakefly, the public TEST master key)
/// and router running on the CI runner, with the backups on a local S3 stand-in, keeping a screenshot of every
/// step. CI runs it once per appearance (light, then dark), each time against a fresh core and router and a
/// reset simulator keychain, so each pass recovers from scratch: recovery (8 words, the test master key, the
/// stand-in bucket's keys) → stores (create, unlock) → new session (secure page, software key) → pause →
/// resume → resume with the latest image (approval) → destroy → records → the master key page.
final class Jarvis2UITests: XCTestCase {
  let app = XCUIApplication()
  var tag = "run"
  var step = 0
  let env = ProcessInfo.processInfo.environment

  func shot(_ name: String) {
    step += 1
    let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
    a.name = String(format: "%@-%02d-%@", tag, step, name); a.lifetime = .keepAlways; add(a)
  }
  func note(_ name: String, _ text: String) { let a = XCTAttachment(string: text); a.name = name; a.lifetime = .keepAlways; add(a) }
  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any)[id] }
  func prefixed(_ p: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", p)).firstMatch }
  @discardableResult func wait(_ e: XCUIElement, _ s: TimeInterval, _ what: String) -> Bool {
    let ok = e.waitForExistence(timeout: s)
    XCTAssertTrue(ok, "[\(tag)] \(what)")
    if !ok { note("\(tag)-tree-\(what)", app.debugDescription); shot("missing-" + what.replacingOccurrences(of: " ", with: "-")) }
    return ok
  }
  func gone(_ e: XCUIElement, _ s: TimeInterval) -> Bool {
    let until = Date().addingTimeInterval(s)
    while e.exists && Date() < until { usleep(300_000) }
    return !e.exists
  }

  func testWalkthrough() {
    continueAfterFailure = true
    tag = env["JARVIS2_APPEARANCE"] ?? "run"
    app.launch()

    // ---- recovery: the core's 8 words (checked against the box key), then the kit
    guard wait(el("recovery-words"), 60, "recovery page with the core's words") else { return }
    XCTAssertEqual(el("recovery-words").label, env["JARVIS2_WORDS"] ?? "", "[\(tag)] the 8 words are the core's own")
    shot("recovery")
    let master = el("recovery-master")
    wait(master, 10, "master key field")
    master.tap(); master.typeText(env["JARVIS2_MASTER_KIT"] ?? "")
    let s3 = el("recovery-s3")
    s3.tap(); s3.typeText(env["JARVIS2_S3_KIT"] ?? "")
    shot("recovery-kit-pasted")
    el("recovery-go").tap()
    sleep(1)
    shot("recovering")

    // ---- the React Native list (in the extension)
    guard wait(el("newBtn"), 120, "session list") else { return }
    sleep(2)
    shot("sessions-empty")

    // ---- unlock the default store on the secure stores page (split key: the phone's share + the core's)
    el("tab-stores").tap()
    wait(el("stores-manage"), 20, "stores tab")
    sleep(2)
    shot("stores-tab")
    el("stores-manage").tap()
    wait(el("unlock-default"), 30, "secure stores page")
    sleep(1)
    shot("secure-stores")
    XCTAssertFalse(el("unlock-core").exists, "[\(tag)] the core's own store is not a store anyone sees")
    XCTAssertFalse(el("mark-marked").exists, "[\(tag)] a store with a sensitive marker in the backups came back sensitive")
    XCTAssertTrue(el("mark-default").exists, "[\(tag)] default came back not sensitive")
    // a new, empty store
    let nm = el("store-new-name")
    nm.tap(); nm.typeText("ci-notes")
    el("store-create").tap()
    wait(el("mark-ci-notes"), 20, "created store listed (empty, not sensitive)")
    el("unlock-default").tap()
    wait(el("lock-default"), 30, "default unlocked (core's signed unlocked list)")
    XCTAssertFalse(el("secure-error").exists, "[\(tag)] unlock error: \(el("secure-error").exists ? el("secure-error").label : "")")
    shot("secure-stores-unlocked")
    el("secure-back").tap()
    wait(el("stores-manage"), 20, "back to the stores tab")
    sleep(2)
    shot("stores-tab-after")
    el("tab-sessions").tap()

    // ---- new session: the form (normal mode) → the shell's secure page → Create (one signature)
    wait(el("newBtn"), 10, "list again")
    el("newBtn").tap()
    wait(el("ns-start"), 15, "new session form")
    sleep(2)
    shot("new-session-form")
    el("ns-start").tap()
    wait(el("secure-create"), 20, "secure new session page")
    sleep(2)
    shot("secure-new-session")
    XCTAssertTrue(el("secure-store-default").exists, "[\(tag)] default offered")
    XCTAssertFalse(el("secure-store-core").exists, "[\(tag)] the core store is not offered to a session")
    XCTAssertFalse(el("secure-store-claude-login").exists, "[\(tag)] the harness's own store is not offered")
    if el("secure-store-gmail").waitForExistence(timeout: 5) {
      el("secure-store-gmail").tap(); sleep(1)
      XCTAssertTrue(el("secure-sensitive-warning").exists, "[\(tag)] sensitive warning")
      shot("secure-sensitive-picked")
      el("secure-store-gmail").tap(); sleep(1)
    }
    el("secure-create").tap()
    for _ in 0..<3 { shot("creating"); sleep(2) }
    let created = el("newBtn").waitForExistence(timeout: 180)
    XCTAssertTrue(created, "[\(tag)] back to the list after Create")
    if el("secure-error").exists { note("\(tag)-create-error", el("secure-error").label); shot("create-error"); return }
    sleep(3)
    shot("session-created")

    // ---- pause → resume (same image: the core's dead-machine responder, no approval)
    guard wait(prefixed("pause-"), 60, "pause button") else { return }
    el(prefixed("pause-").identifier).tap()
    sleep(1)
    shot("pausing")
    guard wait(prefixed("resume-"), 90, "paused session") else { return }
    sleep(1)
    shot("paused")
    el(prefixed("resume-").identifier).tap()
    sleep(1)
    shot("resuming")
    guard wait(prefixed("pause-"), 120, "resumed session") else { return }
    sleep(1)
    shot("resumed")

    // ---- resume with the latest image: pause, then More → the approval opens on the secure page
    el(prefixed("pause-").identifier).tap()
    guard wait(prefixed("resume-"), 90, "paused again") else { return }
    el(prefixed("more-").identifier).tap()
    wait(el("menu-resume-with-latest-image"), 10, "menu")
    shot("more-menu")
    el("menu-resume-with-latest-image").tap()
    wait(el("ask-ok"), 10, "upgrade question")
    shot("upgrade-question")
    el("ask-ok").tap()
    if wait(el("secure-approve"), 120, "resume-upgrade approval page") {
      sleep(2)
      shot("secure-approval-upgrade")
      el("secure-approve").tap()
      XCTAssertTrue(el("newBtn").waitForExistence(timeout: 60), "[\(tag)] back after approving")
      if el("secure-error").exists { note("\(tag)-approve-error", el("secure-error").label); shot("approve-error") }
      sleep(3)
      shot("upgraded")
    }

    // ---- destroy → records
    guard wait(prefixed("more-"), 60, "more button") else { return }
    el(prefixed("more-").identifier).tap()
    wait(el("menu-destroy"), 10, "menu destroy")
    el("menu-destroy").tap()
    wait(el("ask-ok"), 10, "destroy question")
    shot("destroy-question")
    el("ask-ok").tap()
    XCTAssertTrue(gone(prefixed("more-"), 90), "[\(tag)] session gone from the list")
    sleep(1)
    shot("destroyed")
    el("tab-records").tap()
    sleep(3)
    shot("records")
    el("tab-settings").tap()
    sleep(2)
    shot("settings")

    // ---- the master key page (smoke): a fresh pair, the private kit and the public key
    el("open-master-key").tap()
    if wait(el("master-private"), 20, "master key page") {
      XCTAssertTrue(el("master-private").label.hasPrefix("jarvis2-master:MIG"), "[\(tag)] private kit \(el("master-private").label.prefix(20))")
      XCTAssertTrue(el("master-public").label.hasPrefix("B"), "[\(tag)] public key (x963 base64)")
      shot("master-key")
      el("secure-back").tap()
      wait(el("open-master-key"), 20, "back to settings")
    }
    app.terminate()
  }
}
