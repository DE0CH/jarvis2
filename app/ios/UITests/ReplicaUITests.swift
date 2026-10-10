import XCTest

/// The phone replica (infra/phone-replica.sh, .github/workflows/replica.yml): the RELEASE build on the simulator
/// closest to Deyao's iPhone, against a real throwaway box (its own Cloudflare tunnel + Access login, core, router,
/// backups) and real Fly sessions, every flow tapped as a person would. Face ID is enrolled on the simulator and
/// each match or failure is sent by the runner (the host helper, ios/ci/replica-host.py, on 127.0.0.1:18300),
/// which also relays to the setup session (the Access login code from the bot's mailbox; "reset done" → the stores
/// are written). A step fails on a blank screen (no expected element within its time, or a near-uniform
/// screenshot), a stuck state (a session not running within its time) or a broken transition.
final class ReplicaUITests: XCTestCase {
  let app = XCUIApplication()
  let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
  let safari = XCUIApplication(bundleIdentifier: "com.apple.SafariViewService")
  let env = ProcessInfo.processInfo.environment
  var step = 0
  var kit = ""

  // ---- evidence ----
  func shot(_ name: String) {
    step += 1
    let s = XCUIScreen.main.screenshot()
    let a = XCTAttachment(screenshot: s)
    a.name = String(format: "replica-%02d-%@", step, name); a.lifetime = .keepAlways; add(a)
    XCTAssertFalse(blank(s.image), "blank screen at \(name)")
  }
  /// a blank screen (a white or black page with nothing drawn on it): below the status bar, fewer than 0.2% of the
  /// sampled pixels differ from the page's background colour (any text or control is far more)
  func blank(_ img: UIImage) -> Bool {
    guard let cg = img.cgImage, let data = cg.dataProvider?.data, let p = CFDataGetBytePtr(data) else { return false }
    let bpr = cg.bytesPerRow, bpp = cg.bitsPerPixel / 8
    let y0 = cg.height * 12 / 100
    let bg = (Int(p[y0 * bpr + 4 * bpp]), Int(p[y0 * bpr + 4 * bpp + 1]), Int(p[y0 * bpr + 4 * bpp + 2]))
    var n = 0, differ = 0
    for y in stride(from: y0, to: cg.height, by: 4) {
      for x in stride(from: 0, to: cg.width, by: 4) {
        let o = y * bpr + x * bpp
        n += 1
        if abs(Int(p[o]) - bg.0) > 24 || abs(Int(p[o + 1]) - bg.1) > 24 || abs(Int(p[o + 2]) - bg.2) > 24 { differ += 1 }
      }
    }
    return n > 0 && differ * 500 < n
  }
  func note(_ name: String, _ text: String) { let a = XCTAttachment(string: text); a.name = name; a.lifetime = .keepAlways; add(a) }
  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any)[id] }
  func prefixed(_ p: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", p)).firstMatch }
  @discardableResult func wait(_ e: XCUIElement, _ s: TimeInterval, _ what: String) -> Bool {
    let ok = e.waitForExistence(timeout: s)
    XCTAssertTrue(ok, what)
    if !ok { note("tree-\(what)", app.debugDescription); shot("missing-" + what.replacingOccurrences(of: " ", with: "-")) }
    return ok
  }
  func gone(_ e: XCUIElement, _ s: TimeInterval) -> Bool {
    let until = Date().addingTimeInterval(s)
    while e.exists && Date() < until { usleep(300_000) }
    return !e.exists
  }
  func must(_ ok: Bool) throws { if !ok { throw XCTSkip("stopping: an earlier step failed") } }

  // ---- the runner: Face ID and the relay to the setup session ----
  @discardableResult func host(_ path: String, timeout: TimeInterval = 30) -> String {
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var out = ""
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18300/" + path)!)
    r.timeoutInterval = timeout
    URLSession.shared.dataTask(with: r) { d, _, _ in out = String(decoding: d ?? Data(), as: UTF8.self); sem.signal() }.resume()
    _ = sem.wait(timeout: .now() + timeout + 5)
    return out
  }
  /// Face ID matches for the next `seconds` (one or more prompts), as a person looking at the phone
  func faceIDMatches(_ seconds: Int = 40) { host("faceid/match?for=\(seconds)") }
  func faceIDFails() { host("faceid/nomatch") }
  func relay(_ msg: String) -> String { host("relay?msg=\(msg)", timeout: 600) }

  // ---- the system around the app: backgrounding, a kill and relaunch ----
  func background(_ seconds: UInt32 = 5) {
    XCUIDevice.shared.press(.home)
    sleep(seconds)
    app.activate()
    sleep(2)
  }
  func relaunch() {
    app.terminate()
    sleep(2)
    app.launch()
  }

  // ---- the Access login, as on the phone: the system sheet, the email, the code from the mailbox ----
  func signInIfAsked(_ s: TimeInterval) {
    let cont = springboard.buttons["Continue"]
    guard cont.waitForExistence(timeout: s) else { return }
    shot("signin-ask")
    cont.tap()
    let email = [safari.textFields.firstMatch, app.webViews.textFields.firstMatch]
    guard let field = waitAny(email, 60) else { XCTFail("the Access login page didn't show"); shot("signin-blank"); return }
    shot("signin-page")
    field.tap(); field.typeText((env["REPLICA_EMAIL"] ?? "") + "\n")   // Return sends the form (the button sits under the keyboard)
    sleep(2)
    if field.exists && (field.value as? String ?? "").contains("@") { tapButton(["Send login code", "Send me a code", "Send code", "Continue"]) }
    // the code page's field (the email field is gone by then; never type the code into it)
    let notEmail = NSPredicate(format: "label != 'Email' AND placeholderValue != 'example@email.com'")
    let codeField = [safari.textFields.matching(notEmail).firstMatch, app.webViews.textFields.matching(notEmail).firstMatch]
    sleep(3)
    let code = relay("otp").trimmingCharacters(in: .whitespacesAndNewlines)
    XCTAssertEqual(code.count, 6, "a 6-digit Access code from the mailbox (got \(code.count) chars)")
    guard let cf = waitAny(codeField, 30) else { XCTFail("no code field"); return }
    cf.tap(); cf.typeText(code)
    shot("signin-code")
    cf.typeText("\n")
    sleep(2)
    if cf.waitForExistence(timeout: 1), !gone(cf, 8) { tapButton(["Sign in", "Log in", "Verify", "Submit", "Continue"]) }
  }
  func waitAny(_ es: [XCUIElement], _ s: TimeInterval) -> XCUIElement? {
    let until = Date().addingTimeInterval(s)
    while Date() < until { if let e = es.first(where: { $0.exists }) { return e }; usleep(500_000) }
    return nil
  }
  func tapButton(_ labels: [String]) {
    for l in labels {
      for b in [safari.buttons[l], app.webViews.buttons[l]] where b.exists { b.tap(); return }
    }
    XCTFail("no button \(labels) on the login page"); note("login-tree", safari.debugDescription)
  }

  /// + New session opens the shell's one-page New session (an older app: the React Native form first, then Start)
  func openNewSession() -> Bool {
    el("newBtn").tap()
    if el("ns-start").waitForExistence(timeout: 5) && !el("secure-create").exists { shot("new-session-form"); el("ns-start").tap() }
    let ok = wait(el("secure-create"), 60, "the New session page")
    if ok { sleep(1); shot("new-session") }
    return ok
  }

  func testReplica() throws {
    continueAfterFailure = true
    app.launch()
    signInIfAsked(30)

    // ---- Reset: a new kit, copied and confirmed; the core is set up with no stores ----
    try must(wait(el("setup-state-empty"), 180, "Reset or recover: the core is empty"))
    shot("setup-empty")
    el("setup-choose-reset").tap()
    try must(wait(el("setup-kit"), 30, "the new recovery kit"))
    kit = el("setup-kit").label
    XCTAssertTrue(kit.hasPrefix("jarvis2-kit:2:"), "the kit is one string (\(kit.prefix(16))…)")
    shot("setup-kit")
    background()   // mid-flow: the kit page survives backgrounding
    XCTAssertTrue(el("setup-kit").exists, "the kit page is still there after backgrounding")
    el("setup-kit-copy").tap()
    el("setup-kit-saved").tap()
    try must(wait(el("setup-done"), 120, "reset done"))
    shot("setup-reset-done")
    el("secure-back").tap()
    // the setup session fills the stores now (as after a real Reset)
    XCTAssertEqual(relay("reset-done"), "filled", "the setup session wrote the stores")

    // ---- stores: Face ID refused, then unlock and lock ----
    try must(wait(el("tab-stores"), 120, "the app's tabs"))
    el("tab-stores").tap()
    try must(wait(el("stores-manage"), 30, "stores tab"))
    sleep(2); shot("stores")
    el("stores-manage").tap()
    try must(wait(el("unlock-rh-plain"), 60, "secure stores page with rh-plain"))
    XCTAssertTrue(el("mark-rh-plain").exists, "rh-plain is not sensitive")
    XCTAssertFalse(el("mark-rh-secret").exists, "rh-secret is sensitive")
    shot("secure-stores")
    faceIDFails()
    el("unlock-rh-plain").tap()
    sleep(3)
    shot("faceid-failed")
    // the "Face Not Recognized" alert (Try Face ID Again / Cancel) comes from the system: whichever process shows it
    let laui = XCUIApplication(bundleIdentifier: "com.apple.LocalAuthenticationUIService")
    if let c = waitAny([app.buttons["Cancel"].firstMatch, springboard.buttons["Cancel"].firstMatch, laui.buttons["Cancel"].firstMatch], 20) { shot("faceid-not-recognized"); c.tap() } else { XCTFail("no Face Not Recognized alert") }
    XCTAssertTrue(wait(el("secure-error"), 20, "a failed Face ID leaves the store locked, with a message"), "Face ID failure shown")
    XCTAssertFalse(el("lock-rh-plain").exists, "no unlock without Face ID")
    faceIDMatches()
    el("unlock-rh-plain").tap()
    wait(el("lock-rh-plain"), 60, "rh-plain unlocked")
    shot("stores-unlocked")
    el("lock-rh-plain").tap()
    XCTAssertTrue(gone(el("lock-rh-plain"), 30), "rh-plain locked again")
    shot("stores-locked")
    el("secure-back").tap()

    // ---- new session: one page, its stores (and the harness's) unlocked with Face ID, running on Fly ----
    el("tab-sessions").tap()
    try must(wait(el("newBtn"), 30, "sessions tab"))
    try must(openNewSession())
    if wait(el("secure-store-rh-plain"), 30, "rh-plain offered") { el("secure-store-rh-plain").tap() }
    XCTAssertFalse(el("secure-store-claude").exists, "the harness's own store isn't offered")
    shot("secure-new-session")
    faceIDMatches(90)
    el("secure-create").tap()
    try must(wait(prefixed("term-"), 600, "the session is running on Fly (Terminal offered) within 10 minutes"))
    sleep(2); shot("session-running")
    let sid = String(prefixed("term-").identifier.dropFirst(5))
    note("session", sid)

    // ---- a kill and relaunch mid-flow: the session list comes back, no setup page, still signed in ----
    relaunch()
    signInIfAsked(10)
    XCTAssertFalse(el("setup-state-empty").waitForExistence(timeout: 10), "no Reset or recover after a relaunch")
    try must(wait(el("term-" + sid), 90, "the running session after a relaunch"))
    shot("after-relaunch")

    // ---- terminal: turned away → the grant page → Deny, then Allow with Face ID → a command runs ----
    el("term-" + sid).tap()
    try must(wait(el("term-in"), 30, "terminal page"))
    if wait(el("term-allow"), 60, "the terminal asks for a grant") {
      shot("terminal-needs-grant")
      el("term-allow").tap()
      if wait(el("secure-grant-allow"), 30, "the grant page") {
        shot("grant-page")
        el("secure-back").tap() // Deny
        XCTAssertTrue(wait(el("term-allow"), 20, "denied: still turned away"), "deny")
        el("term-allow").tap()
        wait(el("secure-grant-allow"), 30, "the grant page again")
        faceIDMatches()
        el("secure-grant-allow").tap()
        XCTAssertTrue(gone(el("secure-grant-allow"), 90), "the grant page closes after Face ID")
        XCTAssertTrue(wait(el("term-in"), 30, "back on the terminal") && gone(el("term-allow"), 60), "allowed: the terminal opens")
      }
    }
    let marker = "replica-\(Int.random(in: 1000...9999))"
    el("term-in").tap(); el("term-in").typeText("echo \(marker)-$((1+1))\n")
    if el("term-send").exists { el("term-send").tap() }
    let out = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "\(marker)-2")).firstMatch
    XCTAssertTrue(out.waitForExistence(timeout: 60), "the command's output on the terminal")
    shot("terminal-output")
    background(3)
    XCTAssertTrue(el("term-in").waitForExistence(timeout: 20), "the terminal survives backgrounding")
    el("term-close").tap()

    // ---- grants: More → Grants → a standing rule, then forget it ----
    if wait(el("more-" + sid), 30, "more button") {
      el("more-" + sid).tap()
      if wait(el("menu-grants-"), 10, "menu grants") {
        el("menu-grants-").tap()
        if wait(el("grant-new-rule"), 30, "grants page") {
          el("grant-new-rule").tap()
          if wait(el("secure-grant-allow"), 30, "rule page") {
            if el("grant-holder-scheduler").exists { el("grant-holder-scheduler").tap() }
            faceIDMatches()
            el("secure-grant-allow").tap()
            if wait(prefixed("grant-forget-"), 60, "the rule listed") {
              shot("grants")
              el(prefixed("grant-forget-").identifier).tap()
              if wait(el("ask-ok"), 10, "forget question") { el("ask-ok").tap() }
            }
          }
          if el("page-back").exists { el("page-back").tap() }
        }
      }
    }

    // ---- settings + repos: add the throwaway repo (its deploy key made by the core on a Face ID), remove it ----
    el("tab-settings").tap()
    sleep(2); shot("settings")
    let repo = env["REPLICA_REPO"] ?? ""
    let repoName = String(repo.split(separator: "/").last ?? "")
    if !repo.isEmpty, wait(el("repo-url"), 30, "the repos card") {
      el("repo-url").tap(); el("repo-url").typeText(repo + "\n")
      if wait(el("secure-repo-go"), 30, "the add-repo page") {
        shot("repo-add")
        faceIDMatches()
        el("secure-repo-go").tap()
        if wait(el("repo-key-" + repoName), 90, "the repo listed with its deploy key") {
          shot("repo-added")
          el("repo-remove-" + repoName).tap()
          if wait(el("secure-repo-go"), 30, "the remove-repo page") {
            faceIDMatches()
            el("secure-repo-go").tap()
            XCTAssertTrue(gone(el("repo-key-" + repoName), 90), "the repo is removed")
            shot("repo-removed")
          }
        }
        if el("secure-error").exists { note("repo-error", el("secure-error").label) }
      }
    }
    XCTAssertEqual(relay("repo-check"), "ok", "GitHub shows the deploy key added and removed")

    // ---- a session stuck at boot (its store locked again right after Create) is destroyed at once ----
    el("tab-sessions").tap()
    _ = wait(el("newBtn"), 30, "sessions tab")
    do {
      if openNewSession() {
        if wait(el("secure-store-rh-secret"), 30, "rh-secret offered") { el("secure-store-rh-secret").tap() }
        faceIDMatches(90)
        el("secure-create").tap()
        _ = wait(el("newBtn"), 120, "back on the list")
        // lock it before the machine boots (the image pull takes a minute or more)
        el("tab-stores").tap()
        if wait(el("stores-manage"), 30, "stores tab (stuck)") {
          el("stores-manage").tap()
          if wait(el("lock-rh-secret"), 30, "rh-secret unlocked by the new session") { el("lock-rh-secret").tap(); _ = gone(el("lock-rh-secret"), 30) }
          el("secure-back").tap()
        }
        el("tab-sessions").tap()
        sleep(150) // the machine boots and loops on the locked store
        shot("stuck-session")
        let mores = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'more-' AND identifier != %@", "more-" + sid))
        if mores.count > 0 {
          let stuck = mores.firstMatch.identifier
          el(stuck).tap()
          if wait(el("menu-destroy"), 10, "destroy (stuck)") {
            el("menu-destroy").tap()
            if wait(el("ask-ok"), 30, "destroy question (stuck)") { el("ask-ok").tap() }
            let t0 = Date()
            XCTAssertTrue(gone(el(stuck), 90), "a session stuck at boot is destroyed within 90 s")
            note("stuck-destroy-seconds", "\(Int(Date().timeIntervalSince(t0)))")
            shot("stuck-destroyed")
          }
        } else { XCTFail("no second session to destroy") }
      }
    }

    // ---- destroy the running session (it would end with the Recover anyway) ----
    if wait(el("more-" + sid), 30, "more button (destroy)") {
      el("more-" + sid).tap()
      if wait(el("menu-destroy"), 10, "menu destroy") {
        el("menu-destroy").tap()
        if wait(el("ask-ok"), 60, "destroy question") { el("ask-ok").tap() }
        let pill = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'destroying'")).firstMatch
        if pill.waitForExistence(timeout: 20) { note("destroy-pill", pill.label); shot("destroying") }
        XCTAssertTrue(gone(el("more-" + sid), 900), "the session is destroyed")
      }
    }

    // ---- Recover with the kit: Settings → Reset or recover → Recover (restart) → every store back ----
    el("tab-settings").tap()
    if wait(el("open-setup"), 30, "Reset or recover in Settings") {
      el("open-setup").tap()
      try must(wait(el("setup-choose-recover"), 60, "the setup page (set up: mine)"))
      shot("setup-mine")
      el("setup-choose-recover").tap()
      try must(wait(el("setup-kit-field"), 15, "kit field"))
      el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
      el("setup-recover-go").tap()
      if wait(el("setup-restart-confirm"), 30, "restart and recover") {
        shot("setup-restart")
        el("setup-restart-confirm").tap()
      }
      try must(wait(el("setup-done"), 600, "recovered"))
      shot("setup-recovered")
      el("secure-back").tap()
      el("tab-stores").tap()
      if wait(el("stores-manage"), 30, "stores after Recover") {
        el("stores-manage").tap()
        wait(el("unlock-rh-plain"), 60, "rh-plain back")
        XCTAssertTrue(el("mark-rh-plain").exists, "rh-plain came back not sensitive")
        XCTAssertTrue(el("unlock-rh-secret").exists && !el("mark-rh-secret").exists, "rh-secret came back sensitive")
        shot("stores-recovered")
        el("secure-back").tap()
      }
    }
    relaunch()
    XCTAssertTrue(el("tab-sessions").waitForExistence(timeout: 90), "the app opens after the Recover and a relaunch")
    shot("end")
    XCTAssertEqual(relay("done"), "ok")
  }
}
