import XCTest

/// Every switch between the React Native extension and the shell's secure pages, one after another with pauses
/// between them, while transitions.yml records the simulator's screen (`simctl io recordVideo`). The test checks
/// only that each page arrives; the recording (frames cut out per transition by ci/transition-frames.sh) is what
/// shows whether a switch flashes, jumps or sticks. Each tap's wall-clock time goes into the `marks` attachment.
final class TransitionsUITests: XCTestCase {
  let app = XCUIApplication()
  let env = ProcessInfo.processInfo.environment
  var marks: [(String, Double)] = []

  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any)[id] }
  func prefixed(_ p: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", p)).firstMatch }
  @discardableResult func wait(_ e: XCUIElement, _ s: TimeInterval, _ what: String) -> Bool {
    let ok = e.waitForExistence(timeout: s)
    XCTAssertTrue(ok, what)
    return ok
  }
  /// tap and note the time: the recording around this moment is the transition `name`
  func tapMarked(_ e: XCUIElement, _ name: String) {
    marks.append((name, Date().timeIntervalSince1970))
    e.tap()
  }
  /// time for a transition to finish and the screen to settle before the next one
  func settle() { sleep(3) }

  func testTransitions() {
    continueAfterFailure = true
    let kit = env["JARVIS2_KIT"] ?? ""
    defer {
      let a = XCTAttachment(string: marks.map { String(format: "%.3f %@", $0.1, $0.0) }.joined(separator: "\n"))
      a.name = "marks"; a.lifetime = .keepAlways; add(a)
    }
    app.launch()

    // 1. first launch: Reset or recover comes up by itself (no picture of the app under it yet); Recover, then
    //    Done leaves it for the app
    guard wait(el("setup-state-empty"), 60, "setup page at launch") else { return }
    settle()
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "kit field") else { return }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return }
    settle()
    tapMarked(el("secure-back"), "launch-setup-done")
    guard wait(el("newBtn"), 120, "session list") else { return }
    settle(); settle()

    // 2. stores: the tab → the secure stores page → Back
    el("tab-stores").tap()
    wait(el("stores-manage"), 20, "stores tab")
    settle()
    tapMarked(el("stores-manage"), "stores-enter")
    wait(el("unlock-default"), 30, "secure stores page")
    settle()
    tapMarked(el("secure-back"), "stores-back")
    wait(el("stores-manage"), 20, "stores tab again")
    settle()

    // 3. new session: + New session → the one secure page → Back; again, with the keyboard up on the page when Back
    //    is tapped; again → Start (leaves as done over the list)
    el("tab-sessions").tap()
    wait(el("newBtn"), 10, "list")
    settle()
    tapMarked(el("newBtn"), "newsession-enter")
    wait(el("secure-create"), 20, "secure new session page")
    settle()
    tapMarked(el("secure-back"), "newsession-back")
    wait(el("newBtn"), 20, "the list again")
    settle()
    tapMarked(el("newBtn"), "newsession-enter-2")
    wait(el("ns-title"), 20, "secure new session page (2)")
    el("ns-title").tap(); el("ns-title").typeText("transitions")
    settle()
    tapMarked(el("secure-back"), "newsession-back-keyboard")
    wait(el("newBtn"), 20, "the list again (2)")
    settle()
    tapMarked(el("newBtn"), "newsession-enter-3")
    wait(el("secure-create"), 20, "secure new session page (3)")
    settle()
    tapMarked(el("secure-create"), "newsession-start")
    wait(prefixed("more-"), 120, "the new session's card after Start")
    settle(); settle()

    // 4. a grant: More → Grants… → the secure grant page → Back, then again → Allow
    if wait(prefixed("more-"), 60, "more button") {
      el(prefixed("more-").identifier).tap()
      wait(el("menu-grants-"), 10, "menu grants")
      el("menu-grants-").tap()
      if wait(el("grant-review"), 20, "grants page") {
        settle()
        el("grant-holder-terminal").tap(); el("grant-len-10").tap()
        tapMarked(el("grant-review"), "grant-enter")
        if wait(el("grant-meaning"), 30, "secure grant page") {
          settle()
          tapMarked(el("secure-back"), "grant-deny")
        }
        wait(el("grant-review"), 20, "grants page again")
        settle()
        tapMarked(el("grant-review"), "grant-enter-2")
        if wait(el("grant-meaning"), 30, "secure grant page (2)") {
          settle()
          tapMarked(el("secure-grant-allow"), "grant-allow")
          wait(el("grant-forget-terminal"), 60, "grant listed")
        }
        settle()
        el("page-back").tap()
      }
    }

    // 5. Settings → Reset or recover… (a picture of the app under it this time) → Back
    el("tab-settings").tap()
    if wait(el("open-setup"), 20, "settings") {
      settle()
      tapMarked(el("open-setup"), "setup-enter")
      wait(el("setup-state-mine"), 30, "setup page")
      settle()
      tapMarked(el("secure-back"), "setup-back")
      wait(el("open-setup"), 20, "settings again")
      settle()
    }

    // 6. the same switches with the app sent to the background and back in between (a resumed scene)
    el("tab-stores").tap()
    wait(el("stores-manage"), 20, "stores tab")
    settle()
    tapMarked(el("stores-manage"), "stores-enter-2")
    wait(el("unlock-default"), 30, "secure stores page")
    settle()
    XCUIDevice.shared.press(.home)
    sleep(2)
    app.activate()
    settle()
    tapMarked(el("secure-back"), "stores-back-after-background")
    wait(el("stores-manage"), 20, "stores tab again")
    settle()
    app.terminate()
  }
}
