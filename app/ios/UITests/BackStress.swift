import XCTest

/// Back (the button and the edge swipe) from the shell's secure pages, under the stress a real iPhone adds and a
/// calm walkthrough doesn't (Deyao, TestFlight build 77: "Tapping back from secure still sometimes get me the blank
/// screen"): repeated open/Back loops, Back while the page is still sliding in, a double tap, the swipe, Back after
/// the app sat in the background, after iOS ended the extension's process (SIGKILL, as jetsam does under memory
/// pressure), with the extension slow to come back (SIGSTOP for a few seconds), after a memory warning, and the
/// extension ended while the app itself is on screen. Each Back must bring the app's own `target` back with the
/// screen never blank (a near-uniform screenshot) for over 1.5 s on the way, and no secure page left over.
///
/// The runner's helper (ci/replica-host.py on 127.0.0.1:18300) kills/stops the extension and sends the memory
/// warning. Used by TransitionsUITests (transitions.yml) and ReplicaUITests (the gate before TestFlight).
struct BackStress {
  let test: XCTestCase
  let app: XCUIApplication
  var tag = "stress"
  /// screenshots on the way back (kept for the evidence)
  var keepShots = true

  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any)[id] }

  @discardableResult func host(_ path: String) -> String {
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var out = ""
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18300/" + path)!)
    r.timeoutInterval = 20
    URLSession.shared.dataTask(with: r) { d, _, _ in out = String(decoding: d ?? Data(), as: UTF8.self); sem.signal() }.resume()
    _ = sem.wait(timeout: .now() + 25)
    return out
  }

  func attach(_ s: XCUIScreenshot, _ name: String) {
    guard keepShots else { return }
    let a = XCTAttachment(screenshot: s); a.name = "\(tag)-\(name)"; a.lifetime = .keepAlways; test.add(a)
  }
  func note(_ name: String, _ text: String) { let a = XCTAttachment(string: text); a.name = "\(tag)-\(name)"; a.lifetime = .keepAlways; test.add(a) }

  /// a blank screen: below the status bar, fewer than 0.2% of the sampled pixels differ from the background colour
  static func blank(_ img: UIImage) -> Bool {
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

  /// watches the screen by screenshots for `pixelsFor` seconds (no accessibility queries: they hang on a stopped
  /// extension), failing on a blank stretch over `blank` s; then `target` must exist within `s` with no secure page
  @discardableResult func backArrives(_ target: XCUIElement, _ s: TimeInterval, _ what: String, pixelsFor: TimeInterval = 4, blank: TimeInterval = 1.5) -> Bool {
    let t0 = Date()
    var blankSince: Date?, worst: TimeInterval = 0, failed = false
    func look() {
      let shot = XCUIScreen.main.screenshot()
      if BackStress.blank(shot.image) {
        if blankSince == nil { blankSince = Date(); attach(shot, "blank-start-\(what)") }
        let d = Date().timeIntervalSince(blankSince!)
        worst = max(worst, d)
        if d > blank && !failed {
          failed = true
          attach(shot, "BLANK-\(what)")
          XCTFail("[\(tag)] blank screen for over \(blank) s after leaving the secure page: \(what)")
        }
      } else { blankSince = nil }
    }
    while Date().timeIntervalSince(t0) < pixelsFor { look(); usleep(100_000) }
    let until = t0.addingTimeInterval(s)
    while Date() < until {
      if target.exists && !el("secure-banner").exists { look(); if blankSince == nil { break } }
      look()
      usleep(150_000)
    }
    let ok = target.exists && !el("secure-banner").exists && blankSince == nil
    note("timing-\(what)", String(format: "arrived=%@ after %.1f s, longest blank %.2f s", ok ? "yes" : "no", Date().timeIntervalSince(t0), worst))
    if !ok {
      attach(XCUIScreen.main.screenshot(), "MISSING-\(what)")
      XCTFail("[\(tag)] \(what): the app (\(target.identifier)) didn't come back within \(Int(s)) s (secure page still up: \(el("secure-banner").exists))")
    }
    return ok && !failed
  }

  /// one secure page: `open` brings it up (from where `target` is on screen), `arrived` is on it
  struct Page {
    let name: String
    let open: () -> Void
    let arrived: XCUIElement
    /// the app's element that must be back after Back
    let target: XCUIElement
    /// how to get back to where `open` works after the extension restarted (it comes up at its first screen)
    var reset: () -> Void = {}
  }

  func enter(_ p: Page, _ what: String) -> Bool {
    p.open()
    let ok = p.arrived.waitForExistence(timeout: 30) && el("secure-back").waitForExistence(timeout: 5)
    if !ok { attach(XCUIScreen.main.screenshot(), "no-page-\(what)"); XCTFail("[\(tag)] \(p.name): the secure page didn't come up (\(what))") }
    return ok
  }
  /// the Back button's place on screen, once the page is fully in
  func backPoint() -> XCUICoordinate {
    let f = el("secure-back").frame
    return app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: f.midX, dy: f.midY))
  }
  func tapBack() { el("secure-back").tap() }

  /// every stress case on one page; returns false when the page couldn't be reached at all
  @discardableResult func run(_ p: Page, loops: Int = 3) -> Bool {
    // 1. open/Back loops
    var point: XCUICoordinate?
    for i in 1...loops {
      guard enter(p, "loop \(i)") else { return false }
      sleep(1)
      if point == nil { point = backPoint() }
      tapBack()
      backArrives(p.target, 20, "\(p.name)-loop-\(i)")
    }
    guard let back = point else { return false }

    // 2. Back while the page is still sliding in (a tap where Back will be, right after opening)
    p.open()
    usleep(250_000)
    back.tap()
    backArrives(p.target, 20, "\(p.name)-back-during-entry")
    // whatever the race left: no page may stay up without its way out
    if el("secure-back").waitForExistence(timeout: 2) { tapBack(); backArrives(p.target, 20, "\(p.name)-back-during-entry-2") }

    // 3. a double tap on Back
    if enter(p, "double") {
      sleep(1)
      back.tap(); back.tap()
      backArrives(p.target, 20, "\(p.name)-double-back")
    }

    // 4. open again right after Back
    if enter(p, "reopen") {
      sleep(1)
      tapBack()
      usleep(300_000)
      if enter(p, "reopen-2") { sleep(1); tapBack() }
      backArrives(p.target, 20, "\(p.name)-reopen-after-back")
    }

    // 5. the edge swipe (a native page's swipe back)
    if enter(p, "swipe") {
      sleep(1)
      let y = 0.5
      let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.01, dy: y))
      let to = app.coordinate(withNormalizedOffset: CGVector(dx: 0.85, dy: y))
      from.press(forDuration: 0.05, thenDragTo: to)
      backArrives(p.target, 20, "\(p.name)-swipe-back")
      if el("secure-banner").exists { XCTFail("[\(tag)] \(p.name): the edge swipe didn't leave the page"); tapBack(); backArrives(p.target, 20, "\(p.name)-swipe-fallback") }
    }

    // 6. Back after the app sat in the background
    if enter(p, "background") {
      XCUIDevice.shared.press(.home)
      sleep(20)
      app.activate()
      sleep(2)
      tapBack()
      backArrives(p.target, 20, "\(p.name)-back-after-background")
    }

    // 7. a memory warning while the page is up
    if enter(p, "memwarn") {
      host("memwarn")
      sleep(2)
      tapBack()
      backArrives(p.target, 20, "\(p.name)-back-after-memory-warning")
    }

    // 8. iOS ended the extension while the page was up (jetsam): Back relaunches it (it comes up at its first
    //    screen, so the app's tab list is what must come back)
    let anyApp = el("tablist")
    if enter(p, "killed") {
      note("kill-\(p.name)", host("ext/kill"))
      sleep(2)
      tapBack()
      backArrives(anyApp, 45, "\(p.name)-back-after-extension-killed", pixelsFor: 8)
      p.reset()
    }

    // 9. ended while the app was in the background (what a phone under memory pressure does)
    if enter(p, "killed-background") {
      XCUIDevice.shared.press(.home)
      sleep(3)
      note("kill-bg-\(p.name)", host("ext/kill"))
      sleep(10)
      app.activate()
      sleep(2)
      tapBack()
      backArrives(anyApp, 45, "\(p.name)-back-after-background-kill", pixelsFor: 8)
      p.reset()
    }

    // 10. the extension slow to come back: stopped for 5 s from the moment Back is tapped
    if enter(p, "slow") {
      sleep(1)
      note("stop-\(p.name)", host("ext/stop?for=5"))
      back.tap()
      backArrives(p.target, 45, "\(p.name)-back-extension-slow", pixelsFor: 8)
    }
    return true
  }

  /// the extension ended while the app itself is on screen: it must come back by itself, never a blank app
  func killWhileShown(_ target: XCUIElement) {
    note("kill-shown", host("ext/kill"))
    backArrives(target, 45, "extension-killed-while-shown", pixelsFor: 8)
    XCUIDevice.shared.press(.home)
    sleep(3)
    note("kill-shown-bg", host("ext/kill"))
    sleep(5)
    app.activate()
    backArrives(target, 45, "extension-killed-in-background-while-shown", pixelsFor: 8)
    host("memwarn")
    backArrives(target, 20, "memory-warning-while-shown")
  }
}
