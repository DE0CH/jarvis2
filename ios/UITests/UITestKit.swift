import XCTest

/// What every UI test of the native app shares: elements by accessibility id, waits that leave evidence, the blank-screen
/// checks (a screen with no navigation bar, tab bar or sheet for over 1.5 s, or a near-uniform screenshot), tabs and
/// the app's alerts.
class JarvisUITestCase: XCTestCase {
  let app = XCUIApplication()
  let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
  let env = ProcessInfo.processInfo.environment
  var tag = "run"
  var step = 0

  // ---- evidence ----
  func shot(_ name: String, checkBlank: Bool = true) {
    step += 1
    let s = XCUIScreen.main.screenshot()
    let a = XCTAttachment(screenshot: s)
    a.name = String(format: "%@-%02d-%@", tag, step, name); a.lifetime = .keepAlways; add(a)
    if checkBlank { XCTAssertFalse(Self.blank(s.image), "[\(tag)] blank screen at \(name)") }
  }
  func note(_ name: String, _ text: String) { let a = XCTAttachment(string: text); a.name = "\(tag)-\(name)"; a.lifetime = .keepAlways; add(a) }
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

  // ---- elements ----
  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any).matching(identifier: id).firstMatch }
  func prefixed(_ p: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", p)).firstMatch }
  func labelled(_ text: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch }
  @discardableResult func wait(_ e: XCUIElement, _ s: TimeInterval, _ what: String) -> Bool {
    let ok = e.waitForExistence(timeout: s)
    XCTAssertTrue(ok, "[\(tag)] \(what)")
    if !ok { note("tree-\(what)", app.debugDescription); shot("missing-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false) }
    return ok
  }
  func gone(_ e: XCUIElement, _ s: TimeInterval) -> Bool {
    let until = Date().addingTimeInterval(s)
    while e.exists && Date() < until { usleep(300_000) }
    return !e.exists
  }
  /// something the app draws is on screen: a navigation bar, the tab bar, or an alert
  var somethingDrawn: Bool { app.navigationBars.firstMatch.exists || app.tabBars.firstMatch.exists || app.alerts.firstMatch.exists }
  /// after a transition: `target` must come up within `s` seconds, and the screen may never be blank (nothing drawn)
  /// for longer than `blank` seconds on the way
  @discardableResult func arrives(_ target: XCUIElement, _ s: TimeInterval, _ what: String, blank: TimeInterval = 1.5) -> Bool {
    let until = Date().addingTimeInterval(s)
    var blankSince: Date?
    while Date() < until {
      if target.exists { return true }
      if somethingDrawn { blankSince = nil } else if blankSince == nil { blankSince = Date() }
      if let b = blankSince, Date().timeIntervalSince(b) > blank {
        shot("blank-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false)
        XCTFail("[\(tag)] blank screen for over \(blank) s on the way to \(what)")
        return target.waitForExistence(timeout: max(0, until.timeIntervalSinceNow))
      }
      usleep(150_000)
    }
    XCTFail("[\(tag)] \(what) didn't come up within \(Int(s)) s")
    note("tree-\(what)", app.debugDescription)
    shot("missing-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false)
    return false
  }

  // ---- the app's furniture ----
  func tab(_ name: String) {
    let b = app.tabBars.buttons[name]
    if b.waitForExistence(timeout: 10) { b.tap() } else { XCTFail("[\(tag)] no tab \(name)"); note("tree-tab-\(name)", app.debugDescription) }
  }
  /// a tab at its first screen: select it, then tap it again (iOS pops a selected tab's stack to its root)
  func tabRoot(_ name: String) {
    tab(name)
    let b = app.tabBars.buttons[name]
    if b.exists { b.tap(); usleep(600_000) }
  }
  /// back one screen in the current navigation stack
  func back() {
    let b = app.navigationBars.buttons.element(boundBy: 0)
    if b.waitForExistence(timeout: 5) { b.tap() }
  }
  /// answer the app's alert: type `text` into its field when given, then tap `button`
  @discardableResult func answer(_ button: String, text: String? = nil, timeout: TimeInterval = 20) -> Bool {
    let alert = app.alerts.firstMatch
    guard wait(alert, timeout, "an alert for \(button)") else { return false }
    if let text {
      let f = alert.textFields.firstMatch
      if f.waitForExistence(timeout: 5) { f.tap(); f.typeText(text) }
    }
    let b = alert.buttons.matching(NSPredicate(format: "label == %@", button)).firstMatch
    guard wait(b, 5, "alert button \(button)") else { return false }
    b.tap()
    return true
  }
  /// a Form picker: open it, choose an option
  func pick(_ pickerId: String, _ option: String) {
    let p = el(pickerId)
    guard wait(p, 10, "picker \(pickerId)") else { return }
    p.tap()
    let o = app.buttons.matching(NSPredicate(format: "label == %@", option)).firstMatch
    if o.waitForExistence(timeout: 5) { o.tap() } else {
      let c = app.collectionViews.buttons[option].firstMatch
      if c.waitForExistence(timeout: 3) { c.tap() } else { XCTFail("[\(tag)] no option \(option) in \(pickerId)"); note("tree-pick-\(pickerId)", app.debugDescription) }
    }
  }
  /// one character at a time (a burst into a URL keyboard can reorder characters)
  func slowType(_ e: XCUIElement, _ text: String) { for ch in text { e.typeText(String(ch)); usleep(120_000) } }
  /// scroll the current list until `e` is there (a Form draws rows lazily), then back to the top
  @discardableResult func scrolledTo(_ e: XCUIElement, max: Int = 6) -> Bool {
    var n = 0
    while !e.exists && n < max { app.swipeUp(); n += 1 }
    return e.exists
  }
  func isOn(_ e: XCUIElement) -> Bool { (e.value as? String) == "1" || e.isSelected }

  // ---- the router on the runner (the test reads payloads; the app checks signatures) ----
  func corePayload(_ path: String, _ field: String) -> [[String: Any]] {
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18080/" + path)!)
    r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type")
    r.httpBody = Data(#"{"nonce":"0123456789abcdef0123456789abcdef"}"#.utf8)
    nonisolated(unsafe) var out: [[String: Any]] = []
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: r) { data, _, _ in
      if let data, let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let p = doc["payload"] as? String,
         let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let st = pj[field] as? [[String: Any]] { out = st }
      done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + 20)
    return out
  }
  func coreStores() -> [[String: Any]] { corePayload("api/core/stores", "stores") }
  func coreUnlocked() -> [[String: Any]] { corePayload("api/core/unlocked", "unlocked") }

  /// Reset or recover at first launch: Recover with the kit (the core is empty)
  func recoverAtLaunch(_ kit: String) -> Bool {
    guard wait(el("setup-state-empty"), 90, "setup page: the core is empty") else { return false }
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return false }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return false }
    el("secure-back").tap()
    return arrives(el("newBtn"), 60, "the session list after setup")
  }
}
