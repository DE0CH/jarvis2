import XCTest

/// Walks Jarvis 2 on a simulator against the REAL core (built with -tags fakefly) and router running on the CI
/// runner, with the backups on a local S3 stand-in that the router reads, keeping a screenshot of every step. CI
/// runs it once per appearance (light, then dark), each time against a fresh, empty core, a fresh router and a
/// reset simulator keychain: Reset or recover (the core is empty; an old kit is refused; Recover with the public
/// TEST kit) → stores (create, unlock) → new session (secure page, software key) → grants (a 10-minute grant and a
/// standing rule on the secure grant page, forget one) → schedules (a wakeup and a cron) → terminal → pause →
/// transcript → resume (with a prompt) → resume with the latest image (approval) → destroy (the changes check) →
/// previous sessions → search → settings (repos: add with its deploy key, remove; Fly) → Reset (the current kit ends the core, a new empty one
/// comes up, a new kit is shown and saved, the core is set up with it and its stores are empty).
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
  /// after a switch between the shell and the app: `target` must come up within `s` seconds, and at no moment on
  /// the way may the screen be blank — neither a secure page (its banner) nor the app's own content (its tab list
  /// or any of `alsoApp`) for longer than `blank` seconds
  @discardableResult func arrives(_ target: XCUIElement, _ s: TimeInterval, _ what: String, blank: TimeInterval = 1.5) -> Bool {
    let until = Date().addingTimeInterval(s)
    var blankSince: Date?
    while Date() < until {
      if target.exists { return true }
      let something = el("secure-banner").exists || el("tablist").exists || el("page-back").exists || el("newBtn").exists
      if something { blankSince = nil } else if blankSince == nil { blankSince = Date() }
      if let b = blankSince, Date().timeIntervalSince(b) > blank {
        shot("blank-" + what.replacingOccurrences(of: " ", with: "-"))
        XCTFail("[\(tag)] blank screen for over \(blank) s on the way to \(what)")
        return target.waitForExistence(timeout: max(0, until.timeIntervalSinceNow))
      }
      usleep(150_000)
    }
    XCTFail("[\(tag)] \(what) didn't come up within \(Int(s)) s")
    shot("missing-" + what.replacingOccurrences(of: " ", with: "-"))
    return false
  }
  /// the core's store list as the router relays it (the test reads the payload; the app checks the signature)
  func coreStores() -> [[String: Any]] {
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18080/api/core/stores")!)
    r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type")
    r.httpBody = Data(#"{"nonce":"0123456789abcdef0123456789abcdef"}"#.utf8)
    var out: [[String: Any]] = []
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: r) { data, _, _ in
      if let data, let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let p = doc["payload"] as? String,
         let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let st = pj["stores"] as? [[String: Any]] { out = st }
      done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + 20)
    return out
  }
  func gone(_ e: XCUIElement, _ s: TimeInterval) -> Bool {
    let until = Date().addingTimeInterval(s)
    while e.exists && Date() < until { usleep(300_000) }
    return !e.exists
  }

  func testWalkthrough() {
    continueAfterFailure = true
    tag = env["JARVIS2_APPEARANCE"] ?? "run"
    let kit = env["JARVIS2_KIT"] ?? ""
    app.launch()

    // ---- Reset or recover: the core is empty (checked against the box key by the app itself)
    guard wait(el("setup-state-empty"), 60, "setup page: the core is empty") else { return }
    shot("setup-empty")
    // an old (version 1) kit gets one plain sentence, details folded away
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText("jarvis2-kit:1:AAAA:ak:sk")
    el("setup-recover-go").tap()
    if wait(el("secure-error"), 15, "an old kit is refused") {
      XCTAssertTrue(el("secure-error").label.contains("older Jarvis 2"), "[\(tag)] plain message: \(el("secure-error").label)")
      XCTAssertFalse(el("secure-error-detail").exists, "[\(tag)] details folded")
      shot("setup-old-kit")
    }
    el("secure-back").tap() // back to the choice: the field is forgotten
    guard wait(el("setup-choose-recover"), 15, "the choice again") else { return }
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    shot("setup-recover-kit")
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return }
    shot("setup-recovered")
    el("secure-back").tap() // Done: the page stays until the app has drawn its list, then slides away over it

    // ---- the React Native list (in the extension)
    guard arrives(el("newBtn"), 120, "session list after Done at first launch") else { return }
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
    arrives(el("stores-manage"), 5, "back to the stores tab")
    sleep(2)
    shot("stores-tab-after")
    el("tab-sessions").tap()

    // ---- new session: ONE page in the shell (every option, the stores, the harness) → Start (one Face ID, which
    // also unlocks the session's locked stores — here the harness's own claude-login, locked until now)
    XCTAssertEqual(coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool, false, "[\(tag)] the harness store starts locked")
    wait(el("newBtn"), 10, "list again")
    el("newBtn").tap()
    guard arrives(el("secure-create"), 10, "the secure New session page") else { return }
    sleep(2)
    shot("secure-new-session")
    XCTAssertTrue(el("ns-prompt").exists && el("ns-title").exists && el("ns-mode-oneshot").exists, "[\(tag)] prompt, title and one-shot are on the one page")
    XCTAssertTrue(el("secure-mode-bypass").exists, "[\(tag)] the secure page picks the permission mode")
    XCTAssertTrue(el("secure-store-default").exists, "[\(tag)] default offered")
    XCTAssertFalse(el("secure-store-core").exists, "[\(tag)] the core store is not offered to a session")
    XCTAssertFalse(el("secure-store-claude-login").exists, "[\(tag)] the harness's own store is not offered")
    XCTAssertTrue(el("ns-unlocks").exists && el("ns-unlocks").label.contains("claude-login"), "[\(tag)] Start says it unlocks the locked harness store")
    el("ns-title").tap(); el("ns-title").typeText("ci session")
    if el("secure-store-gmail").waitForExistence(timeout: 5) {
      el("secure-store-gmail").tap(); sleep(1)
      XCTAssertTrue(el("secure-sensitive-warning").exists, "[\(tag)] sensitive warning")
      shot("secure-sensitive-picked")
      el("secure-store-gmail").tap(); sleep(1)
    }
    if el("ns-model-opus").exists || prefixed("ns-model-").exists { shot("secure-new-session-options") }
    el("secure-create").tap()
    for _ in 0..<2 { shot("creating"); sleep(1) }
    let created = arrives(prefixed("more-"), 180, "the new session's card after Start")
    XCTAssertTrue(created, "[\(tag)] back to the list after Start")
    if el("secure-error").exists { note("\(tag)-create-error", el("secure-error").label); shot("create-error"); return }
    XCTAssertEqual(coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool, true,
                   "[\(tag)] one Start opened the locked harness store, so the machine's secrets pull isn't refused")
    XCTAssertFalse(prefixed("unlock-s").exists, "[\(tag)] no session waits on a locked store")
    sleep(2)
    shot("session-created")

    // ---- grants: More → Grants… → the shell's grant page (a 10-minute terminal grant, then a standing rule
    // for the scheduler) → listed → forget the terminal one
    guard wait(prefixed("more-"), 60, "more button") else { return }
    el(prefixed("more-").identifier).tap()
    wait(el("menu-grants-"), 10, "menu grants")
    shot("more-menu-running")
    el("menu-grants-").tap()
    if wait(el("grant-review"), 20, "grants page") {
      sleep(1)
      shot("grants-empty")
      // the choice is made here (React Native); the shell's page only reviews it: Allow or Deny
      el("grant-holder-terminal").tap()
      el("grant-len-10").tap()
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 10, "the grant review page") {
        sleep(1)
        note("\(tag)-grant-meaning", el("grant-meaning").label)
        XCTAssertTrue(el("grant-meaning").label.contains("Terminal") && el("grant-meaning").label.contains("10 minutes"), "[\(tag)] the review says what is asked: \(el("grant-meaning").label)")
        XCTAssertFalse(prefixed("grant-holder-").exists || prefixed("grant-min-").exists, "[\(tag)] nothing to change on the review page")
        XCTAssertTrue(el("secure-back").label.contains("Deny"), "[\(tag)] Allow or Deny")
        shot("secure-grant")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-terminal"), 60, "terminal grant listed")
        if el("secure-error").exists { note("\(tag)-grant-error", el("secure-error").label); shot("grant-error"); el("secure-back").tap() }
        sleep(1)
        shot("grants-one")
      }
      // Deny leaves without signing
      el("grant-holder-status").tap()
      el("grant-len-2").tap()
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 10, "the grant review page (deny)") {
        el("secure-back").tap()
        arrives(el("grant-review"), 5, "the grants page after Deny")
        XCTAssertFalse(el("grant-forget-status").exists, "[\(tag)] Deny signed nothing")
      }
      el("grant-holder-scheduler").tap()
      el("grant-len-rule").tap()
      el("grant-days-30").tap()
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 10, "the grant review page (rule)") {
        sleep(1)
        XCTAssertTrue(el("grant-meaning").label.contains("Scheduler") && el("grant-meaning").label.contains("until"), "[\(tag)] the rule's review: \(el("grant-meaning").label)")
        shot("secure-grant-rule")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-scheduler"), 60, "standing rule listed")
        if el("secure-error").exists { note("\(tag)-rule-error", el("secure-error").label); shot("rule-error"); el("secure-back").tap() }
        sleep(1)
        shot("grants-two")
      }
      if el("grant-forget-terminal").exists {
        el("grant-forget-terminal").tap()
        wait(el("ask-ok"), 10, "forget question")
        el("ask-ok").tap()
        XCTAssertTrue(gone(el("grant-forget-terminal"), 30), "[\(tag)] forgotten grant gone")
        shot("grants-forgot")
      }
      el("page-back").tap()
    }

    // ---- schedules: a wakeup in an hour and a daily cron
    guard wait(prefixed("more-"), 30, "more button (schedules)") else { return }
    el(prefixed("more-").identifier).tap()
    wait(el("menu-schedules-"), 10, "menu schedules")
    el("menu-schedules-").tap()
    if wait(el("sch-prompt"), 20, "schedules page") {
      el("sch-prompt").tap(); el("sch-prompt").typeText("CI wakeup: check the build")
      el("sch-save").tap()
      wait(el("sch-cancel-w-default"), 20, "wakeup armed")
      el("sch-kind-cron").tap()
      el("sch-prompt").tap(); el("sch-prompt").typeText("CI cron: daily summary")
      el("sch-save").tap()
      wait(el("sch-cancel-c-daily"), 20, "cron armed")
      sleep(1)
      shot("schedules")
      el("page-back").tap()
    }
    sleep(2)
    shot("session-scheduled")

    // ---- the terminal page (a fake machine answers nothing: the page's chrome, status and key row)
    if wait(prefixed("term-"), 20, "terminal button") {
      el(prefixed("term-").identifier).tap()
      if wait(el("term-in"), 20, "terminal page") {
        sleep(3)
        shot("terminal")
        el("term-close").tap()
      }
    }

    // ---- pause → transcript → resume with a prompt (same image: the core's dead-machine responder)
    guard wait(prefixed("pause-"), 60, "pause button") else { return }
    el(prefixed("pause-").identifier).tap()
    sleep(1)
    shot("pausing")
    guard wait(prefixed("resume-"), 90, "paused session") else { return }
    sleep(1)
    shot("paused")
    if wait(prefixed("tail-"), 10, "transcript button") {
      el(prefixed("tail-").identifier).tap()
      wait(el("page-back"), 10, "transcript page")
      sleep(2)
      shot("paused-transcript")
      el("page-back").tap()
    }
    el(prefixed("resume-").identifier).tap()
    if wait(el("ask-text"), 10, "resume question") {
      el("ask-text").tap(); el("ask-text").typeText("carry on")
      shot("resume-question")
      el("ask-ok").tap()
    }
    sleep(1)
    shot("resuming")
    guard wait(prefixed("pause-"), 120, "resumed session") else { return }
    sleep(1)
    shot("resumed")

    // ---- resume with the latest image: pause, then More → the approval opens on the secure page
    el(prefixed("pause-").identifier).tap()
    guard wait(prefixed("resume-"), 90, "paused again") else { return }
    // the permission mode (signed): a paused session switches at its next resume, which the iPhone approves
    el(prefixed("more-").identifier).tap()
    let toAuto = el("menu-switch-to-auto-mode"), toBypass = el("menu-switch-to-bypass-mode")
    XCTAssertTrue(toAuto.waitForExistence(timeout: 10), "[\(tag)] the session was made in bypass (the form's pick reached the secure page): switch to auto offered")
    if toAuto.exists || toBypass.exists {
      (toAuto.exists ? toAuto : toBypass).tap()
      wait(el("ask-ok"), 10, "switch mode question")
      el("ask-ok").tap()
      sleep(2)
      shot("mode-switched-paused")
    }
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
      XCTAssertTrue(el("secure-mode").exists, "[\(tag)] the approval shows the signed permission mode")
      if el("secure-mode").exists { note("\(tag)-approval-mode", el("secure-mode").label) }
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
    wait(el("ask-ok"), 30, "destroy question (after the changes check)")
    shot("destroy-question")
    el("ask-ok").tap()
    XCTAssertTrue(gone(prefixed("more-"), 90), "[\(tag)] session gone from the list")
    sleep(1)
    shot("destroyed")
    el("tab-records").tap()
    sleep(3)
    shot("previous")
    // the CI router has no Storage Box, so a destroy leaves no record unless it archived something
    if prefixed("rremove-").waitForExistence(timeout: 10) {
      el(prefixed("rremove-").identifier).tap()
      wait(el("ask-ok"), 10, "remove question")
      shot("previous-remove-question")
      el("ask-ok").tap()
      XCTAssertTrue(gone(prefixed("rremove-"), 30), "[\(tag)] removed from the list")
      shot("previous-removed")
    }
    // ---- search: the router forwards to Jarvis 1, which the CI router has no token for, so the tab shows
    // that answer in words; then the iCloud mode
    el("tab-search").tap()
    if wait(el("search-q"), 15, "search tab") {
      el("search-q").tap(); el("search-q").typeText("hello")
      el("search-go").tap()
      wait(el("search-error"), 30, "search answer (no Jarvis 1 in CI)")
      shot("search")
      el("search-mode-files").tap()
      sleep(1)
      shot("search-icloud")
    }
    el("tab-settings").tap()
    sleep(2)
    shot("settings")
    app.swipeUp()
    sleep(1)
    shot("settings-more")

    // ---- Settings → Repos: add a repo on the shell's secure page (the core's signed request; one Face ID → the
    // core makes the key, the CI core's fake GitHub takes its public half, the store github-china-train holds the
    // private half), see Jarvis 2's own repo come up sensitive, then remove the first again
    let repoField = el("repo-url")
    if wait(repoField, 15, "the repos card in Settings") {
      repoField.tap(); repoField.typeText("DE0CH/china-train\n")
      if wait(el("secure-repo-go"), 30, "the secure add-repo page") {
        wait(el("store-line-github-china-train"), 15, "…naming the repo's store")
        XCTAssertFalse(el("secure-repo-sensitive").isSelected, "[\(tag)] a repo's store isn't sensitive by default")
        sleep(1)
        shot("secure-repo-add")
        el("secure-repo-go").tap()
        if wait(el("repo-key-china-train"), 60, "the repo listed with its deploy key") {
          sleep(2)
          XCTAssertTrue(el("repo-key-china-train").label.contains("github-china-train"), "[\(tag)] the key lives in github-china-train: \(el("repo-key-china-train").label)")
          shot("settings-repo-added")
        }
        XCTAssertFalse(el("secure-error").exists, "[\(tag)] add-repo error: \(el("secure-error").exists ? el("secure-error").label : "")")
      }
      repoField.tap(); repoField.typeText("DE0CH/jarvis2\n")
      if wait(el("secure-repo-go"), 30, "the secure add-repo page for jarvis2") {
        wait(el("store-line-github-jarvis2"), 15, "…naming github-jarvis2")
        sleep(1)
        XCTAssertTrue(el("secure-repo-sensitive").isSelected, "[\(tag)] Jarvis 2's own repo comes up sensitive (the core's word)")
        shot("secure-repo-sensitive")
        el("secure-back").tap() // nothing happens without Face ID
      }
      if wait(el("repo-remove-china-train"), 30, "Remove on the repo") {
        el("repo-remove-china-train").tap()
        if wait(el("secure-repo-go"), 30, "the secure remove-repo page") {
          sleep(1)
          shot("secure-repo-remove")
          el("secure-repo-go").tap()
          XCTAssertTrue(gone(el("repo-key-china-train"), 60), "[\(tag)] the repo is off the list after remove")
          sleep(1)
          shot("settings-repo-removed")
        }
      }
    }

    // ---- tasks: make one from the hello template (the iPhone approves its line, opened by itself), run it,
    // the run page (stop), a daily schedule, the Schedules tab
    el("tab-tasks").tap()
    if wait(el("new-hello"), 30, "tasks tab with the hello template") {
      sleep(1)
      shot("tasks")
      el("new-hello").tap()
      if wait(el("tf-message"), 15, "new task form") {
        el("tf-message").tap(); el("tf-message").typeText("hello from CI")
        shot("task-new")
        el("te-save").tap()
        if wait(el("secure-approve"), 90, "the task's approval (opened by itself)") {
          sleep(1)
          shot("task-approval")
          el("secure-approve").tap()
        }
        if wait(el("td-schedule"), 60, "task page") {
          sleep(2)
          shot("task-page")
          if el("td-run").waitForExistence(timeout: 30) {
            el("td-run").tap()
            if wait(prefixed("td-run-"), 30, "a run listed") {
              sleep(1)
              shot("task-run-queued")
              el(prefixed("td-run-").identifier).tap()
              if wait(el("tr-stop"), 20, "run page") {
                sleep(1)
                shot("task-run-page")
                el("tr-stop").tap()
                wait(el("ask-ok"), 10, "stop question")
                el("ask-ok").tap()
                XCTAssertTrue(gone(el("tr-stop"), 30), "[\(tag)] run stopped")
                shot("task-run-stopped")
              }
              el("page-back").tap()
            }
          }
          wait(el("td-schedule"), 10, "task page again")
          el("td-schedule").tap()
          if wait(el("se-save"), 15, "schedule form") {
            shot("task-schedule-form")
            el("se-save").tap()
          }
          sleep(2)
          shot("task-page-scheduled")
          el("page-back").tap()
        }
      }
      el("tab-schedules").tap()
      sleep(2)
      shot("task-schedules")
      el("tab-settings").tap()
      sleep(1)
    }

    // ---- Reset on a set-up core: only with the kit it was set up with; a new, empty core, then a new kit
    el("open-setup").tap()
    if wait(el("setup-state-mine"), 30, "setup page: set up on this iPhone") {
      shot("setup-mine")
      el("setup-choose-reset").tap()
      if wait(el("setup-kit-field"), 15, "the current kit's field") {
        el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
        shot("reset-current-kit")
        el("setup-reset-go").tap()
        if wait(el("setup-kit"), 180, "the new kit, after the core restarted empty") {
          let newKit = el("setup-kit").label
          XCTAssertTrue(newKit.hasPrefix("jarvis2-kit:2:MIG") && newKit != kit, "[\(tag)] a new kit \(newKit.prefix(18))…")
          XCTAssertFalse(newKit.dropFirst(14).contains(":"), "[\(tag)] the kit is the master key only")
          shot("reset-new-kit")
          el("setup-kit-copy").tap()
          el("setup-kit-saved").tap()
          if wait(el("setup-done"), 60, "reset done") {
            shot("reset-done")
            el("secure-back").tap()
            // the stores start empty
            el("tab-stores").tap()
            if wait(el("stores-manage"), 20, "stores tab") {
              el("stores-manage").tap()
              if wait(el("store-new-name"), 30, "secure stores page") {
                XCTAssertFalse(el("unlock-default").exists, "[\(tag)] no stores after a Reset")
                shot("reset-stores-empty")
                el("secure-back").tap()
              }
            }
          }
        }
      }
    }
    app.terminate()
  }
}
