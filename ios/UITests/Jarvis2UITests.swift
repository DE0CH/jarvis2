import XCTest

/// Walks the native Jarvis 2 app on a simulator against the REAL core (fakefly build) and router running on the CI runner,
/// with the backups on a local S3 stand-in, keeping a screenshot of every step. ios.yml runs it once per appearance
/// (light, then dark), each against a fresh, empty core and router and a reset simulator keychain:
/// Reset or recover (an old kit refused; Recover with the public TEST kit) → stores (create, unlock) → New session (the
/// one page; Start also opens the locked harness store) → grants (a 10-minute grant and a standing rule on the Face ID
/// review, one denied, one forgotten) → schedules → terminal (the router's page in a WebView) → pause → transcript →
/// resume with a prompt (signed, shown on the approval) → permission mode → resume with the latest image → destroy →
/// Previous → search → repos (add with its deploy key, Jarvis 2's own repo comes up sensitive, remove; claude-env
/// pre-selected on New session only when listed) → tasks → Reset (the kit ends the core; a new kit; the stores empty).
final class Jarvis2UITests: JarvisUITestCase {

  /// New session pre-selects DE0CH/claude-env (and its store) only when it is on the repo list (Deyao, 2026-10-11)
  func checkNewSessionRepoDefault(expect: Bool) {
    tab("Sessions")
    guard wait(el("newBtn"), 20, "the list (repo default)") else { return }
    el("newBtn").tap()
    guard arrives(el("secure-create"), 20, "New session (repo default)") else { return }
    sleep(2)
    let repo = el("ns-repo-claude-env"), store = el("secure-store-github-claude-env")
    if expect {
      XCTAssertTrue(repo.waitForExistence(timeout: 10) && repo.isSelected, "[\(tag)] claude-env pre-selected on New session")
      XCTAssertTrue(store.exists && store.isSelected, "[\(tag)] github-claude-env pre-selected with it")
      shot("new-session-claude-env-default")
      repo.tap(); sleep(1)
      XCTAssertFalse(repo.isSelected, "[\(tag)] claude-env can be de-selected")
    } else {
      let anyRepo = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'ns-repo-' AND selected == true")).count
      XCTAssertEqual(anyRepo, 0, "[\(tag)] no repo pre-selected without claude-env")
    }
    el("secure-back").tap()
    arrives(el("newBtn"), 20, "the list after the repo-default check")
  }

  func openRepos() {
    tabRoot("Settings")
    if wait(el("open-repos"), 15, "Settings → Repos") { el("open-repos").tap() }
  }
  func addRepo(_ repo: String) -> Bool {
    openRepos()
    guard wait(el("repo-add"), 15, "Add repo") else { return false }
    el("repo-add").tap()
    let f = el("repo-url")
    guard wait(f, 15, "the repo field") else { return false }
    f.tap(); slowType(f, repo + "\n")
    return arrives(el("secure-repo-go"), 30, "the add-repo review for \(repo)")
  }

  func testWalkthrough() {
    continueAfterFailure = true
    tag = env["JARVIS2_APPEARANCE"] ?? "run"
    let kit = env["JARVIS2_KIT"] ?? ""
    app.launch()

    // ---- Reset or recover: the core is empty (checked against the box key by the app itself)
    guard wait(el("setup-state-empty"), 60, "setup page: the core is empty") else { return }
    shot("setup-empty")
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText("jarvis2-kit:1:AAAA:ak:sk")
    el("setup-recover-go").tap()
    if wait(el("secure-error"), 15, "an old kit is refused") {
      XCTAssertTrue(el("secure-error").label.contains("older Jarvis 2"), "[\(tag)] plain message: \(el("secure-error").label)")
      shot("setup-old-kit")
    }
    el("secure-back").tap()
    guard wait(el("setup-choose-recover"), 15, "the choice again") else { return }
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    XCTAssertEqual((el("setup-kit-field").value as? String)?.hasPrefix("jarvis2-kit:1"), false, "[\(tag)] the old kit was forgotten on Back")
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    shot("setup-recover-kit")
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return }
    shot("setup-recovered")
    el("secure-back").tap()
    guard arrives(el("newBtn"), 60, "the session list after Done") else { return }
    sleep(2)
    shot("sessions-empty")

    // ---- stores: the core's signed list; create one, unlock default (Face ID: a software key here)
    tabRoot("Settings")
    guard wait(el("open-stores"), 15, "Settings → Stores") else { return }
    el("open-stores").tap()
    wait(el("unlock-default"), 30, "the stores page")
    sleep(1)
    shot("stores")
    XCTAssertFalse(el("store-core").exists, "[\(tag)] the core's own store is not listed")
    XCTAssertTrue(el("sensitive-marked").exists, "[\(tag)] a store with a sensitive marker in the backups came back sensitive")
    XCTAssertFalse(el("sensitive-default").exists, "[\(tag)] default came back not sensitive")
    el("store-new").tap()
    answer("Create", text: "ci-notes")
    wait(el("store-ci-notes"), 20, "created store listed")
    el("unlock-default").tap()
    wait(el("lock-default"), 30, "default unlocked (the core's signed unlocked list)")
    shot("stores-unlocked")
    back()

    // ---- New session: one page; Start signs and opens the locked harness store under one Face ID
    XCTAssertEqual(coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool, false, "[\(tag)] the harness store starts locked")
    tab("Sessions")
    guard wait(el("newBtn"), 10, "list again") else { return }
    el("newBtn").tap()
    guard arrives(el("secure-create"), 15, "New session") else { return }
    sleep(2)
    shot("new-session")
    XCTAssertTrue(el("ns-prompt").exists && el("ns-title").exists && el("ns-mode").exists, "[\(tag)] prompt, title and one-shot are on the one page")

    XCTAssertTrue(el("secure-store-default").exists, "[\(tag)] default offered")
    XCTAssertFalse(el("secure-store-core").exists, "[\(tag)] the core store is not offered")
    XCTAssertFalse(el("secure-store-claude-login").exists, "[\(tag)] the harness's own store is not offered as a pick")
    XCTAssertTrue(el("ns-harness-store-claude-login").exists, "[\(tag)] …but listed as what the harness brings")
    XCTAssertTrue(scrolledTo(el("secure-mode-bypass")), "[\(tag)] the page picks the permission mode")
    let unlocks = el("ns-unlocks")
    XCTAssertTrue(scrolledTo(unlocks) && unlocks.label.contains("claude-login"), "[\(tag)] Start says it unlocks the locked harness store")
    for _ in 0..<6 { app.swipeDown() }
    el("ns-title").tap(); el("ns-title").typeText("ci session")
    if el("secure-store-gmail").waitForExistence(timeout: 3) {
      el("secure-store-gmail").tap(); sleep(1)
      XCTAssertTrue(el("secure-sensitive-warning").exists, "[\(tag)] sensitive warning")
      shot("new-session-sensitive")
      el("secure-store-gmail").tap()
    }
    el("secure-create").tap()
    let row = prefixed("srow-")
    guard arrives(row, 120, "the new session's row after Start") else {
      if el("secure-error").exists { note("create-error", el("secure-error").label) }
      return
    }
    XCTAssertTrue(coreUnlocked().contains { ($0["store"] as? String) == "claude-login" }
                  || coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool == true,
                  "[\(tag)] one Start opened the locked harness store")
    let sid = String(row.identifier.dropFirst("srow-".count))
    note("session", sid)
    sleep(2)
    shot("session-created")
    row.tap()
    guard arrives(el("grants-\(sid)"), 20, "the session's page") else { return }
    shot("session-detail")

    // ---- grants: chosen here, reviewed on the Face ID page: a 10-minute grant, a denied one, a standing rule, forget one
    el("grants-\(sid)").tap()
    if wait(el("grant-review"), 20, "grants page") {
      sleep(1)
      shot("grants-empty")
      pick("grant-holder", "Terminal")
      pick("grant-len", "10 min")
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 15, "the grant review") {
        sleep(1)
        note("grant-meaning", el("grant-meaning").label)
        XCTAssertTrue(el("grant-meaning").label.contains("Terminal") && el("grant-meaning").label.contains("10 minutes"), "[\(tag)] the review says what is asked: \(el("grant-meaning").label)")
        XCTAssertTrue(el("grant-meaning").label.contains("ci session"), "[\(tag)] the session is named from its signed cert: \(el("grant-meaning").label)")
        XCTAssertTrue(el("secure-back").label.contains("Deny"), "[\(tag)] Allow or Deny")
        shot("grant-review")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-terminal"), 60, "terminal grant listed")
        shot("grants-one")
      }
      pick("grant-holder", "Status")
      pick("grant-len", "2 min")
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 15, "the grant review (deny)") {
        el("secure-back").tap()
        arrives(el("grant-review"), 10, "the grants page after Deny")
        XCTAssertFalse(el("grant-forget-status").exists, "[\(tag)] Deny signed nothing")
      }
      pick("grant-holder", "Scheduler")
      pick("grant-len", "Standing rule")
      pick("grant-days", "30 days")
      el("grant-review").tap()
      if arrives(el("grant-meaning"), 15, "the grant review (rule)") {
        sleep(1)
        XCTAssertTrue(el("grant-meaning").label.contains("Scheduler") && el("grant-meaning").label.contains("until"), "[\(tag)] the rule's review: \(el("grant-meaning").label)")
        shot("grant-review-rule")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-scheduler"), 60, "standing rule listed")
        shot("grants-two")
      }
      if el("grant-forget-terminal").exists {
        el("grant-forget-terminal").tap()
        answer("Forget")
        XCTAssertTrue(gone(el("grant-forget-terminal"), 30), "[\(tag)] forgotten grant gone")
        shot("grants-forgot")
      }
      back()
    }

    // ---- schedules: a wakeup in an hour and a daily cron
    if wait(el("schedules-\(sid)"), 20, "Schedules") {
      el("schedules-\(sid)").tap()
      if wait(el("sch-prompt"), 20, "schedules page") {
        el("sch-prompt").tap(); el("sch-prompt").typeText("CI wakeup: check the build")
        el("sch-save").tap()
        wait(el("sch-cancel-w-default"), 20, "wakeup armed")
        app.buttons["Repeating"].firstMatch.tap()
        el("sch-prompt").tap(); el("sch-prompt").typeText("CI cron: daily summary")
        el("sch-save").tap()
        wait(el("sch-cancel-c-daily"), 20, "cron armed")
        shot("schedules")
        back()
      }
    }

    // ---- the terminal: the router's page in a WebView (a fake machine answers nothing: the page, its status, its keys)
    if wait(el("term-\(sid)"), 20, "Terminal") {
      el("term-\(sid)").tap()
      let input = app.webViews.textFields["Terminal input"].firstMatch
      if arrives(input, 30, "the terminal page") {
        sleep(3)
        shot("terminal")
        XCTAssertTrue(app.webViews.buttons["Send"].exists, "[\(tag)] the page's Send")
      }
      back()
    }

    // ---- pause → transcript → resume with a prompt (a one-time input the phone signs: the approval shows it)
    guard wait(el("pause-\(sid)"), 60, "Pause") else { return }
    el("pause-\(sid)").tap()
    shot("pausing")
    guard wait(el("resume-\(sid)"), 120, "paused") else { return }
    shot("paused")
    if wait(el("tail-\(sid)"), 10, "Transcript") {
      el("tail-\(sid)").tap()
      arrives(el("transcript"), 15, "the transcript")
      sleep(2)
      shot("transcript")
      back()
    }
    el("resume-\(sid)").tap()
    answer("Resume", text: "carry on")
    if arrives(el("secure-approve"), 90, "the resume-prompt approval") {
      sleep(1)
      shot("approval-resume-prompt")
      XCTAssertTrue(el("signed-once-prompt").exists && el("signed-once-prompt").label.contains("carry on"), "[\(tag)] the approval shows the signed resume prompt")
      XCTAssertTrue(el("secure-session").exists && el("secure-session").label.contains("ci session"), "[\(tag)] the session is named from the signed predecessor: \(el("secure-session").label)")
      el("secure-approve").tap()
    }
    guard wait(el("pause-\(sid)"), 150, "resumed") else { return }
    shot("resumed")

    // ---- permission mode (signed) and resume with the latest image (the approval opens by itself)
    el("pause-\(sid)").tap()
    guard wait(el("resume-\(sid)"), 120, "paused again") else { return }
    el("more-\(sid)").tap()
    let toAuto = app.buttons["Switch to auto mode"]
    XCTAssertTrue(toAuto.waitForExistence(timeout: 10), "[\(tag)] made in bypass: switch to auto offered")
    if toAuto.exists { toAuto.tap(); answer("Switch"); sleep(2); shot("mode-switched") } else { app.tap() }
    el("more-\(sid)").tap()
    if wait(app.buttons["Resume with latest image"], 10, "menu: resume latest") {
      app.buttons["Resume with latest image"].tap()
      answer("Resume with latest image")
      if arrives(el("secure-approve"), 120, "the resume-upgrade approval") {
        sleep(2)
        shot("approval-upgrade")
        XCTAssertTrue(el("secure-mode").exists, "[\(tag)] the approval shows the signed permission mode")
        el("secure-approve").tap()
        sleep(3)
        shot("upgraded")
      }
    }

    // ---- destroy → Previous
    if (scrolledTo(el("destroy-\(sid)")) || true), wait(el("destroy-\(sid)"), 60, "Destroy") {
      el("destroy-\(sid)").tap()
      answer("Destroy session", timeout: 30)
      XCTAssertTrue(gone(el("srow-\(sid)"), 120), "[\(tag)] session gone from the list")
      shot("destroyed")
    }
    tab("Sessions")
    if wait(el("previousBtn"), 10, "Previous") {
      el("previousBtn").tap()
      sleep(3)
      shot("previous")
      let rec = prefixed("record-")
      if rec.waitForExistence(timeout: 5) {
        rec.press(forDuration: 1.2)
        if app.buttons["Remove from the list"].waitForExistence(timeout: 5) {
          app.buttons["Remove from the list"].tap()
          answer("Remove")
          XCTAssertTrue(gone(rec, 30), "[\(tag)] removed from the list")
        }
      }
      back()
    }

    // ---- search: the router forwards to Jarvis 1, which the CI router can't reach, so the answer is an error in words
    tab("Search")
    let field = app.searchFields.firstMatch
    if wait(field, 15, "the search field") {
      field.tap(); field.typeText("hello\n")
      wait(el("search-error"), 30, "search answer (no Jarvis 1 in CI)")
      shot("search")
      if app.buttons["iCloud files"].waitForExistence(timeout: 5) { app.buttons["iCloud files"].tap(); sleep(2); shot("search-icloud") }
    }

    // ---- repos: add DE0CH/china-train (the CI core's fake GitHub takes the key), Jarvis 2's own comes up sensitive, remove
    if addRepo("DE0CH/china-train") {
      wait(el("store-line-github-china-train"), 15, "…naming the repo's store")
      XCTAssertFalse(isOn(el("secure-repo-sensitive")), "[\(tag)] a repo's store isn't sensitive by default")
      shot("repo-add")
      el("secure-repo-go").tap()
      if wait(el("repo-key-china-train"), 60, "the repo listed with its deploy key") {
        XCTAssertTrue(el("repo-key-china-train").label.contains("github-china-train"), "[\(tag)] the key lives in github-china-train")
        shot("repo-added")
      }
    }
    checkNewSessionRepoDefault(expect: false)
    if addRepo("DE0CH/claude-env") {
      sleep(1); el("secure-repo-go").tap()
      wait(el("repo-key-claude-env"), 60, "claude-env listed")
    }
    checkNewSessionRepoDefault(expect: true)
    if addRepo("DE0CH/jarvis2") {
      wait(el("store-line-github-jarvis2"), 15, "…naming github-jarvis2")
      sleep(1)
      XCTAssertTrue(isOn(el("secure-repo-sensitive")), "[\(tag)] Jarvis 2's own repo comes up sensitive (the core's word)")
      shot("repo-sensitive")
      el("secure-back").tap()
    }
    openRepos()
    if wait(el("repo-remove-china-train"), 30, "Remove on the repo") {
      el("repo-remove-china-train").tap()
      if arrives(el("secure-repo-go"), 30, "the remove-repo review") {
        shot("repo-remove")
        el("secure-repo-go").tap()
        XCTAssertTrue(gone(el("repo-key-china-train"), 60), "[\(tag)] the repo is off the list after remove")
      }
    }

    // ---- tasks: make one from the hello template (its line's approval opens by itself), run it, stop the run, schedule it
    tab("Tasks")
    if (scrolledTo(el("new-hello")) || true), wait(el("new-hello"), 30, "the hello template") {
      shot("tasks")
      el("new-hello").tap()
      if wait(el("tf-message"), 15, "new task form") {
        el("tf-message").tap(); el("tf-message").typeText("hello from CI")
        shot("task-new")
        el("te-save").tap()
        if arrives(el("secure-approve"), 90, "the task's approval") {
          sleep(1); shot("task-approval")
          el("secure-approve").tap()
        }
        if wait(el("td-schedule"), 60, "task page") {
          sleep(2)
          shot("task-page")
          if el("td-run").waitForExistence(timeout: 60) {
            el("td-run").tap()
            if wait(prefixed("td-run-"), 30, "a run listed") {
              prefixed("td-run-").tap()
              if wait(el("tr-stop"), 20, "run page") {
                shot("task-run")
                el("tr-stop").tap()
                answer("Stop")
                XCTAssertTrue(gone(el("tr-stop"), 30), "[\(tag)] run stopped")
              }
              back()
            }
          }
          if wait(el("td-schedule"), 10, "task page again") {
            el("td-schedule").tap()
            if wait(el("se-save"), 15, "schedule form") { shot("task-schedule"); el("se-save").tap() }
            sleep(2)
            back()
          }
        }
      }
    }
    tab("Tasks")
    sleep(2)
    shot("task-schedules")

    // ---- Reset on a set-up core: only with its kit; a new, empty core, a new kit, the stores empty
    tabRoot("Settings")
    if (scrolledTo(el("open-setup")) || true), wait(el("open-setup"), 15, "Reset or recover") {
      el("open-setup").tap()
      if wait(el("setup-state-mine"), 30, "setup page: set up on this iPhone") {
        shot("setup-mine")
        el("setup-choose-reset").tap()
        if wait(el("setup-kit-field"), 15, "the current kit's field") {
          el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
          el("setup-reset-go").tap()
          if wait(el("setup-kit"), 180, "the new kit after the core restarted empty") {
            let newKit = el("setup-kit").label
            XCTAssertTrue(newKit.hasPrefix("jarvis2-kit:2:MIG") && newKit != kit, "[\(tag)] a new kit \(newKit.prefix(18))…")
            shot("reset-new-kit", checkBlank: false)
            el("setup-kit-copy").tap()
            el("setup-kit-saved").tap()
            if wait(el("setup-done"), 60, "reset done") {
              shot("reset-done")
              el("secure-back").tap()
              tabRoot("Settings")
              if wait(el("open-stores"), 15, "stores") {
                el("open-stores").tap()
                sleep(3)
                XCTAssertFalse(el("unlock-default").exists, "[\(tag)] no stores after a Reset")
                shot("reset-stores-empty")
              }
            }
          }
        }
      }
    }
    app.terminate()
  }
}
