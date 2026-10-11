// Jarvis 2: a small native shell that owns the window. The whole Jarvis React Native UI runs in the
// bundled ExtensionKit extension (JarvisUI), in its own process, shown full-screen in normal mode. Anything
// may ask to ENTER secure mode (XPC requestSecureMode) on one of the shell's pages — new session, an
// approval, stores, Reset or recover, a grant; only this shell's own code leaves it. In secure mode the extension's view is
// removed — it cannot draw or receive taps — and the shell pushes its own page over a still snapshot of the
// app with the native push motion (no sheets: forms are pages), so the switch looks seamless. Leaving always
// pops the page to the right: Back over the snapshot, a finished action over the live app once React Native
// has drawn the result under the page (Shell.exitSecure). The shell also owns sign-in (RouterClient) and hands
// the extension the router's address and the Access token.
import ExtensionFoundation
import Combine
import ExtensionKit
import SwiftUI
import UIKit

extension AppExtensionPoint {
  @Definition
  public static var jarvisUI: AppExtensionPoint {
    Name("jarvisUI")
    UserInterface()
  }
}

@main
struct Jarvis2App: App {
  var body: some Scene { WindowGroup { RootView() } }
}

enum Mode: Equatable { case normal, secure }
/// the shell's secure pages
enum Route: Equatable { case newSession, approval(String), stores, setup, grant(String), repoKey, unlock(String) }

@Observable
final class Shell {
  var mode: Mode = .normal
  var route: Route = .setup
  var secureOptions: [String: Any] = [:]
  /// "What you sign (exact)" for an Inbox request's review (Inbox.swift): the page sets it from the signed content
  var signedAction: String?
  var identity: AppExtensionIdentity?
  var loadError: String?
  /// the push/pop motion: 0 = the app on screen, 1 = a secure page fully in (the app slid back under it)
  var progress: CGFloat = 0
  /// the extension's view is in the window. Never while a secure page is up; back in the moment the shell
  /// decides to leave, under the page (and under the picture below) until it has drawn
  var extensionMounted = true
  /// a still picture of the app (shell-owned pixels), taken when a secure page is asked for — only of an extension
  /// that has drawn (a picture of a blank, relaunching extension would just be a blank page to pop over)
  var snapshot: UIImage?
  /// the picture is on screen: in the extension's place under a page, and over the re-added (or relaunched)
  /// extension until it has drawn again
  var showSnapshot = false
  /// the shell has left secure mode (only its own code does): the page takes no more taps
  var leaving = false
  /// leaving, with the page still fully in: the app is getting ready under it (after Create, or at launch)
  var preparing = false
  /// each mount of the extension's view is a new EXHostViewController (a new scene, and a new process when iOS
  /// ended the old one); the view carries this as its identity, so bumping it relaunches the extension in place
  var mount = 0
  /// the window's width (the push moves by it; the edge swipe measures against it)
  var width: CGFloat = 0
  var extensionProxy: ExtensionService?
  weak var hostVC: EXHostViewController?
  var lines: [String] = []
  private var monitor: AppExtensionPoint.Monitor?
  private let t0 = Date()
  /// the result to tell React Native once the re-added extension's connection is up
  @ObservationIgnored private var pendingFinish: String?
  /// the id that result carries; React Native's secureSettled must name it (a late answer to an earlier exit
  /// doesn't count)
  @ObservationIgnored private var exitId = ""
  @ObservationIgnored private var popDone = false
  @ObservationIgnored private var settled = false
  /// the extension of mount `drawnMount` has drawn real content in its window (its whenDrawn answer)
  @ObservationIgnored private var drawnMount = -1
  private var drawn: Bool { drawnMount == mount && extensionMounted }
  /// when the current mount was made, and when it last proved alive (hello / whenDrawn answered)
  @ObservationIgnored private var mountedAt = Date()
  @ObservationIgnored private var relaunches: [Date] = []
  /// what waits for the extension: run once it has drawn (and, after a finished action, handled the result)
  @ObservationIgnored private var onReady: (() -> Void)?
  @ObservationIgnored private var readySince = Date()
  @ObservationIgnored private var watchdog: Timer?
  /// every enter and exit bumps it: a step scheduled by an earlier transition doesn't run in a later one
  @ObservationIgnored private var transition = 0
  /// a secure page asked for while one is still leaving: it comes once that one is gone
  @ObservationIgnored private var queuedEnter: String?

  func log(_ s: String) {
    let line = String(format: "%.1f ", Date().timeIntervalSince(t0)) + s
    NSLog("[shell] %@", line)
    lines.append(line)
  }

  /// the core's signed store list, fetched at launch so the secure page is filled at once (it is
  /// fetched again, with a fresh nonce, every time the page opens)
  var prefetched: [StoreView]?
  /// what the New session page offers besides the stores (the router's lists; nothing here is signed as such: the
  /// signed challenge is checked against what the page sends), fetched with the stores so the page opens filled
  var lists = Lists()
  struct Lists { var harnessStores: [String: [String]] = [:]; var models: [RouterClient.Choice] = []; var sizes: [RouterClient.Choice] = []; var repos: [RouterClient.RepoDTO] = [] }

  /// fills `prefetched` and `lists` in the background (at launch, after a setup and whenever a secure page has gone)
  func refreshLists() {
    guard CoreTrust.pinned != nil else { return }
    Task { @MainActor in
      let r = RouterClient.shared
      async let hs = r.harnessStores()
      async let ms = r.models()
      async let sz = r.sizes()
      async let rp = r.repos()
      lists = Lists(harnessStores: await hs, models: await ms, sizes: await sz, repos: await rp)
      let t = Date()
      do { prefetched = try await r.stores(); log(String(format: "core stores prefetched in %.2fs", Date().timeIntervalSince(t))) }
      catch { log("core stores prefetch failed: \(error.localizedDescription)") }
    }
  }

  func load() async {
    // the master private key an earlier build held in the Keychain (it went into the version-1 kit): no core
    // trusts it any more, so it goes
    Keychain.set("held-master", nil); Keychain.set("held-master-public", nil)
    if CoreTrust.pinned == nil {
      // not set up from this iPhone yet: Reset or recover comes first (Back leaves it for the app, which can still view)
      route = .setup; extensionMounted = false; progress = 1; mode = .secure
    } else {
      Task { @MainActor in
        // a restarted core is a new, empty core: until it is set up again nothing can be signed, so the page comes up
        if let x = try? await RouterClient.shared.identity(), x.signingKey != CoreTrust.pinned?.signingKey {
          log("the router reports another core: Reset or recover")
          enterSecure(#"{"kind":"setup"}"#)
          return
        }
        refreshLists()
      }
    }
    do {
      let m = try await AppExtensionPoint.Monitor(appExtensionPoint: .jarvisUI)
      monitor = m
      identity = m.identities.first
      log("extensions \(m.identities.count)")
    } catch {
      loadError = String(describing: error)
      log("monitor error \(error)")
    }
  }

  /// a picture of the extension's view, only once it has drawn real content
  private func picture() -> UIImage? {
    guard drawn, let v = hostVC?.view, v.bounds.width > 0 else { return nil }
    let img = UIGraphicsImageRenderer(bounds: v.bounds).image { _ in _ = v.drawHierarchy(in: v.bounds, afterScreenUpdates: false) }
    // decoded now, so it is on screen in the very next frame (a 1206×2622 image decoded on its first draw left the
    // screen blank for ~70 ms)
    return img.preparingForDisplay() ?? img
  }

  /// anyone may ask (the extension, over XPC); the options only pre-fill the shell's page
  func enterSecure(_ optionsJSON: String) {
    if leaving { queuedEnter = optionsJSON; return }
    guard mode == .normal else { return }
    let opts = (try? JSONSerialization.jsonObject(with: Data(optionsJSON.utf8))) as? [String: Any] ?? [:]
    switch opts["kind"] as? String {
    case "new-session": route = .newSession
    case "approval":
      guard let id = opts["approvalId"] as? String else { log("approval without an id refused"); return }
      route = .approval(id)
    case "stores": route = .stores
    case "grant":
      guard let id = opts["sessionId"] as? String else { log("grant without a session refused"); return }
      route = .grant(id)
    case "setup": route = .setup
    case "unlock":
      guard let id = opts["sessionId"] as? String else { log("unlock without a session refused"); return }
      route = .unlock(id)
    case "repo-key":
      guard let r = opts["repo"] as? String, !r.isEmpty, ["add", "remove"].contains(opts["action"] as? String ?? "") else { log("repo key without a repo or action refused"); return }
      route = .repoKey
    default: log("secure request of unknown kind refused"); return
    }
    log("enter secure \(opts["kind"] ?? "")")
    secureOptions = opts
    signedAction = nil
    transition += 1
    let tr = transition
    // the picture of the app as it is now; while the shell is already covering a relaunching extension with the
    // last picture, that one stays (the extension has nothing better on screen)
    if !(showSnapshot && onReady != nil) { snapshot = picture() }
    stopWaiting()
    // the picture goes over the extension's view at the same frame and the page waits off the trailing edge; the
    // extension takes no taps from now on
    Shell.instantly {
      showSnapshot = snapshot != nil
      progress = 0
      mode = .secure
    }
    // a moment later (the picture drawn) the extension's view goes — it can't draw or take taps while a secure page
    // is up — and the push runs: the page comes in, the app slides back a third and dims a little. Not when this
    // page has been left already (a Back in these 50 ms): the extension must stay for the app
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [self] in
      guard tr == transition, mode == .secure, !leaving else { return }
      Shell.instantly { extensionMounted = false }
      extensionProxy = nil; hostVC = nil
      withAnimation(Shell.push) { progress = 1 }
    }
  }

  /// only the shell's own code calls this. `done` = the page's action went through (a cert the core
  /// issued, an unlock the core confirmed…); `id` = the session it concerned, if any.
  ///
  /// Back pops at once over the picture of the app as it was (that is what lies under the page); the extension
  /// is re-added under the picture, and the picture goes once the extension says it has drawn real content in its
  /// window — after a relaunch too (iOS ends the extension's process while its view is away, under memory
  /// pressure or in the background), which the shell notices and repairs. A finished action (or leaving a page with
  /// no picture under it) first lets the app show the result under the page, e.g. the New session form closed,
  /// then pops over the live app: one motion, never the old screen first and never a blank one.
  func exitSecure(_ why: String, done: Bool = false, id: String? = nil) {
    guard mode == .secure, !leaving else { return }
    log("exit secure: \(why)")
    // an Inbox request whose page went through leaves the Inbox (an approval leaves by itself once answered)
    if done, let iid = secureOptions["inboxId"] as? String, secureOptions["approvalId"] == nil { Task { await RouterClient.shared.inboxDone(iid) } }
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    transition += 1
    let tr = transition
    exitId = (secureOptions["requestId"] as? String) ?? "shell-" + UUID().uuidString
    var r: [String: Any] = ["result": done ? "done" : "back", "requestId": exitId]
    if let k = secureOptions["kind"] as? String { r["kind"] = k }
    if let id { r["id"] = id }
    pendingFinish = (try? JSONSerialization.data(withJSONObject: r)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    leaving = true; popDone = false; settled = false
    let live = done || !showSnapshot || snapshot == nil
    Shell.instantly { preparing = live }
    if extensionMounted {
      // never removed (a Back within the page's first 50 ms): the same extension, told at once
      deliverFinish()
    } else {
      mount += 1; mountedAt = Date()
      Shell.instantly { extensionMounted = true }
    }
    if live {
      waitReady { [self] in
        Shell.instantly { preparing = false; showSnapshot = false }
        ready = true
        pop(tr)
      }
    } else {
      pop(tr)
      waitReady { [self] in ready = true; finishLeaving() }
    }
  }
  @ObservationIgnored private var ready = false

  private func pop(_ tr: Int) {
    withAnimation(Shell.push) { progress = 0 } completion: { [self] in popped(tr) }
    // a completion that doesn't come (nothing left to animate after an edge swipe, or the app went to the
    // background mid-motion) doesn't hold the page
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [self] in popped(tr) }
  }
  private func popped(_ tr: Int) {
    guard tr == transition, leaving, !popDone else { return }
    popDone = true
    finishLeaving()
  }

  private func finishLeaving() {
    guard popDone else { return }
    if mode == .secure { Shell.instantly { mode = .normal; progress = 0 } }
    guard ready else { return }
    if showSnapshot { withAnimation(.easeOut(duration: 0.12)) { showSnapshot = false } }
    leaving = false; popDone = false; ready = false; settled = false
    refreshLists()
    if let q = queuedEnter { queuedEnter = nil; DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { self.enterSecure(q) } }
  }

  // ---- waiting for the extension: its own word that it has drawn, a check that it is alive, a relaunch if not ----

  /// runs `then` once the extension has drawn real content in its window (and, when it was told a result,
  /// handled it — or a second after drawing, since the app is on screen by then). A dead or hung extension is
  /// relaunched while the picture (or the page) stays; nothing here reveals a blank app on a timer. A last-resort
  /// cap (20 s, an extension that answers but never draws) is logged.
  private func waitReady(_ then: @escaping () -> Void) {
    onReady = then; readySince = Date(); drawnAt = nil
    watchdog?.invalidate()
    watchdog = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.checkReady() }
    checkReady()
  }
  private func stopWaiting() { onReady = nil; watchdog?.invalidate(); watchdog = nil }
  @ObservationIgnored private var drawnAt: Date?
  private func checkReady() {
    guard let then = onReady else { stopWaiting(); return }
    var go = false
    if drawn {
      if drawnAt == nil { drawnAt = Date() }
      go = settled || Date().timeIntervalSince(drawnAt!) > 1
    } else {
      checkAlive()
      if Date().timeIntervalSince(readySince) > 20 { log("the extension hasn't drawn in 20 s: showing it anyway"); go = true }
    }
    if go {
      log(String(format: "app ready after %.2f s", Date().timeIntervalSince(readySince)))
      stopWaiting(); then()
    }
  }
  @ObservationIgnored private var pingAt = Date.distantPast
  /// the extension answers `hello` from its XPC queue even while its main thread is busy starting React Native,
  /// so no answer within 2 s means it is gone or hung: relaunch it
  private func checkAlive() {
    guard extensionMounted, Date().timeIntervalSince(pingAt) > 3 else { return }
    guard let p = extensionProxy else {
      if Date().timeIntervalSince(mountedAt) > 6 { relaunch("no connection from the extension 6 s after mounting it") }
      return
    }
    ping(p) { [self] alive in if !alive && !drawn { relaunch("the extension doesn't answer") } }
  }
  private func ping(_ p: ExtensionService, _ result: @escaping (Bool) -> Void) {
    pingAt = Date()
    let m = mount
    let answered = Flag()
    p.hello { _ in DispatchQueue.main.async { answered.on = true } }
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [self] in if m == mount { result(answered.on) } }
  }
  final class Flag { var on = false }

  /// a new EXHostViewController for the extension, in place: iOS starts a new process when the old one is gone
  private func relaunch(_ why: String) {
    relaunches = relaunches.filter { Date().timeIntervalSince($0) < 60 }
    guard relaunches.count < 4 else { log("not relaunching again (4 in a minute): \(why)"); return }
    relaunches.append(Date())
    log("relaunching the extension: \(why)")
    extensionProxy = nil; hostVC = nil; pingAt = .distantPast
    if drawnMount == mount { drawnMount = -1 }
    mount += 1; mountedAt = Date()
  }

  /// the extension's process ended or its connection broke (`m` = the mount it belonged to)
  func extensionLost(_ m: Int, _ why: String) {
    guard m == mount, extensionMounted else { return }
    log("extension lost (mount \(m)): \(why)")
    if drawnMount == m { drawnMount = -1 }
    // in the app (no page leaving): the last picture covers it while it comes back, never a blank app
    if mode == .normal && !leaving && onReady == nil {
      if snapshot != nil { Shell.instantly { showSnapshot = true } }
      settled = true
      waitReady { [self] in if showSnapshot { withAnimation(.easeOut(duration: 0.12)) { showSnapshot = false } }; settled = false }
    }
    relaunch(why)
  }

  /// the app went to the background (a fresh picture to cover a relaunch with) or came back (is the extension
  /// still there? iOS may have ended it meanwhile)
  func sceneChanged(_ phase: ScenePhase) {
    switch phase {
    case .background:
      if mode == .normal, !leaving, let p = picture() { snapshot = p }
    case .active:
      guard mode == .normal, !leaving, onReady == nil, extensionMounted else { return }
      guard let p = extensionProxy else { extensionLost(mount, "no connection after coming back"); return }
      let m = mount
      ping(p) { [self] alive in if !alive && m == mount { extensionLost(m, "no answer after coming back") } }
    default: break
    }
  }

  /// the iOS navigation push/pop curve
  static let push = Animation.timingCurve(0.2, 0.9, 0.3, 1, duration: 0.45)
  static func instantly(_ change: () -> Void) {
    var t = Transaction(); t.disablesAnimations = true
    withTransaction(t, change)
  }

  /// the extension of mount `m` is connected: tell React Native how the page ended, and ask it to say when it
  /// has drawn real content in its window
  func extensionDidActivate(_ m: Int, _ proxy: ExtensionService?) {
    guard m == mount else { return }
    extensionProxy = proxy
    deliverFinish()
    proxy?.whenDrawn { [weak self] _ in DispatchQueue.main.async { self?.extensionDrawn(m) } }
  }
  private func deliverFinish() {
    guard let f = pendingFinish, let p = extensionProxy else { return }
    pendingFinish = nil
    p.secureFinished(f)
  }
  func extensionDrawn(_ m: Int) {
    guard m == mount else { return }
    if drawnMount != m { log(String(format: "extension drawn (mount %d) %.2f s after mounting", m, Date().timeIntervalSince(mountedAt))) }
    drawnMount = m
    checkReady()
  }
  /// React Native has handled the result of exit `id` and drawn it
  func extensionSettled(_ id: String) {
    guard leaving, id == exitId else { return }
    settled = true
    checkReady()
  }

  // ---- the edge swipe: the page follows the finger over the picture of the app, as a native page does ----
  var canSwipeBack: Bool { mode == .secure && !leaving && showSnapshot && snapshot != nil }
  func swipeChanged(_ dx: CGFloat) {
    guard canSwipeBack, width > 0 else { return }
    Shell.instantly { progress = max(0, min(1, 1 - dx / width)) }
  }
  func swipeEnded(_ dx: CGFloat, predicted: CGFloat) {
    guard mode == .secure, !leaving, width > 0 else { return }
    if dx > width * 0.5 || predicted > width * 0.6 { exitSecure("back (edge swipe)") }
    else { withAnimation(Shell.push) { progress = 1 } }
  }
}

final class HostServiceImpl: NSObject, HostService {
  let shell: Shell
  init(shell: Shell) { self.shell = shell }
  func requestSecureMode(_ options: String) { DispatchQueue.main.async { [shell] in shell.enterSecure(options) } }
  func report(_ line: String) { DispatchQueue.main.async { [shell] in shell.log("ext: " + line) } }
  func secureSettled(_ requestId: String) { DispatchQueue.main.async { [shell] in shell.extensionSettled(requestId) } }
  /// the router's address and the Access token, as JSON {base, token}
  func session(_ reply: @escaping (String) -> Void) {
    Task { @MainActor in
      let r = RouterClient.shared
      let j = (try? JSONSerialization.data(withJSONObject: ["base": r.base.absoluteString, "token": r.token])) ?? Data("{}".utf8)
      reply(String(decoding: j, as: UTF8.self))
    }
  }
  /// runs the sign-in sheet; replies the new token, "" when it didn't complete
  func signIn(_ reply: @escaping (String) -> Void) { Task { @MainActor in reply(await RouterClient.shared.signIn()) } }
  /// plain text onto the clipboard for the React Native UI (links, ids, paths — never anything the shell
  /// guards: the recovery kit has its own local-only, expiring copy). At most 64 KB.
  func copyText(_ text: String) {
    guard text.utf8.count <= 65536 else { return }
    DispatchQueue.main.async { UIPasteboard.general.string = text }
  }
}

struct RootView: View {
  @State private var shell = Shell()
  @Environment(\.scenePhase) private var scenePhase

  var body: some View {
    let width = shell.width
    ZStack {
      Radix.background.ignoresSafeArea()
      // the app — the extension's live view, and its picture over it while that stands in — slides back a third
      // and dims a little under a secure page, like the page under a native push
      ZStack {
        if shell.extensionMounted, let identity = shell.identity {
          // a new mount is a new EXHostViewController (and a relaunched process when iOS ended the old one)
          ExtensionHost(identity: identity, shell: shell, mount: shell.mount)
            .id(shell.mount)
            .ignoresSafeArea()
            .accessibilityIdentifier("extension-host")
            .allowsHitTesting(shell.mode == .normal)
        } else if shell.mode == .normal, let e = shell.loadError {
          Text(e).font(.footnote).foregroundStyle(Radix.red.a[11]).padding()
        }
        if shell.showSnapshot, let img = shell.snapshot {
          Image(uiImage: img).resizable().ignoresSafeArea().allowsHitTesting(false).accessibilityHidden(true)
        }
        Color.black.opacity(0.12 * shell.progress).ignoresSafeArea().allowsHitTesting(false)
      }
      .offset(x: -width * 0.3 * shell.progress)
      if shell.mode == .secure {
        SecurePageFor(shell: shell)
          .shadow(color: .black.opacity(0.12), radius: 12, x: -2, y: 0)
          .offset(x: (width + 24) * (1 - shell.progress))
          .allowsHitTesting(!shell.leaving)
      }
    }
    .background { Color.clear.ignoresSafeArea().onGeometryChange(for: CGFloat.self) { $0.size.width } action: { shell.width = $0 } }
    .task { await shell.load() }
    .onChange(of: scenePhase) { _, p in shell.sceneChanged(p) }
    .onReceive(NotificationCenter.default.publisher(for: UIApplication.didReceiveMemoryWarningNotification)) { _ in shell.log("memory warning") }
  }
}

/// the page for the current route
struct SecurePageFor: View {
  let shell: Shell
  var body: some View {
    switch shell.route {
    case .newSession: SecureNewSession(shell: shell, options: shell.secureOptions)
    case .approval(let id): SecureApproval(shell: shell, approvalId: id)
    case .stores: SecureStores(shell: shell)
    case .setup: SetupPage(shell: shell)
    case .grant(let id): SecureGrant(shell: shell, sessionId: id, options: shell.secureOptions)
    case .repoKey: SecureRepoKey(shell: shell, options: shell.secureOptions)
    case .unlock(let id): SecureUnlock(shell: shell, sessionId: id, options: shell.secureOptions)
    }
  }
}

struct ExtensionHost: UIViewControllerRepresentable {
  let identity: AppExtensionIdentity
  let shell: Shell
  /// which mount this is (Shell.mount): what this host reports is dropped once a newer one exists
  let mount: Int

  func makeCoordinator() -> Coordinator { Coordinator(shell: shell, mount: mount) }
  func makeUIViewController(context: Context) -> EXHostViewController {
    let vc = EXHostViewController()
    vc.delegate = context.coordinator
    vc.configuration = EXHostViewController.Configuration(appExtension: identity, sceneID: "main")
    shell.hostVC = vc
    return vc
  }
  func updateUIViewController(_ vc: EXHostViewController, context: Context) {}

  final class Coordinator: NSObject, EXHostViewControllerDelegate {
    let shell: Shell
    let mount: Int
    var connection: NSXPCConnection?
    init(shell: Shell, mount: Int) { self.shell = shell; self.mount = mount }

    func hostViewControllerDidActivate(_ viewController: EXHostViewController) {
      do {
        let c = try viewController.makeXPCConnection()
        c.exportedInterface = NSXPCInterface(with: HostService.self)
        c.exportedObject = HostServiceImpl(shell: shell)
        c.remoteObjectInterface = NSXPCInterface(with: ExtensionService.self)
        // the extension's process ended (iOS ends it under memory pressure or in the background) or the link broke
        c.invalidationHandler = { [shell, mount] in DispatchQueue.main.async { shell.extensionLost(mount, "XPC connection invalidated") } }
        c.interruptionHandler = { [shell, mount] in DispatchQueue.main.async { shell.extensionLost(mount, "XPC connection interrupted") } }
        c.resume()
        connection = c
        let proxy = c.remoteObjectProxyWithErrorHandler { [shell] e in DispatchQueue.main.async { shell.log("xpc error \(e)") } } as? ExtensionService
        // an XPC connection only reaches the other side with its first message
        proxy?.hello { [shell, mount] a in DispatchQueue.main.async { shell.log("xpc (mount \(mount)): \(a)") } }
        // after the hello on the same connection: how the secure page ended, and "say when you have drawn"
        shell.extensionDidActivate(mount, proxy)
      } catch {
        shell.log("xpc error \(error)")
        shell.extensionLost(mount, "no XPC connection: \(error.localizedDescription)")
      }
    }
    func hostViewControllerWillDeactivate(_ viewController: EXHostViewController, error: (any Error)?) {
      // with an error the extension is gone; without one (the app going to the background) the shell checks
      // the extension when the app comes back (Shell.sceneChanged)
      if let error { DispatchQueue.main.async { [shell, mount] in shell.extensionLost(mount, "deactivated: \(error.localizedDescription)") } }
      else { DispatchQueue.main.async { [shell, mount] in shell.log("extension deactivated (mount \(mount))") } }
    }
  }
}
