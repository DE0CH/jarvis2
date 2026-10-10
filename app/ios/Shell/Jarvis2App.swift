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
  var identity: AppExtensionIdentity?
  var loadError: String?
  /// the push/pop motion: 0 = the app on screen, 1 = a secure page fully in (the app slid back under it)
  var progress: CGFloat = 0
  /// the extension's view is in the window. Never while a secure page is up; back in the moment the shell
  /// decides to leave, under the page (and under the picture below) until it has drawn
  var extensionMounted = true
  /// a still picture of the app (shell-owned pixels), taken when a secure page is asked for
  var snapshot: UIImage?
  /// the picture is on screen: in the extension's place under a page, and over the re-added extension on a Back
  /// until React Native has drawn again
  var showSnapshot = false
  /// the shell has left secure mode (only its own code does): the page takes no more taps
  var leaving = false
  /// leaving, with the page still fully in: the app is getting ready under it (after Create, or at launch)
  var preparing = false
  var extensionProxy: ExtensionService?
  weak var hostVC: EXHostViewController?
  var lines: [String] = []
  private var monitor: AppExtensionPoint.Monitor?
  private let t0 = Date()
  /// the result to tell React Native once the re-added extension's connection is up
  private var pendingFinish: String?
  private var onSettled: (() -> Void)?
  private var popDone = false, settled = false
  /// a secure page asked for while one is still leaving: it comes once that one is gone
  private var queuedEnter: String?

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

  func captureSnapshot() {
    guard let v = hostVC?.view, v.bounds.width > 0 else { snapshot = nil; return }
    snapshot = UIGraphicsImageRenderer(bounds: v.bounds).image { _ in _ = v.drawHierarchy(in: v.bounds, afterScreenUpdates: false) }
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
    captureSnapshot()
    // decoded now, so the picture is on screen in the very next frame (a 1206×2622 image decoded on its first draw
    // left the screen blank for ~70 ms, and the push then jumped to its end)
    snapshot = snapshot?.preparingForDisplay() ?? snapshot
    // the picture goes over the extension's view at the same frame and the page waits off the trailing edge; the
    // extension takes no taps from now on
    Shell.instantly {
      showSnapshot = snapshot != nil
      progress = 0
      mode = .secure
    }
    // a moment later (the picture drawn) the extension's view goes — it can't draw or take taps while a secure page
    // is up — and the push runs: the page comes in, the app slides back a third and dims a little
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
      Shell.instantly { self.extensionMounted = false }
      withAnimation(Shell.push) { self.progress = 1 }
    }
  }

  /// only the shell's own code calls this. `done` = the page's action went through (a cert the core
  /// issued, an unlock the core confirmed…); `id` = the session it concerned, if any.
  ///
  /// Back pops at once over the picture of the app as it was (that is what lies under the page); the extension
  /// is re-added under the picture, and the picture goes once React Native has drawn again. A finished action
  /// (or leaving the page shown at launch, with no picture) first lets the app show the result under the page,
  /// e.g. the New session form closed, then pops over the live app: one motion, never the old screen first.
  func exitSecure(_ why: String, done: Bool = false, id: String? = nil) {
    guard mode == .secure, !leaving else { return }
    log("exit secure: \(why)")
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    var r: [String: Any] = ["result": done ? "done" : "back"]
    if let rid = secureOptions["requestId"] as? String { r["requestId"] = rid }
    if let k = secureOptions["kind"] as? String { r["kind"] = k }
    if let id { r["id"] = id }
    pendingFinish = (try? JSONSerialization.data(withJSONObject: r)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    leaving = true; popDone = false; settled = false
    let live = done || !showSnapshot
    Shell.instantly { preparing = live; extensionMounted = true }
    if live {
      waitSettled(timeout: showSnapshot ? 2 : 15) { [self] in
        settled = true
        Shell.instantly { preparing = false; showSnapshot = false }
        pop()
      }
    } else {
      pop()
      waitSettled(timeout: 2) { [self] in settled = true; finishLeaving() }
    }
  }

  private func pop() {
    withAnimation(Shell.push) { progress = 0 } completion: { [self] in popDone = true; finishLeaving() }
  }

  private func finishLeaving() {
    guard popDone else { return }
    if mode == .secure { Shell.instantly { mode = .normal } }
    guard settled else { return }
    if showSnapshot { withAnimation(.easeOut(duration: 0.12)) { showSnapshot = false } }
    leaving = false; popDone = false; settled = false
    refreshLists()
    if let q = queuedEnter { queuedEnter = nil; DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { self.enterSecure(q) } }
  }

  /// runs `then` once React Native says it has drawn the result, or after `timeout` (a missing answer never
  /// leaves a page or a picture on screen)
  private func waitSettled(timeout: TimeInterval, _ then: @escaping () -> Void) {
    var fired = false
    let fire: () -> Void = { [weak self] in
      guard !fired else { return }
      fired = true; self?.onSettled = nil; then()
    }
    onSettled = fire
    DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
      guard !fired else { return }
      self?.log("no answer from the app in \(Int(timeout)) s: showing it anyway")
      fire()
    }
  }

  /// the iOS navigation push/pop curve
  static let push = Animation.timingCurve(0.2, 0.9, 0.3, 1, duration: 0.45)
  static func instantly(_ change: () -> Void) {
    var t = Transaction(); t.disablesAnimations = true
    withTransaction(t, change)
  }

  /// the re-added extension is connected again: tell React Native how the page ended
  func extensionDidActivate() {
    guard let f = pendingFinish else { return }
    pendingFinish = nil
    extensionProxy?.secureFinished(f)
  }
  func extensionSettled() { onSettled?() }
}

final class HostServiceImpl: NSObject, HostService {
  let shell: Shell
  init(shell: Shell) { self.shell = shell }
  func requestSecureMode(_ options: String) { DispatchQueue.main.async { [shell] in shell.enterSecure(options) } }
  func report(_ line: String) { DispatchQueue.main.async { [shell] in shell.log("ext: " + line) } }
  func secureSettled(_ requestId: String) { DispatchQueue.main.async { [shell] in shell.extensionSettled() } }
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
  /// the window's full width (the push moves by it)
  @State private var width: CGFloat = 0

  var body: some View {
    ZStack {
      Radix.background.ignoresSafeArea()
      // the app — the extension's live view, and its picture over it while that stands in — slides back a third
      // and dims a little under a secure page, like the page under a native push
      ZStack {
        if shell.extensionMounted, let identity = shell.identity {
          ExtensionHost(identity: identity, shell: shell)
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
    .background { Color.clear.ignoresSafeArea().onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 } }
    .task { await shell.load() }
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

  func makeCoordinator() -> Coordinator { Coordinator(shell: shell) }
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
    var connection: NSXPCConnection?
    init(shell: Shell) { self.shell = shell }

    func hostViewControllerDidActivate(_ viewController: EXHostViewController) {
      do {
        let c = try viewController.makeXPCConnection()
        c.exportedInterface = NSXPCInterface(with: HostService.self)
        c.exportedObject = HostServiceImpl(shell: shell)
        c.remoteObjectInterface = NSXPCInterface(with: ExtensionService.self)
        c.resume()
        connection = c
        shell.extensionProxy = c.remoteObjectProxyWithErrorHandler { [shell] e in DispatchQueue.main.async { shell.log("xpc error \(e)") } } as? ExtensionService
        // an XPC connection only reaches the other side with its first message
        (c.remoteObjectProxyWithErrorHandler { [shell] e in DispatchQueue.main.async { shell.log("xpc error \(e)") } } as? ExtensionService)?
          .hello { [shell] a in DispatchQueue.main.async { shell.log("xpc: \(a)") } }
        // after the hello on the same connection: how the secure page ended, if the shell has just left one
        shell.extensionDidActivate()
      } catch {
        shell.log("xpc error \(error)")
      }
    }
    func hostViewControllerWillDeactivate(_ viewController: EXHostViewController, error: (any Error)?) {}
  }
}
