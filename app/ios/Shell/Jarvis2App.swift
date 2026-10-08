// Jarvis 2: a small native shell that owns the window. The whole Jarvis React Native UI runs in the
// bundled ExtensionKit extension (JarvisUI), in its own process, shown full-screen in normal mode. Anything
// may ask to ENTER secure mode (XPC requestSecureMode) on one of the shell's pages — new session, an
// approval, stores, pairing; only this shell's own code leaves it. In secure mode the extension's view is
// removed — it cannot draw or receive taps — and the shell pushes its own page over a still snapshot of the
// app with the native push motion (no sheets: forms are pages), so the switch looks seamless. Back pops it
// to the right; a finished action leaves to the left. The shell also owns sign-in (RouterClient) and hands
// the extension the router's address and the Access token.
import ExtensionFoundation
import ExtensionKit
import SwiftUI

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
enum Route: Equatable { case newSession, approval(String), stores, pairing }

@Observable
final class Shell {
  var mode: Mode = .normal
  var route: Route = .pairing
  var secureOptions: [String: Any] = [:]
  var identity: AppExtensionIdentity?
  var snapshot: UIImage?
  var coverWithSnapshot = false
  var loadError: String?
  /// how the secure page leaves: to the trailing edge (Back) or the leading edge (Create — "go ahead")
  var exitForward = false
  var extensionProxy: ExtensionService?
  weak var hostVC: EXHostViewController?
  var lines: [String] = []
  private var monitor: AppExtensionPoint.Monitor?
  private let t0 = Date()

  func log(_ s: String) {
    let line = String(format: "%.1f ", Date().timeIntervalSince(t0)) + s
    NSLog("[shell] %@", line)
    lines.append(line)
  }

  /// the core's signed store list, fetched at launch so the secure page is filled at once (it is
  /// fetched again, with a fresh nonce, every time the page opens)
  var prefetched: [StoreView]?

  func load() async {
    if CoreTrust.paired == nil {
      // not paired yet: the pairing page comes first (Back leaves it for the app, which can still view)
      route = .pairing; mode = .secure
    } else {
      Task { @MainActor in
        let t = Date()
        do { prefetched = try await RouterClient.shared.stores(); log(String(format: "core stores prefetched in %.2fs", Date().timeIntervalSince(t))) }
        catch { log("core stores prefetch failed: \(error.localizedDescription)") }
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
    guard mode == .normal else { return }
    let opts = (try? JSONSerialization.jsonObject(with: Data(optionsJSON.utf8))) as? [String: Any] ?? [:]
    switch opts["kind"] as? String {
    case "new-session": route = .newSession
    case "approval":
      guard let id = opts["approvalId"] as? String else { log("approval without an id refused"); return }
      route = .approval(id)
    case "stores": route = .stores
    case "pairing": route = .pairing
    default: log("secure request of unknown kind refused"); return
    }
    log("enter secure \(opts["kind"] ?? "")")
    secureOptions = opts
    captureSnapshot()
    exitForward = false
    withAnimation(Shell.push) { mode = .secure }
  }

  /// only the shell's own code calls this. `done` = the page's action went through (a cert the core
  /// issued, an unlock the core confirmed…); `id` = the session it concerned, if any.
  func exitSecure(_ why: String, done: Bool = false, id: String? = nil) {
    log("exit secure: \(why)")
    exitForward = done
    coverWithSnapshot = snapshot != nil
    withAnimation(Shell.push) { mode = .normal }
    var r: [String: Any] = ["result": done ? "done" : "back"]
    if let rid = secureOptions["requestId"] as? String { r["requestId"] = rid }
    if let k = secureOptions["kind"] as? String { r["kind"] = k }
    if let id { r["id"] = id }
    let json = (try? JSONSerialization.data(withJSONObject: r)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    // the extension's view is back a moment later; tell React Native once it is listening again
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.extensionProxy?.secureFinished(json) }
  }

  /// the iOS navigation push/pop curve
  static let push = Animation.timingCurve(0.2, 0.9, 0.3, 1, duration: 0.45)

  func extensionDidActivate() {
    guard coverWithSnapshot else { return }
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { withAnimation(.easeOut(duration: 0.15)) { self.coverWithSnapshot = false } }
  }
}

final class HostServiceImpl: NSObject, HostService {
  let shell: Shell
  init(shell: Shell) { self.shell = shell }
  func requestSecureMode(_ options: String) { DispatchQueue.main.async { [shell] in shell.enterSecure(options) } }
  func report(_ line: String) { DispatchQueue.main.async { [shell] in shell.log("ext: " + line) } }
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
}

struct RootView: View {
  @State private var shell = Shell()

  var body: some View {
    ZStack {
      Radix.background.ignoresSafeArea()
      if shell.mode == .normal {
        if let identity = shell.identity {
          ExtensionHost(identity: identity, shell: shell)
            .ignoresSafeArea()
            .accessibilityIdentifier("extension-host")
            .transition(.identity)
            .overlay {
              if shell.coverWithSnapshot, let img = shell.snapshot {
                Image(uiImage: img).resizable().ignoresSafeArea().allowsHitTesting(false)
              }
            }
        } else if let e = shell.loadError {
          Text(e).font(.footnote).foregroundStyle(Radix.red.a[11]).padding()
        }
      } else {
        // a still image of the app (shell-owned pixels) slides back and dims a little, like the page
        // under a native push; the shell's own page comes in over it
        GeometryReader { g in
          if let img = shell.snapshot {
            Image(uiImage: img).resizable().ignoresSafeArea()
              .overlay(Color.black.opacity(0.12).ignoresSafeArea())
              .offset(x: -g.size.width * 0.3)
              .transition(.asymmetric(insertion: .offset(x: g.size.width * 0.3).combined(with: .identity), removal: .offset(x: g.size.width * 0.3)))
              .accessibilityHidden(true)
          }
        }
        .ignoresSafeArea()
        SecurePageFor(shell: shell)
          .shadow(color: .black.opacity(0.12), radius: 12, x: -2, y: 0)
          .transition(.asymmetric(insertion: .move(edge: .trailing), removal: shell.exitForward ? .move(edge: .leading) : .move(edge: .trailing)))
      }
    }
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
    case .pairing: PairingPage(shell: shell)
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
      shell.extensionDidActivate()
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
      } catch {
        shell.log("xpc error \(error)")
      }
    }
    func hostViewControllerWillDeactivate(_ viewController: EXHostViewController, error: (any Error)?) {}
  }
}
