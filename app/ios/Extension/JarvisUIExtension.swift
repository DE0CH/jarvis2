// The ExtensionKit extension that runs the whole Jarvis React Native UI, in its own process. It can ask
// the shell to enter secure mode (ShellBridge → HostLink → XPC); it can't leave it, and while it is up the
// shell has removed this extension's view.
import ExtensionFoundation
import ExtensionKit
import SwiftUI

struct JarvisUIConfiguration<E: JarvisUIExtensionProtocol>: AppExtensionConfiguration {
  let appExtension: E
  init(_ appExtension: E) { self.appExtension = appExtension }
  func accept(connection: NSXPCConnection) -> Bool { HostLink.shared.attach(connection); return true }
}

protocol JarvisUIExtensionProtocol: AppExtension {
  associatedtype Body: JarvisUIScene
  var body: Body { get }
}
protocol JarvisUIScene: AppExtensionScene {}

struct MainScene<Content: View>: JarvisUIScene {
  private let content: () -> Content
  init(content: @escaping () -> Content) { self.content = content }
  var body: some AppExtensionScene {
    PrimitiveAppExtensionScene(id: "main") { content() } onConnection: { connection in
      HostLink.shared.attach(connection)
      return true
    }
  }
}

extension JarvisUIExtensionProtocol {
  var configuration: AppExtensionSceneConfiguration { AppExtensionSceneConfiguration(self.body, configuration: JarvisUIConfiguration(self)) }
}

@main
final class JarvisUIExtension: JarvisUIExtensionProtocol {
  required init() { _ = HostLink.shared }
  @AppExtensionPoint.Bind
  var boundExtensionPoint: AppExtensionPoint { AppExtensionPoint.Identifier(host: "dev.de0ch.jarvis2", name: "jarvisUI") }
  var body: some JarvisUIScene { MainScene { RNContainer().ignoresSafeArea() } }
}

/// the extension's end of the XPC link; ShellBridge (ObjC, React Native) reaches it via NotificationCenter
final class HostLink: NSObject {
  static let shared = HostLink()
  private var connection: NSXPCConnection?
  typealias Reply = @convention(block) (NSString) -> Void
  private var pending: [(String, String, Reply?)] = []

  override init() {
    super.init()
    NotificationCenter.default.addObserver(forName: Notification.Name("JarvisShellCall"), object: nil, queue: .main) { [weak self] n in
      let reply = n.userInfo?["reply"].map { unsafeBitCast($0 as AnyObject, to: Reply.self) }
      self?.call(n.userInfo?["method"] as? String ?? "", n.userInfo?["arg"] as? String ?? "", reply)
    }
  }

  func attach(_ c: NSXPCConnection) {
    c.remoteObjectInterface = NSXPCInterface(with: HostService.self)
    c.exportedInterface = NSXPCInterface(with: ExtensionService.self)
    c.exportedObject = ExtensionServiceImpl()
    c.resume()
    connection = c
    let q = pending; pending = []
    for (m, a, r) in q { call(m, a, r) }
  }

  /// calls wait for the shell's first message (XPC is lazy: the connection exists only once it arrives)
  func call(_ method: String, _ arg: String, _ reply: Reply? = nil) {
    guard let c = connection else { pending.append((method, arg, reply)); return }
    let proxy = c.remoteObjectProxyWithErrorHandler { e in
      NSLog("[ext] xpc error %@", String(describing: e))
      DispatchQueue.main.async { reply?("" as NSString) }
    } as? HostService
    switch method {
    case "secure":
      RN.rootView.window?.endEditing(true) // cosmetic: no keyboard over the shell's snapshot
      proxy?.requestSecureMode(arg)
    case "session": proxy?.session { s in DispatchQueue.main.async { reply?(s as NSString) } }
    case "signIn": proxy?.signIn { s in DispatchQueue.main.async { reply?(s as NSString) } }
    case "copy": proxy?.copyText(arg)
    default: proxy?.report(arg)
    }
  }
}

final class ExtensionServiceImpl: NSObject, ExtensionService {
  func hello(_ reply: @escaping (String) -> Void) { reply("extension pid \(getpid())") }
  func secureFinished(_ result: String) {
    DispatchQueue.main.async { NotificationCenter.default.post(name: Notification.Name("JarvisShellEvent"), object: nil, userInfo: ["name": "secureFinished", "body": result]) }
  }
}
