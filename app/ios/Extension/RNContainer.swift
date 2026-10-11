// React Native (Expo) started inside the extension, the way Expo's own AppDelegate starts it in an app.
internal import Expo
import React
import ReactAppDependencyProvider
import SwiftUI
import UIKit

final class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? { bundleURL() }
  override func bundleURL() -> URL? { Bundle.main.url(forResource: "main", withExtension: "jsbundle") }
}

/// one React Native instance per extension process; the root view is reused if the scene is rebuilt
enum RN {
  static let delegate: ReactNativeDelegate = {
    let d = ReactNativeDelegate()
    d.dependencyProvider = RCTAppDependencyProvider()
    return d
  }()
  static let factory = ExpoReactNativeFactory(delegate: delegate)
  static let rootView: UIView = factory.rootViewFactory.view(withModuleName: "main", initialProperties: nil, launchOptions: nil)
}

struct RNContainer: UIViewRepresentable {
  /// the newest scene's host view: React Native's root view lives in it (HostLink.whenDrawn looks there)
  static weak var current: UIView?
  func makeUIView(context: Context) -> UIView {
    let host = UIView()
    RNContainer.current = host
    let v = RN.rootView
    v.removeFromSuperview()
    v.frame = host.bounds
    v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    host.addSubview(v)
    return host
  }
  func updateUIView(_ uiView: UIView, context: Context) {}
}
