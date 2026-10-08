// swift-tools-version:5.9
// The shell's crypto (Shell/CoreCrypto.swift, symlinked in) against the REAL core binary: CI builds the core
// with -tags fakefly, starts it and runs `swift run Interop <core url> <setup token>`. On macOS this uses
// CryptoKit (what the app uses); on Linux swift-crypto (same API) for running it locally.
import PackageDescription
#if os(Linux)
let deps: [Package.Dependency] = [.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")]
let tdeps: [Target.Dependency] = [.product(name: "Crypto", package: "swift-crypto")]
#else
let deps: [Package.Dependency] = []
let tdeps: [Target.Dependency] = []
#endif
let package = Package(name: "Interop", platforms: [.macOS(.v14)], dependencies: deps,
  targets: [.executableTarget(name: "Interop", dependencies: tdeps)])
