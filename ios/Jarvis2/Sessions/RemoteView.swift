// Remote control of a session the Claude app doesn't see (GET api/sessions/:id/remote): OpenCode's Paseo web UI and
// pairing offer, or OpenClaw's Control UI. The router reads them inside the machine with a shell command, so only while
// a terminal is open (a 403 {needsTerminal} offers the terminal's approval).
import CoreImage.CIFilterBuiltins
import SwiftUI

struct RemoteView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.openURL) private var openURL
  let sessionId: String
  let title: String
  @State private var info: JSON?
  @State private var error: String?
  @State private var needsTerminal = false
  @State private var attempt = 0

  var body: some View {
    List {
      if let error {
        Section {
          ErrorRow(text: error, id: "rm-error")
          if needsTerminal, let m = model.session(sessionId) {
            Button("Open a terminal for 10 minutes", systemImage: "terminal") {
              Task { await model.requestTerminal(m) { ok in if ok { attempt += 1 } } }
            }
            .accessibilityIdentifier("rm-allow")
          }
        }
      } else if let info {
        let web = info["webUrl"].string ?? ""
        let openclaw = info["harness"].string == "openclaw"
        Section {
          if let u = URL(string: web) {
            Button(openclaw ? "Open the Control UI" : "Open the web UI", systemImage: "safari") { openURL(u) }.accessibilityIdentifier("rm-web")
          }
          Button("Copy link", systemImage: "doc.on.doc") { model.copy(web, "Link") }.accessibilityIdentifier("rm-copy-web")
        } header: { Text("Web UI") } footer: {
          Text("Carries the session's key: don't share it.")
        }
        if let pair = info["pairUrl"].text {
          let appUrl = pair.contains("#offer=") ? "paseo:///" + String(pair[pair.range(of: "#offer=")!.lowerBound...]) : pair
          Section {
            if let u = URL(string: appUrl) {
              Button("Pair this device", systemImage: "iphone.and.arrow.forward") { openURL(u) }.accessibilityIdentifier("rm-pair")
            }
            Button("Copy pairing link", systemImage: "doc.on.doc") { model.copy(pair, "Pairing link") }.accessibilityIdentifier("rm-copy-pair")
            Text(pair).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            if let qr = QRCode.image(appUrl) {
              Image(uiImage: qr).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 320)
                .accessibilityLabel("Pairing QR code").accessibilityIdentifier("rm-qr")
            }
          } header: { Text("Paseo app") } footer: {
            Text("Carries the session's key: don't share it.")
          }
        }
      }
    }
    .overlay { if info == nil && error == nil { ProgressView("Loading…") } }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .task(id: attempt) { await load() }
  }

  private func load() async {
    error = nil; info = nil; needsTerminal = false
    do { info = try await RouterClient.shared.get("api/sessions/\(sessionId)/remote") }
    catch { self.error = errText(error); needsTerminal = (error as? RouterError)?.body["needsTerminal"].bool == true }
  }
}

enum QRCode {
  /// a square QR code of `text` (CoreImage), black on white with a quiet zone
  static func image(_ text: String) -> UIImage? {
    let f = CIFilter.qrCodeGenerator()
    f.message = Data(text.utf8)
    f.correctionLevel = "M"
    guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
          let cg = CIContext().createCGImage(out, from: out.extent) else { return nil }
    return UIImage(cgImage: cg)
  }
}
