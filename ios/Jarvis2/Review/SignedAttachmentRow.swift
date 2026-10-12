// One attachment of a new session as its signed config names it (name, size, sha256), on the approval page. The bytes the
// router staged are read back and hashed here; the thumbnail shows only when they are the signed file
// (docs/DECISIONS.md 97). Whatever the router answers, the name, size and hash shown come from the signed config.
import SwiftUI

struct SignedAttachmentRow: View {
  let session: String?
  let ref: Checks.Attachment
  @State private var state: Checked = .reading

  enum Checked: Equatable { case reading, matches(UIImage?), differs, unavailable(String) }

  var body: some View {
    HStack(spacing: 12) {
      Group {
        if case .matches(let t?) = state { Image(uiImage: t).resizable().scaledToFill() }
        else { Image(systemName: state == .differs ? "exclamationmark.triangle.fill" : "photo").foregroundStyle(state == .differs ? .orange : .secondary) }
      }
      .frame(width: 56, height: 56)
      .clipShape(.rect(cornerRadius: 6))
      .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 2) {
        Text(ref.name).lineLimit(1).truncationMode(.middle)
        Text("\(Int64(ref.size).formatted(.byteCount(style: .file))) · sha256 \(ref.sha256.prefix(12))…").font(.footnote.monospaced()).foregroundStyle(.secondary)
        Text(words).font(.footnote).foregroundStyle(state == .differs ? .orange : .secondary)
      }
    }
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("signed-attachment-\(ref.name)")
    .task(id: ref.sha256) { await check() }
  }

  private var words: String {
    switch state {
    case .reading: "Checking the router's copy…"
    case .matches: "The router's copy is this file (its hash matches)."
    case .differs: "The router's copy doesn't match what you sign: the machine will refuse it."
    case .unavailable(let why): "Not shown (\(why)); the machine takes it only if it matches."
    }
  }

  private func check() async {
    guard let session else { state = .unavailable("no session"); return }
    do {
      let data = try await RouterClient.shared.attachment(session: session, name: ref.name)
      let sum = try await offMain { ImagePrep.sha256(data) }
      state = sum == ref.sha256 && data.count == ref.size ? .matches(ImagePrep.thumbnail(data)) : .differs
    } catch {
      state = .unavailable(errText(error))
    }
  }
}
