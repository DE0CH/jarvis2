// The React Native UI kit's look (src/ui/kit.tsx: Radix Themes, radius "large", accent blue, gray slate)
// rebuilt in SwiftUI for the shell's secure pages, so moving between the two is seamless.
import SwiftUI

enum K {
  static let radius: [CGFloat] = [0, 4.5, 6, 9, 12, 18, 24]
  static let fontSize: [CGFloat] = [0, 12, 14, 16, 18, 20, 24]
}

/// a section label (Lbl): size 1, bold, gray, upper case
struct Lbl: View {
  let text: String
  var body: some View {
    Text(text.uppercased()).font(.system(size: K.fontSize[1], weight: .bold)).foregroundStyle(Radix.gray.s[11])
      .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 16).padding(.bottom, 8)
  }
}

struct Muted: View {
  let text: String
  var body: some View { Text(text).font(.system(size: K.fontSize[2])).foregroundStyle(Radix.gray.s[11]).frame(maxWidth: .infinity, alignment: .leading) }
}

enum BtnVariant { case solid, soft }
enum BtnColor { case blue, gray, red }

/// Button (size 2): solid = step 9 fill, soft = alpha 3 fill with alpha 11 text
struct KitButton: View {
  let title: String
  var variant: BtnVariant = .solid
  var color: BtnColor = .blue
  var disabled = false
  var busy = false
  var id: String? = nil
  let action: () -> Void
  private func scale() -> (s: [Color], a: [Color]) {
    switch color { case .blue: return (Radix.blue.s, Radix.blue.a); case .gray: return (Radix.gray.s, Radix.gray.a); case .red: return (Radix.red.s, Radix.red.a) }
  }
  var body: some View {
    let c = scale()
    Button(action: action) {
      HStack(spacing: 8) {
        if busy { ProgressView().controlSize(.small).tint(variant == .solid ? .white : c.a[11]) }
        Text(title).font(.system(size: K.fontSize[2], weight: .medium)).lineLimit(1)
      }
      .padding(.horizontal, 12).frame(height: 32)
      .foregroundStyle(disabled ? Radix.gray.a[8] : (variant == .solid ? Color.white : c.a[11]))
      .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(disabled ? Radix.gray.a[3] : (variant == .solid ? c.s[9] : c.a[3])))
    }
    .buttonStyle(.plain).disabled(disabled || busy)
    .accessibilityIdentifier(id ?? title)
  }
}

/// RadioCards / CheckboxCards: a card per option, the chosen radio gets a 2 pt accent border, a checkbox
/// a filled accent box on the right
struct ChoiceCard<Content: View>: View {
  let on: Bool
  var check = false
  var id: String
  let action: () -> Void
  @ViewBuilder let content: () -> Content
  var body: some View {
    Button(action: action) {
      HStack(spacing: 8) {
        VStack(alignment: .leading, spacing: 2) { content() }.frame(maxWidth: .infinity, alignment: .leading)
        if check {
          ZStack {
            RoundedRectangle(cornerRadius: 4).fill(on ? Radix.blue.s[9] : Radix.surface)
            RoundedRectangle(cornerRadius: 4).strokeBorder(on ? Color.clear : Radix.gray.a[7], lineWidth: 1)
            if on { Text("✓").font(.system(size: 11, weight: .bold)).foregroundStyle(.white) }
          }.frame(width: 16, height: 16)
        }
      }
      .padding(.vertical, !check && on ? 9 : 10).padding(.horizontal, !check && on ? 11 : 12)
      .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.surface))
      .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous)
        .strokeBorder(!check && on ? Radix.blue.s[9] : Radix.gray.a[6], lineWidth: !check && on ? 2 : 1))
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .accessibilityIdentifier(id)
    .accessibilityAddTraits(on ? .isSelected : [])
  }
}

struct ChoiceText: View {
  let title: String
  var sub: String? = nil
  var body: some View {
    Text(title).font(.system(size: K.fontSize[2], weight: .medium)).foregroundStyle(Radix.gray.s[12])
    if let sub { Text(sub).font(.system(size: K.fontSize[1])).foregroundStyle(Radix.gray.s[11]) }
  }
}

/// Badge (size 1, soft)
struct Badge: View {
  let text: String
  var color: BtnColor = .gray
  var body: some View {
    let c: (s: [Color], a: [Color]) = color == .red ? (Radix.red.s, Radix.red.a) : color == .blue ? (Radix.blue.s, Radix.blue.a) : (Radix.gray.s, Radix.gray.a)
    Text(text).font(.system(size: 11, weight: .medium)).foregroundStyle(c.a[11])
      .padding(.horizontal, 6).padding(.vertical, 2)
      .background(RoundedRectangle(cornerRadius: K.radius[1]).fill(c.a[3]))
  }
}

/// Callout (soft)
struct Callout: View {
  let text: String
  var color: BtnColor = .gray
  var amber = false
  var body: some View {
    let s = amber ? Radix.amber.a : (color == .red ? Radix.red.a : color == .blue ? Radix.blue.a : Radix.gray.a)
    Text(text).font(.system(size: K.fontSize[2])).foregroundStyle(s[11])
      .frame(maxWidth: .infinity, alignment: .leading).padding(12)
      .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(s[3]))
  }
}
