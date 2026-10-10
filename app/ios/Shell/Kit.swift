// The React Native UI kit (src/ui/kit.tsx + theme/tokens.ts — Jarvis 1's Radix Themes port: radius "large",
// accent blue, gray slate, solid panels) rebuilt in SwiftUI for the shell's secure pages, value for value, so
// the shell's pages and the app look the same: the same type ramp (size, line height, letter spacing, weight),
// the same buttons, cards, fields, callouts and badges, the same colours in light and dark (RadixColors.swift).
import SwiftUI
import UIKit

enum K {
  // theme/tokens.ts (scaling 1, radius factor 1.5)
  static let space: [CGFloat] = [0, 4, 8, 12, 16, 24, 32, 40, 48, 64]
  static let radius: [CGFloat] = [0, 4.5, 6, 9, 12, 18, 24]
  static let fontSize: [CGFloat] = [0, 12, 14, 16, 18, 20, 24, 28, 35, 60]
  static let lineHeight: [CGFloat] = [0, 16, 20, 24, 26, 28, 30, 36, 40, 60]
  static let headingLineHeight: [CGFloat] = [0, 16, 18, 22, 24, 26, 30, 36, 40, 60]
  /// em
  static let letterSpacing: [CGFloat] = [0, 0.0025, 0, 0, -0.0025, -0.005, -0.00625, -0.0075, -0.01, -0.025]
  /// the page column (src/ui/page.tsx): 720 wide, 16 side padding, 20 in the top bar
  static let pageMax: CGFloat = 720
}

enum KitColor {
  case blue, gray, red, green, amber
  var s: [Color] {
    switch self { case .blue: return Radix.blue.s; case .gray: return Radix.gray.s; case .red: return Radix.red.s; case .green: return Radix.green.s; case .amber: return Radix.amber.s }
  }
  var a: [Color] {
    switch self { case .blue: return Radix.blue.a; case .gray: return Radix.gray.a; case .red: return Radix.red.a; case .green: return Radix.green.a; case .amber: return Radix.amber.a }
  }
  /// text on a solid (step 9) fill: white, except amber, where Radix uses dark text
  var onSolid: Color { self == .amber ? Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: 17 / 255, green: 17 / 255, blue: 19 / 255, alpha: 1) : UIColor(red: 0x21 / 255, green: 0x20 / 255, blue: 0x1c / 255, alpha: 1) }) : .white }
}
/// the older names the pages use
typealias BtnColor = KitColor
enum BtnVariant { case solid, soft, surface, outline, ghost }
enum KitWeight {
  case regular, medium, bold
  var font: Font.Weight { switch self { case .regular: return .regular; case .medium: return .medium; case .bold: return .bold } }
  var ui: UIFont.Weight { switch self { case .regular: return .regular; case .medium: return .medium; case .bold: return .bold } }
}

/// React Native's text box: the font at `size`, the line box `lineHeight` tall with the glyphs centred in it
/// (half the extra leading above the first line and below the last, the rest between lines), letter spacing
/// in points.
struct KitFont: ViewModifier {
  let size: CGFloat, lineHeight: CGFloat, weight: KitWeight, tracking: CGFloat, mono: Bool
  func body(content: Content) -> some View {
    let ui = mono ? UIFont.monospacedSystemFont(ofSize: size, weight: weight.ui) : UIFont.systemFont(ofSize: size, weight: weight.ui)
    let extra = max(0, lineHeight - ui.lineHeight)
    return content
      .font(mono ? .system(size: size, weight: weight.font, design: .monospaced) : .system(size: size, weight: weight.font))
      .tracking(tracking).lineSpacing(extra).padding(.vertical, extra / 2)
  }
}
extension View {
  /// kit.tsx Text at `size` (1–6): Radix's size, line height and letter spacing
  func kitText(_ size: Int, weight: KitWeight = .regular, mono: Bool = false, upper: Bool = false) -> some View {
    let fs = mono ? K.fontSize[size] * 0.92 : K.fontSize[size]
    let tracking = upper ? 0.04 * fs : K.letterSpacing[size] * K.fontSize[size]
    return modifier(KitFont(size: fs, lineHeight: K.lineHeight[size], weight: weight, tracking: tracking, mono: mono))
  }
  /// kit.tsx Heading (bold, the tighter heading line height)
  func kitHeading(_ size: Int) -> some View {
    modifier(KitFont(size: K.fontSize[size], lineHeight: K.headingLineHeight[size], weight: .bold, tracking: K.letterSpacing[size] * K.fontSize[size], mono: false))
  }
}

/// kit.tsx P / Text: size 2 by default, the theme's text colour (or a scale's step 11)
struct P: View {
  let text: String
  var size = 2
  var weight: KitWeight = .regular
  var color: KitColor? = nil
  var mono = false
  var body: some View {
    Text(text).kitText(size, weight: weight, mono: mono).foregroundStyle(color.map { $0.a[11] } ?? Radix.gray.s[12])
      .frame(maxWidth: .infinity, alignment: .leading)
  }
}

/// kit.tsx Heading
struct Heading: View {
  let text: String
  var size = 3
  var body: some View { Text(text).kitHeading(size).foregroundStyle(Radix.gray.s[12]) }
}

/// a section label (Lbl): size 1, bold, gray, upper case; 16 above, 8 below
struct Lbl: View {
  let text: String
  var mt: CGFloat = 16
  var body: some View {
    Text(text.uppercased()).kitText(1, weight: .bold, upper: true).foregroundStyle(Radix.gray.a[11])
      .frame(maxWidth: .infinity, alignment: .leading).padding(.top, mt).padding(.bottom, 8)
  }
}

/// kit.tsx Muted: size 2, gray
struct Muted: View {
  let text: String
  var body: some View { Text(text).kitText(2).foregroundStyle(Radix.gray.a[11]).frame(maxWidth: .infinity, alignment: .leading) }
}

/// kit.tsx Button: sizes 1–3 (heights 24/32/40, radii 4.5/6/9), variants solid/soft/surface/outline/ghost,
/// a darker fill while pressed, weight 500 (ghost 400)
struct KitButton: View {
  let title: String
  var variant: BtnVariant = .solid
  var color: KitColor = .blue
  var size = 2
  var disabled = false
  var busy = false
  var id: String? = nil
  let action: () -> Void
  var body: some View {
    Button(action: action) { Text(title) }
      .buttonStyle(KitButtonStyle(variant: variant, color: color, size: size, off: disabled || busy, busy: busy))
      .disabled(disabled || busy)
      .accessibilityIdentifier(id ?? title)
  }
}

struct KitButtonStyle: ButtonStyle {
  let variant: BtnVariant, color: KitColor, size: Int, off: Bool, busy: Bool
  private static let dims: [(h: CGFloat, px: CGFloat, fs: CGFloat, lh: CGFloat, r: CGFloat, gap: CGFloat)] =
    [(0, 0, 0, 0, 0, 0), (24, 8, 12, 16, 4.5, 4), (32, 12, 14, 20, 6, 8), (40, 16, 16, 24, 9, 12)]
  private func look(_ pressed: Bool) -> (bg: Color, fg: Color, border: Color?) {
    let c = color
    if off { return (variant == .ghost ? .clear : Radix.gray.a[3], Radix.gray.a[8], variant == .surface || variant == .outline ? Radix.gray.a[6] : nil) }
    switch variant {
    case .solid: return (pressed ? c.s[10] : c.s[9], c.onSolid, nil)
    case .soft: return (pressed ? c.a[5] : c.a[3], c.a[11], nil)
    case .surface: return (pressed ? c.a[4] : c.a[2], c.a[11], c.a[7])
    case .outline: return (pressed ? c.a[3] : .clear, c.a[11], c.a[8])
    case .ghost: return (pressed ? c.a[4] : .clear, c.a[11], nil)
    }
  }
  func makeBody(configuration: Configuration) -> some View {
    let d = KitButtonStyle.dims[max(1, min(3, size))], l = look(configuration.isPressed), ghost = variant == .ghost
    return HStack(spacing: d.gap) {
      if busy { ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 12, height: 12).tint(l.fg) }
      configuration.label
        .modifier(KitFont(size: d.fs, lineHeight: d.lh, weight: ghost ? .regular : .medium, tracking: 0, mono: false))
        .lineLimit(1).foregroundStyle(l.fg)
    }
    .padding(.horizontal, ghost ? d.px - 4 : d.px).frame(height: ghost ? d.h - 4 : d.h)
    .background(RoundedRectangle(cornerRadius: d.r, style: .continuous).fill(l.bg))
    .overlay { if let b = l.border { RoundedRectangle(cornerRadius: d.r, style: .continuous).strokeBorder(b, lineWidth: 1) } }
    .contentShape(Rectangle())
  }
}

/// kit.tsx Card: a solid panel, radius 12, a hairline border, padding 16 (size 2) or 12 (size 1)
struct KitCard<Content: View>: View {
  var size = 2
  var surface = false
  var id: String? = nil
  @ViewBuilder let content: () -> Content
  var body: some View {
    VStack(alignment: .leading, spacing: 0) { content() }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(size == 1 ? 12 : 16)
      .background(RoundedRectangle(cornerRadius: K.radius[4], style: .continuous).fill(surface ? Radix.gray.a[2] : Radix.panel))
      .overlay(RoundedRectangle(cornerRadius: K.radius[4], style: .continuous).strokeBorder(Radix.gray.a[6], lineWidth: 1))
      .modifier(OptionalID(id: id))
  }
}

/// an accessibility identifier only when there is one
struct OptionalID: ViewModifier {
  let id: String?
  func body(content: Content) -> some View {
    if let id { content.accessibilityIdentifier(id) } else { content }
  }
}

/// RadioCards / CheckboxCards: a card per option on the field surface; the chosen radio gets a 2 pt accent
/// border, a checkbox a filled accent box on the right
struct ChoiceCard<Content: View>: View {
  let on: Bool
  var check = false
  var id: String
  let action: () -> Void
  @ViewBuilder let content: () -> Content
  var body: some View {
    Button(action: action) {
      HStack(spacing: 8) {
        VStack(alignment: .leading, spacing: 0) { content() }.frame(maxWidth: .infinity, alignment: .leading)
        if check {
          ZStack {
            RoundedRectangle(cornerRadius: 4).fill(on ? Radix.blue.s[9] : Radix.surface)
            RoundedRectangle(cornerRadius: 4).strokeBorder(on ? Color.clear : Radix.gray.a[7], lineWidth: 1)
            if on { Text("✓").font(.system(size: 11, weight: .bold)).foregroundStyle(.white) }
          }.frame(width: 16, height: 16)
        }
      }
      .padding(.vertical, !check && on ? 9 : 10).padding(.horizontal, !check && on ? 11 : 12)
      .contentShape(Rectangle())
    }
    .buttonStyle(ChoiceCardStyle(on: on, check: check))
    .accessibilityIdentifier(id)
    .accessibilityAddTraits(on ? .isSelected : [])
  }
}
private struct ChoiceCardStyle: ButtonStyle {
  let on: Bool, check: Bool
  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(configuration.isPressed ? Radix.gray.a[2] : Radix.surface))
      .overlay(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous)
        .strokeBorder(!check && on ? Radix.blue.s[9] : Radix.gray.a[6], lineWidth: !check && on ? 2 : 1))
  }
}

/// kit.tsx ChoiceText: the title (size 2, medium), the line under it (size 1, gray)
struct ChoiceText: View {
  let title: String
  var sub: String? = nil
  var body: some View {
    Text(title).kitText(2, weight: .medium).foregroundStyle(Radix.gray.s[12])
    if let sub { Text(sub).kitText(1).foregroundStyle(Radix.gray.a[11]) }
  }
}

/// kit.tsx Badge: 20 tall, radius 4.5, soft fill, size 1 medium text
struct Badge: View {
  let text: String
  var color: KitColor = .gray
  var upper = false
  var body: some View {
    Text(upper ? text.uppercased() : text)
      .modifier(KitFont(size: 12, lineHeight: 16, weight: .medium, tracking: upper ? 0.36 : 0.03, mono: false))
      .lineLimit(1).foregroundStyle(color.a[11])
      .padding(.horizontal, 6).frame(height: 20)
      .background(RoundedRectangle(cornerRadius: K.radius[1], style: .continuous).fill(color.a[3]))
      .fixedSize()
  }
}

/// kit.tsx Callout (soft): radius 9, padding 12, size 2 text in the scale's step 11
struct Callout: View {
  let text: String
  var color: KitColor = .gray
  /// the older spelling of color: .amber
  var amber = false
  var body: some View {
    let c = amber ? KitColor.amber : color
    Text(text).kitText(2).foregroundStyle(c.a[11])
      .frame(maxWidth: .infinity, alignment: .leading).padding(12)
      .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(c.a[3]))
  }
}

/// kit.tsx TextField: 32 tall (size 2) or 40 (size 3), the field surface, a gray border that turns the focus
/// colour while editing, 16 pt text
struct KitTextField: View {
  let placeholder: String
  @Binding var text: String
  var size = 2
  var mono = false
  var secure = false
  var id: String
  @FocusState private var focused: Bool
  var body: some View {
    Group {
      if secure { SecureField("", text: $text, prompt: prompt) } else { TextField("", text: $text, prompt: prompt) }
    }
    .font(mono ? .system(size: 16, design: .monospaced) : .system(size: 16))
    .foregroundStyle(Radix.gray.s[12]).tint(Radix.blue.s[9])
    .textInputAutocapitalization(.never).autocorrectionDisabled()
    .focused($focused)
    .padding(.horizontal, size == 3 ? 12 : 8).frame(height: size == 3 ? 40 : 32)
    .background(RoundedRectangle(cornerRadius: K.radius[size == 3 ? 3 : 2], style: .continuous).fill(Radix.surface))
    .overlay(RoundedRectangle(cornerRadius: K.radius[size == 3 ? 3 : 2], style: .continuous).strokeBorder(focused ? Radix.blue.s[8] : Radix.gray.a[7], lineWidth: 1))
    .accessibilityIdentifier(id)
  }
  private var prompt: Text { Text(placeholder).foregroundStyle(Radix.gray.a[10]) }
}

/// kit.tsx TextArea: `rows` lines of 22 (+14), radius 6, 16 pt text
struct KitTextArea: View {
  let placeholder: String
  @Binding var text: String
  var rows = 3
  var mono = false
  var id: String
  @FocusState private var focused: Bool
  var body: some View {
    TextField("", text: $text, prompt: Text(placeholder).foregroundStyle(Radix.gray.a[10]), axis: .vertical)
      .modifier(KitFont(size: 16, lineHeight: 22, weight: .regular, tracking: 0, mono: mono))
      .foregroundStyle(Radix.gray.s[12]).tint(Radix.blue.s[9])
      .textInputAutocapitalization(.never).autocorrectionDisabled()
      .focused($focused)
      .padding(.horizontal, 8).padding(.vertical, 6)
      .frame(minHeight: CGFloat(rows) * 22 + 14, alignment: .topLeading)
      .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(Radix.surface))
      .overlay(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).strokeBorder(focused ? Radix.blue.s[8] : Radix.gray.a[7], lineWidth: 1))
      .accessibilityIdentifier(id)
  }
}

/// kit.tsx Segmented: 24 tall, gray track, the chosen item a panel with a hairline border, size 1 text
struct Segmented: View {
  @Environment(\.colorScheme) private var scheme
  let items: [(value: String, title: String)]
  @Binding var value: String
  var id: String
  var body: some View {
    HStack(spacing: 0) {
      ForEach(items, id: \.value) { it in
        let on = it.value == value
        Button { value = it.value } label: {
          Text(it.title).modifier(KitFont(size: 12, lineHeight: 16, weight: on ? .medium : .regular, tracking: 0, mono: false))
            .foregroundStyle(on ? Radix.gray.s[12] : Radix.gray.a[11])
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(on ? (scheme == .dark ? Radix.gray.a[4] : Radix.panel) : .clear))
            .overlay { if on { RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).strokeBorder(Radix.gray.a[5], lineWidth: 1) } }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).accessibilityIdentifier("\(id)-\(it.value)").accessibilityAddTraits(on ? .isSelected : [])
      }
    }
    .frame(height: 24).frame(maxWidth: 420)
    .background(RoundedRectangle(cornerRadius: K.radius[2], style: .continuous).fill(Radix.gray.a[3]))
  }
}

/// a value shown for reading or copying (a key, a code): size 1 monospaced on a soft gray box
struct CodeBox: View {
  let text: String
  var id: String
  var body: some View {
    Text(text).kitText(1, mono: true).foregroundStyle(Radix.gray.s[12]).textSelection(.enabled)
      .padding(12).frame(maxWidth: .infinity, alignment: .leading)
      .background(RoundedRectangle(cornerRadius: K.radius[3], style: .continuous).fill(Radix.gray.a[3]))
      .accessibilityIdentifier(id).accessibilityLabel(text)
  }
}
