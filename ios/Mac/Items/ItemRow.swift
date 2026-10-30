import SwiftUI
import AppSharedMac

/// One list row (mockup `.row`): logo, title, username; on the right the health tag (Breached / Weak / Reused)
/// above the website.
struct ItemRow: View {
    let item: VaultItem
    let selected: Bool
    var tag: String?
    @Environment(\.macTheme) private var theme

    var body: some View {
        HStack(spacing: 12) {
            ItemLogo(item: item, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? item.kindLabel : item.title).foregroundStyle(theme.text).lineLimit(1)
                Text(item.listSubtitle).font(.system(size: 13)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
            Spacer(minLength: 8)
            let target = !item.target.isEmpty && item.target != item.listSubtitle ? item.target : nil
            if tag != nil || target != nil {
                VStack(alignment: .trailing, spacing: 2) {
                    if let tag {
                        Text(tag).font(.system(size: 12)).foregroundStyle(theme.danger)
                            .padding(.horizontal, 6)
                            .background(theme.dangerBackground, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                    }
                    if let target { Text(target).font(.system(size: 12)).foregroundStyle(theme.textFaint).lineLimit(1) }
                }
            }
        }
        .font(.system(size: 14))
        .padding(.horizontal, 14).padding(.vertical, 9)
        .background(selected ? theme.selection : .clear)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }
}

/// The item's logo: a downloaded website icon (Settings › Show website icons), else the bundled brand logo
/// (`SiteLogos`), else the initials on a colour picked from the title (mockup `.logo`).
struct ItemLogo: View {
    let item: VaultItem
    var size: CGFloat = 28
    var store: SiteIconStore = .shared

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
        Group {
            if let host = item.iconHost, let image = store.image(for: host) {
                Image(nsImage: image).resizable().interpolation(.high).scaledToFit()
                    .padding(size * 0.12)
                    .background(Color.white, in: shape)
            } else if let logo = item.siteLogo {
                Image(logo.imageName).renderingMode(.template).resizable().scaledToFit()
                    .foregroundStyle(logo.isLight ? Color.black : Color.white)
                    .padding(size * 0.22)
                    .frame(width: size, height: size)
                    .background(logo.color, in: shape)
            } else {
                Text(Self.initials(item.title.isEmpty ? item.kindLabel : item.title))
                    .font(.system(size: size * 0.43, weight: .bold)).foregroundStyle(.white)
                    .frame(width: size, height: size)
                    .background(Self.colour(for: item.title), in: shape)
            }
        }
        .frame(width: size, height: size)
        .clipShape(shape)
        .accessibilityHidden(true)
        .task(id: item.iconHost) { if let host = item.iconHost { store.request(host) } }
    }

    static func initials(_ title: String) -> String {
        let letters = title.filter { $0.isLetter || $0.isNumber }
        return String(letters.prefix(2)).uppercased()
    }

    /// A stable colour per title, from the mockup's badge colours.
    static func colour(for title: String) -> Color {
        let palette: [Color] = [.rgb(91, 75, 214), .rgb(36, 41, 47), .rgb(15, 110, 86), .rgb(43, 111, 224),
                                .rgb(180, 83, 9), .rgb(190, 24, 93)]
        let sum = title.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }
        return palette[abs(sum) % palette.count]
    }
}
