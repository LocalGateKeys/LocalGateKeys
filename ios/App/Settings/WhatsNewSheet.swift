import SwiftUI
import AppShared

/// The "What's new" sheet: after an update (RootTabs) and from Settings › What's new.
struct WhatsNewSheet: View {
    let onClose: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(WhatsNew.items, id: \.title) { item in
                        HStack(alignment: .top, spacing: 14) {
                            Image(systemName: item.symbol)
                                .font(.title3).foregroundStyle(Palette.accentText)
                                .frame(width: 32)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title).font(.headline).foregroundStyle(Palette.text)
                                Text(item.detail).font(.subheadline).foregroundStyle(Palette.secondaryText)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(20)
            }
            .safeAreaInset(edge: .bottom) {
                Button(action: onClose) {
                    Text("Continue").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
                .padding(.horizontal, 20).padding(.bottom, 12)
            }
            .lgkAuroraBackground()
            .navigationTitle(WhatsNew.title)
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
