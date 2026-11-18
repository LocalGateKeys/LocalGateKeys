import SwiftUI
import UIKit
import AppShared

/// The Wi-Fi network's QR code, opened only after the password was revealed. The image is made when the sheet
/// appears and dropped when it goes away, so it never outlives the sheet.
struct WifiQRSheet: View {
    let text: String
    @Environment(\.dismiss) private var dismiss
    @State private var image: UIImage?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if let image {
                        Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
                            .frame(maxWidth: 280).padding(12).background(Color.white)
                            .accessibilityHidden(true)
                    }
                    Text("The image contains the Wi-Fi password. Only show it to people you want to connect.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
                    Text("This code does not expire: anyone who scans or photographs it keeps the Wi-Fi password. Change the Wi-Fi password to take it back.")
                        .font(.footnote).foregroundStyle(Palette.secondaryText).multilineTextAlignment(.center)
                }
                .padding(16)
                .frame(maxWidth: .infinity)
            }
            .lgkAuroraBackground()
            .navigationTitle("Show QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .presentationBackground { AuroraBackground() }
        .task { image = ShareQR.image(text, correction: "M", side: 280) }
        .onDisappear { image = nil }
    }
}
