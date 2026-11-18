import SwiftUI
import AppShared

/// The iPhone's pairing sheet in Wi-Fi host mode: the Mac's `QRSheet` (same strings and order) in a phone layout.
/// The QR code with this phone's address and the offer code, Copy code text and the countdown; when a device asks,
/// its name, the 6-digit code and key fingerprint with Accept / Decline (Decline by itself after 60 s); then Undo /
/// Keep. Swiping it away closes the code (a device just added is kept).
struct PhoneHostQRSheet: View {
    /// The verification code follows Dynamic Type (review 2026-11-15, UX 3).
    @ScaledMetric(relativeTo: .largeTitle) var codeSize: CGFloat = 40
    let host: PhoneWiFiHost

    private var pairing: HostPairingModel? { host.host?.pairing }
    private var stage: HostPairingModel.Stage { pairing?.stage ?? .idle }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    switch stage {
                    case .confirm, .adding: confirmStep
                    case .paired: pairedStep
                    default: codeStep
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .lgkAuroraBackground()
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if ![.confirm, .adding, .paired].contains(stage) {
                    ToolbarItem(placement: .cancellationAction) { Button("Close") { host.closeQR() } }
                }
            }
        }
        // A waiting request is answered with Accept or Decline, a new device with Undo or Keep.
        .interactiveDismissDisabled([.confirm, .adding, .paired].contains(stage))
    }

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Scan this code with LocalGateKeys on the other device").font(.title3.weight(.semibold))
                .foregroundStyle(Palette.text).fixedSize(horizontal: false, vertical: true)
            if let text = pairing?.qrText, let image = ShareQR.image(text, correction: "M", side: 260) {
                Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 260)
                    .padding(14)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
                    .accessibilityLabel("Pairing QR code")
                    .frame(maxWidth: .infinity)
            } else {
                RoundedRectangle(cornerRadius: 12).fill(Palette.groupSurface).frame(height: 260)
                    .overlay(Text(pairing?.message ?? HostPairingModel.closedText).font(.footnote)
                        .foregroundStyle(Palette.secondaryText).padding())
            }
            if let endpoint = pairing?.endpoint {
                Text(DeviceText.isPad ? String(localized: "ipad.sync.thisDeviceTitle", defaultValue: "This iPad") : String(localized: "This iPhone")).font(.footnote).foregroundStyle(Palette.secondaryText)
                Text(SyncWording.hostPort(endpoint)).font(.system(.body, design: .monospaced).weight(.semibold))
                    .foregroundStyle(Palette.text)
            }
            if let code = pairing?.offerCode {
                Text("Code: \(code)").font(.system(.body, design: .monospaced)).foregroundStyle(Palette.text)
            }
            Text(PhoneWiFiHost.pairHint).font(.footnote).foregroundStyle(Palette.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
            Text("On another PC, use Join with a code and paste the code text instead.")
                .font(.footnote).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
            Text(pairing?.countdown ?? "").font(.footnote).foregroundStyle(Palette.secondaryText)
            if let m = pairing?.message {
                Text(m).font(.footnote).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
            }
            Button("Copy code text") { host.copyCodeText() }.buttonStyle(.bordered)
        }
    }

    private var confirmStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            let r = pairing?.request
            Text(r.map { String(localized: "Add \($0.name)?") } ?? String(localized: "Add this device?"))
                .font(.title3.weight(.semibold)).foregroundStyle(Palette.text)
            if let r {
                Text(r.message).font(.subheadline).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
            }
            Text(verbatim: r?.code ?? "").font(.system(size: codeSize, weight: .semibold, design: .monospaced))
                .foregroundStyle(Palette.text)
                .accessibilityLabel("Verification code")
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            Text(verbatim: "\(HostPairingModel.acceptHint) \(HostPairingModel.declineHint)")
                .font(.footnote).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
            if let f = r?.fingerprint, !f.isEmpty {
                Text("Key fingerprint: \(f)").font(.system(.footnote, design: .monospaced)).foregroundStyle(Palette.secondaryText)
            }
            if stage == .confirm, let s = pairing?.secondsLeft {
                Text(HostPairingModel.declinesText(s)).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            HStack {
                Button("Decline") { host.decide(false) }.buttonStyle(.bordered).disabled(stage == .adding)
                Spacer()
                Button(stage == .adding ? String(localized: "Adding…") : String(localized: "Accept")) { host.decide(true) }
                    .buttonStyle(.borderedProminent).disabled(stage == .adding)
            }
        }
    }

    private var pairedStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            let p = pairing?.paired
            Text("Paired: \(p?.name ?? "")").font(.title3.weight(.semibold)).foregroundStyle(Palette.text)
            if let p {
                Text(p.message).font(.subheadline).foregroundStyle(Palette.secondaryText).fixedSize(horizontal: false, vertical: true)
            }
            if let m = pairing?.message {
                Text(m).font(.footnote).foregroundStyle(Palette.danger).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Undo") { host.undoPairing() }.buttonStyle(.bordered)
                Spacer()
                Button("Keep") { host.keepPairing() }.buttonStyle(.borderedProminent)
            }
        }
    }
}
