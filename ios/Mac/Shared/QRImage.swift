import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins

/// A QR code as an image (CoreImage), shared by the pairing code, the shared-item code and the Wi-Fi QR.
enum QRImage {
    /// Medium error correction, a 4-module quiet zone, each module a whole number of pixels.
    static func make(_ text: String, side: CGFloat = 260) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let modules = output.extent.width + 8   // a 4-module quiet zone on each side
        let scale = max(1, (side * 2 / modules).rounded(.down))   // drawn at 2x for Retina
        let padded = output.transformed(by: CGAffineTransform(translationX: 4, y: 4))
            .composited(over: CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: modules, height: modules)))
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cg = CIContext().createCGImage(padded, from: padded.extent) else { return nil }
        return NSImage(cgImage: cg, size: NSSize(width: padded.extent.width / 2, height: padded.extent.height / 2))
    }
}
