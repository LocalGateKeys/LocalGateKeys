import CoreGraphics
import Foundation
import ImageIO
import Vision
import CoreImage

/// Reads 2FA QR codes from a still image (a photo on the iPhone, an image file, paste or drop on the Mac) with
/// Vision. Only `otpauth://` and `otpauth-migration://` payloads are returned; anything else is ignored. The
/// image stays in memory, is bounded before it is decoded, and no payload is ever logged or put in an error.
public enum TwoFactorQRDecoder {
    public static let maxImageBytes = 50 * 1024 * 1024
    public static let maxPixels = 100_000_000
    static let prefixes = ["otpauth://", "otpauth-migration://"]

    public enum Failure: Error, Equatable, Sendable {
        case tooLarge, unreadable, noQRCode, notTwoFactor

        public var message: String {
            switch self {
            case .tooLarge: String(localized: "That image is too large. Use a screenshot or a smaller photo of the QR code.")
            case .unreadable: String(localized: "That image could not be read.")
            case .noQRCode: String(localized: "No QR code was found in that image. Make sure the whole code is visible and sharp.")
            case .notTwoFactor: String(localized: "That QR code isn't a 2FA setup code.")
            }
        }
    }

    /// Refuses an empty image, or one above 100 megapixels or about 50 MB.
    static func check(width: Int, height: Int, byteCount: Int) throws {
        guard width > 0, height > 0 else { throw Failure.unreadable }
        guard byteCount <= maxImageBytes, width.multipliedReportingOverflow(by: height).partialValue <= maxPixels,
              width <= maxPixels, height <= maxPixels else { throw Failure.tooLarge }
    }

    /// The 2FA payloads in encoded image bytes (PNG, JPEG, HEIC, TIFF…). The size is checked from the header
    /// before any pixels are decoded.
    public static func payloads(inImageData data: Data) throws -> [String] {
        guard data.count <= maxImageBytes else { throw Failure.tooLarge }
        let options = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(data as CFData, options), CGImageSourceGetCount(source) > 0,
              let props = CGImageSourceCopyPropertiesAtIndex(source, 0, options) as? [CFString: Any],
              let width = props[kCGImagePropertyPixelWidth] as? Int,
              let height = props[kCGImagePropertyPixelHeight] as? Int else { throw Failure.unreadable }
        try check(width: width, height: height, byteCount: data.count)
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, options) else { throw Failure.unreadable }
        return try payloads(in: image)
    }

    /// The 2FA payloads in an image, top to bottom, without repeats. Throws `noQRCode` when the image holds no
    /// QR code and `notTwoFactor` when none of its codes is a 2FA code. Runs synchronously: call it off the
    /// main actor.
    public static func payloads(in image: CGImage) throws -> [String] {
        try check(width: image.width, height: image.height, byteCount: 0)
        guard image.bytesPerRow.multipliedReportingOverflow(by: image.height).partialValue <= 4 * maxPixels else {
            throw Failure.tooLarge
        }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        let found: [String]
        do {
            try VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
            found = (request.results ?? [])
                .sorted { ($0.boundingBox.maxY, -$0.boundingBox.minX) > ($1.boundingBox.maxY, -$1.boundingBox.minX) }
                .compactMap(\.payloadStringValue)
        } catch {
            #if targetEnvironment(simulator)
            // Vision's barcode request cannot run in the iOS Simulator: Core Image's QR detector reads the
            // codes there (tests). On a device a Vision failure is reported as unreadable.
            found = try coreImagePayloads(image)
            #else
            throw Failure.unreadable
            #endif
        }
        guard !found.isEmpty else { throw Failure.noQRCode }
        let codes = twoFactorTexts(found)
        guard !codes.isEmpty else { throw Failure.notTwoFactor }
        return codes
    }

    #if targetEnvironment(simulator)
    private static func coreImagePayloads(_ image: CGImage) throws -> [String] {
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                        options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else { throw Failure.unreadable }
        return detector.features(in: CIImage(cgImage: image)).compactMap { $0 as? CIQRCodeFeature }
            .sorted { ($0.bounds.maxY, -$0.bounds.minX) > ($1.bounds.maxY, -$1.bounds.minX) }
            .compactMap(\.messageString)
    }
    #endif

    /// Only 2FA codes, in order, trimmed and without duplicates (`qr_import.otp_texts`).
    public static func twoFactorTexts(_ texts: [String]) -> [String] {
        var out: [String] = []
        for raw in texts {
            let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            let lower = text.lowercased()
            if prefixes.contains(where: { lower.hasPrefix($0) }), !out.contains(text) { out.append(text) }
        }
        return out
    }
}
