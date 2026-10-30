import XCTest
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import UniformTypeIdentifiers
import LGKCore
#if os(macOS)
@testable import AppSharedMac
#else
@testable import AppShared
#endif

/// The shared Vision QR reader behind "Choose from Photos" (iPhone) and the Mac's image scan. Compiled into
/// both AppSharedTests and LocalGateKeysMacTests; the images are generated with CIQRCodeGenerator.
final class TwoFactorQRDecoderTests: XCTestCase {
    static let key = "otpauth://totp/GitHub:octo%40example.com?secret=GAYTEMZUGU3DOOBZ&issuer=GitHub"

    static func qr(_ text: String, scale: CGFloat = 8) -> CIImage {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        return f.outputImage!.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
    }

    /// The codes side by side on a white page with a quiet zone, as one CGImage.
    static func image(_ codes: [CIImage], blank: CGSize = CGSize(width: 300, height: 300)) -> CGImage {
        let margin: CGFloat = 60
        let width = codes.isEmpty ? blank.width : codes.reduce(margin) { $0 + $1.extent.width + margin }
        let height = codes.isEmpty ? blank.height : (codes.map(\.extent.height).max() ?? 0) + 2 * margin
        var canvas = CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: width, height: height))
        var x = margin
        for c in codes {
            canvas = c.transformed(by: CGAffineTransform(translationX: x, y: margin)).composited(over: canvas)
            x += c.extent.width + margin
        }
        return CIContext().createCGImage(canvas, from: canvas.extent)!
    }

    static func png(_ image: CGImage) -> Data {
        let data = NSMutableData()
        let dest = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, image, nil)
        CGImageDestinationFinalize(dest)
        return data as Data
    }

    func testSingleOtpauthCode() throws {
        XCTAssertEqual(try TwoFactorQRDecoder.payloads(in: Self.image([Self.qr(Self.key)])), [Self.key])
    }

    func testMigrationExport() throws {
        let alpha = OTPMigration.Entry(secret: Array("0123456789".utf8), name: "ann", issuer: "Alpha")
        let beta = OTPMigration.Entry(secret: Array("abcdefghijklmnopqrst".utf8), name: "bob", issuer: "Beta")
        let uri = OTPMigration.encode([alpha, beta])
        let found = try TwoFactorQRDecoder.payloads(in: Self.image([Self.qr(uri, scale: 6)]))
        XCTAssertEqual(found, [uri])
        XCTAssertEqual(try OTPMigration.parse(found[0]).accounts.map(\.issuer), ["Alpha", "Beta"])
    }

    func testNoQRCode() {
        XCTAssertThrowsError(try TwoFactorQRDecoder.payloads(in: Self.image([]))) {
            XCTAssertEqual($0 as? TwoFactorQRDecoder.Failure, .noQRCode)
        }
    }

    func testAQRCodeThatIsNotA2FACodeIsRefused() {
        XCTAssertThrowsError(try TwoFactorQRDecoder.payloads(in: Self.image([Self.qr("https://example.com/wifi")]))) {
            XCTAssertEqual($0 as? TwoFactorQRDecoder.Failure, .notTwoFactor)
        }
    }

    func testTwoCodesInOneImageAreBothRead() throws {
        let other = "otpauth://totp/Beta:bob?secret=MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U&issuer=Beta"
        let found = try TwoFactorQRDecoder.payloads(in: Self.image([Self.qr(Self.key), Self.qr("https://example.com"), Self.qr(other)]))
        XCTAssertEqual(Set(found), [Self.key, other])
        XCTAssertEqual(found.count, 2)
    }

    func testImageDataIsDecoded() throws {
        XCTAssertEqual(try TwoFactorQRDecoder.payloads(inImageData: Self.png(Self.image([Self.qr(Self.key)]))), [Self.key])
    }

    func testNotAnImageIsRefused() {
        XCTAssertThrowsError(try TwoFactorQRDecoder.payloads(inImageData: Data("hello".utf8))) {
            XCTAssertEqual($0 as? TwoFactorQRDecoder.Failure, .unreadable)
        }
    }

    func testSizeBounds() {
        XCTAssertNoThrow(try TwoFactorQRDecoder.check(width: 10_000, height: 10_000, byteCount: 1000))
        XCTAssertThrowsError(try TwoFactorQRDecoder.check(width: 10_001, height: 10_000, byteCount: 1000))
        XCTAssertThrowsError(try TwoFactorQRDecoder.check(width: 100, height: 100, byteCount: 50 * 1024 * 1024 + 1))
        XCTAssertThrowsError(try TwoFactorQRDecoder.check(width: 0, height: 100, byteCount: 10))
    }

    func testMessagesAreFixedText() {
        for f in [TwoFactorQRDecoder.Failure.tooLarge, .unreadable, .noQRCode, .notTwoFactor] {
            XCTAssertFalse(f.message.contains("otpauth://totp/"))
            XCTAssertFalse(f.message.isEmpty)
        }
    }
}
