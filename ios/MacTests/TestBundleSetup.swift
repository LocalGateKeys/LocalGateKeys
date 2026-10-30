import Foundation
import ObjectiveC

/// The Mac tests are not hosted in the app (unsigned CI cannot), so `Bundle.main` is the xctest tool and
/// `String(localized:)` falls back to the catalog keys ("1 free slots"). This principal class
/// (NSPrincipalClass in project.yml) points `Bundle.main` at the test bundle, which carries the app's
/// compiled Localizable catalog, before any test runs.
@objc(LGKMacTestBundleSetup)
final class TestBundleSetup: NSObject {
    /// Resolved before the swap (Bundle(for:) itself goes through Bundle.main).
    nonisolated(unsafe) private static var bundle: Bundle?

    override init() {
        super.init()
        Self.bundle = Bundle(for: TestBundleSetup.self)
        guard let original = class_getClassMethod(Bundle.self, #selector(getter: Bundle.main)),
              let replacement = class_getClassMethod(TestBundleSetup.self, #selector(TestBundleSetup.testBundle))
        else { return }
        method_exchangeImplementations(original, replacement)
    }

    @objc dynamic class func testBundle() -> Bundle { TestBundleSetup.bundle! }
}
