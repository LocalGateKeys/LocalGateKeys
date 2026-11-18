import Foundation

/// iPad wording for the texts that name the device ("this iPhone"): each such text has an `ipad.*` catalog entry
/// (translations derived from the iPhone ones) chosen when `isPad` is true. The Mac and the extensions never use them.
public enum DeviceText {
    /// True when the iPhone app runs on an iPad. Read from the model identifier ("iPad16,6"; the simulator passes
    /// its model in `SIMULATOR_MODEL_IDENTIFIER`), not `UIDevice`, so nonisolated copy (sync and share texts) can
    /// use it off the main actor.
    public static let isPad: Bool = {
        #if os(iOS)
        #if targetEnvironment(simulator)
        let model = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? ""
        #else
        var info = utsname()
        uname(&info)
        let model = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        #endif
        return model.hasPrefix("iPad")
        #else
        return false
        #endif
    }()

    /// The generic device name ("iPhone" or "iPad") where the copy interpolates it or another device shows it.
    public static var model: String { isPad ? "iPad" : "iPhone" }
}
