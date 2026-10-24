import Foundation
import AppShared

/// The generator sheet's state: options (saved as the new defaults on every change), the current value, and
/// the hand-off of that value to whoever opened the sheet.
@MainActor
@Observable
final class GeneratorModel {
    var options: GeneratorOptions {
        didSet {
            guard options != oldValue else { return }
            defaults.save(options)
            regenerate()
        }
    }
    private(set) var value = ""
    private(set) var error: String?
    /// The current value is on the pasteboard (cleared when a new value is generated).
    private(set) var copied = false
    /// Use was tapped: the sheet is closing and the value has been handed over (or is about to be).
    private(set) var used = false

    @ObservationIgnored private let defaults: GeneratorDefaults
    @ObservationIgnored private let generator: PasswordGenerator
    @ObservationIgnored private let clipboard: SecretClipboard

    init(defaults: GeneratorDefaults = GeneratorDefaults(), random: any RandomSource = SystemRandomSource(),
         clipboard: SecretClipboard = .shared) {
        self.defaults = defaults; self.clipboard = clipboard
        generator = PasswordGenerator(random: random)
        options = defaults.load()
    }

    var strength: GeneratorStrength.Level { GeneratorStrength.level(options: options) }
    var canUse: Bool { !value.isEmpty && !used }

    /// The first value, when the sheet appears (not in `init`: SwiftUI may build the model more than once).
    func start() { if value.isEmpty && error == nil { regenerate() } }

    func regenerate() {
        copied = false
        do {
            value = try generator.generate(options); error = nil
        } catch let e as GeneratorError {
            value = ""; error = e.message
        } catch {
            value = ""; self.error = "Could not generate a password"
        }
    }

    /// Local-only, with the expiry chosen in Settings.
    func copy() {
        guard !value.isEmpty else { return }
        clipboard.copy(value)
        copied = true
    }

    /// Closes the sheet first, then hands the value over on the next main-actor turn, so the editor is not
    /// changed while the sheet is being dismissed. Delivers at most once.
    func use(dismiss: () -> Void, deliver: @escaping @MainActor (String) -> Void) {
        guard canUse else { return }
        used = true
        let value = value
        dismiss()
        Task { @MainActor in deliver(value) }
    }
}
