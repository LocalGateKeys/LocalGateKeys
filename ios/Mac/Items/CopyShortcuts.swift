import Foundation
import Observation

/// Whether the window's ⌘C / ⇧⌘C / ⌘T copy the selected item, or the system's Edit › Copy runs.
enum CopyShortcutPolicy {
    enum Responder: Equatable {
        /// The item list has keyboard focus.
        case itemList
        /// A text view or field editor (search field, selectable detail text) is first responder.
        case text
        /// Anything else (a button, the window itself).
        case other
    }

    /// ⌘C and ⇧⌘C are taken only from the item list, so copying selected text anywhere else still works.
    /// ⌘T (no system meaning here) is taken anywhere but a text view. Nothing is taken while a sidebar tool
    /// (Settings, Generator, placeholders) replaces the item list (`listShown` false).
    static func intercepts(key: String, shift: Bool, responder: Responder, listShown: Bool) -> Bool {
        guard listShown else { return false }
        return switch key {
        case "c": responder == .itemList
        case "t": !shift && responder != .text
        default: false
        }
    }
}
