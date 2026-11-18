import Foundation
#if os(iOS)
import UIKit
import AppShared
#elseif os(macOS)
import AppKit
import AppSharedMac
#endif

/// The printable emergency kit, shared by the iPhone and the Mac (the Windows and Android kits' content).
///
/// `build` turns facts and the optional recovery phrase into blocks; `attributedText` draws them as black text on
/// white; the iPhone turns that into a PDF in memory (`pdf`) for the system print sheet and the Mac prints it from a
/// text view. Nothing here stores or logs the words: they are only copied into the boxes, and the callers drop them
/// when printing finishes. No file is written. The master or app password line is always blank.
enum EmergencyKitDocument {
    /// The recovery phrase has this many words (`BIP39.wordCount`).
    static let wordCount = 24

    /// Which kit: the phone's (tied to the optional app password) or the Mac's (tied to the master password).
    enum Kind {
        case phone
        case mac(machine: String, vaultFolder: String, backupFolders: [String])
    }

    /// What the kit says about this install. [date] is already formatted for the person's language.
    struct Facts {
        var kind: Kind
        var date: String
        var appVersion: String
    }

    struct Box: CustomStringConvertible, CustomDebugStringConvertible {
        let number: Int
        let word: String
        var description: String { "Box(number: \(number))" } // never the word, even in a log line
        var debugDescription: String { description }
    }

    enum Block {
        case title(String)
        case paragraph(String)
        /// One or more values (the backup folders go one per line).
        case fact(label: String, values: [String])
        /// A label with a line to write on.
        case blankLine(String)
        case heading(String)
        case phraseBoxes([Box])
        case steps([String])
        case warning(String)
    }

    /// [words]: the recovery phrase to print, or nil for blank boxes. The boxes always number `wordCount`.
    static func build(_ facts: Facts, words: [String]?) -> [Block] {
        let boxes = (0..<wordCount).map { i in Box(number: i + 1, word: words.flatMap { i < $0.count ? $0[i] : nil } ?? "") }
        let phraseHeading = String(localized: "Recovery phrase (\(wordCount) words, in order)")
        let warning = Block.warning(String(localized: "Treat this page like your vault. A PDF saved with the recovery phrase on it is as sensitive as the vault itself: keep the paper somewhere safe and delete any saved PDF when you are done."))
        switch facts.kind {
        case .phone:
            return [
                .title(String(localized: "Emergency kit")),
                .paragraph(DeviceText.isPad ? String(localized: "ipad.emergencyKitDocument.keepPageOfflineAnd", defaultValue: "Keep this page offline and apart from your iPad. It tells you how to get back into LocalGateKeys if you forget the app password.") : String(localized: "Keep this page offline and apart from your iPhone. It tells you how to get back into LocalGateKeys if you forget the app password.")),
                .fact(label: String(localized: "Date"), values: [facts.date]),
                .fact(label: String(localized: "LocalGateKeys version"), values: [facts.appVersion]),
                .blankLine(String(localized: "App password (write it by hand, or keep it apart from this page):")),
                .heading(phraseHeading),
                .phraseBoxes(boxes),
                .heading(String(localized: "How to get back in")),
                .steps([
                    String(localized: "On the LocalGateKeys lock screen, tap “\(String(localized: "Forgot app password?"))”."),
                    String(localized: "Type the \(wordCount) words above, in order."),
                    String(localized: "Choose a new app password. Your passwords are not changed."),
                    (DeviceText.isPad ? String(localized: "ipad.emergencyKitDocument.ifLostOrVault", defaultValue: "If the iPad is lost or the vault is gone, install LocalGateKeys on a new iPad and sync it with your PC, Mac or another iPad. An encrypted backup exported from this iPad can be restored on the new iPad (Settings › Import & Export › Restore from a backup).") : String(localized: "If the iPhone is lost or the vault is gone, install LocalGateKeys on a new iPhone and sync it with your PC, Mac or another iPhone. An encrypted backup exported from this iPhone can be restored on the new iPhone (Settings › Import & Export › Restore from a backup).")),
                ]),
                warning,
            ]
        case .mac(let machine, let vaultFolder, let backupFolders):
            return [
                .title(String(localized: "Emergency kit")),
                .paragraph(String(localized: "Keep this page offline and apart from your backups. It tells you how to get your passwords back on a new Mac.")),
                .fact(label: String(localized: "This Mac"), values: [machine]),
                .fact(label: String(localized: "Vault folder"), values: [vaultFolder]),
                .fact(label: String(localized: "Backup folders"),
                      values: backupFolders.isEmpty ? [String(localized: "None yet")] : backupFolders),
                .fact(label: String(localized: "Date"), values: [facts.date]),
                .fact(label: String(localized: "LocalGateKeys version"), values: [facts.appVersion]),
                .blankLine(String(localized: "Master password (write it by hand, or keep it apart from this page):")),
                .heading(phraseHeading),
                .phraseBoxes(boxes),
                .heading(String(localized: "How to restore")),
                .steps([
                    String(localized: "Install LocalGateKeys on the new Mac (the same version or a newer one)."),
                    String(localized: "Open LocalGateKeys, choose Create vault, set a master password (any one you will remember) and unlock the new vault."),
                    String(localized: "Open the Recovery centre, choose Restore… under Full backup, then pick your backup file (.lgk) from one of the backup folders above or from your copy."),
                    String(localized: "Enter the backup password, then the master password in use when the backup was made."),
                    String(localized: "Check the preview, then choose Restore… to replace the empty vault. A safety copy is kept first, and the master password asked once more is the one you set in step 2."),
                    String(localized: "If you forgot the master password on the Mac where this kit was made, choose “Forgot your master password?” on its lock screen, enter the \(wordCount) words above and set a new master password. A backup still asks for the master password it was made with."),
                ]),
                warning,
            ]
        }
    }

    // MARK: drawing

    #if os(iOS)
    private typealias KitFont = UIFont
    private typealias KitColor = UIColor
    #else
    private typealias KitFont = NSFont
    private typealias KitColor = NSColor
    #endif

    private static let columns = 3
    private static let columnWidth: CGFloat = 165

    private static func paragraph(before: CGFloat = 0, after: CGFloat = 6, first: CGFloat = 0, head: CGFloat = 0,
                                  tabs: [CGFloat] = [], wrap: NSLineBreakMode = .byWordWrapping) -> NSParagraphStyle {
        let p = NSMutableParagraphStyle()
        p.paragraphSpacingBefore = before
        p.paragraphSpacing = after
        p.firstLineHeadIndent = first
        p.headIndent = head
        p.tabStops = tabs.map { NSTextTab(textAlignment: .left, location: $0, options: [:]) }
        p.lineBreakMode = wrap
        return p
    }

    /// The kit as black text on white, with tab-stop columns for the phrase boxes. Wraps; the PDF and the Mac's text
    /// view break it into pages.
    static func attributedText(_ blocks: [Block]) -> NSAttributedString {
        let out = NSMutableAttributedString()
        let body = KitFont.systemFont(ofSize: 11)
        let bold = KitFont.systemFont(ofSize: 11, weight: .semibold)
        let mono = KitFont.monospacedSystemFont(ofSize: 12, weight: .regular)

        func append(_ text: String, _ font: KitFont, _ style: NSParagraphStyle, underline: Bool = false) {
            var attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: KitColor.black, .paragraphStyle: style]
            if underline { attrs[.underlineStyle] = NSUnderlineStyle.single.rawValue }
            out.append(NSAttributedString(string: text, attributes: attrs))
        }

        for block in blocks {
            switch block {
            case .title(let text):
                append(text + "\n", KitFont.systemFont(ofSize: 22, weight: .bold), paragraph(after: 8))
            case .paragraph(let text):
                append(text + "\n", body, paragraph(after: 10))
            case .fact(let label, let values):
                let style = paragraph(after: 4, head: 12, wrap: .byCharWrapping)
                append(label + ": ", bold, style)
                // A line separator keeps several values in one paragraph (one hanging indent).
                append(values.joined(separator: "\u{2028}") + "\n", body, style)
            case .blankLine(let label):
                append(label + "\n", body, paragraph(before: 8, after: 8))
                append(String(repeating: "_", count: 44) + "\n", mono, paragraph(after: 6))
            case .heading(let text):
                append(text + "\n", KitFont.systemFont(ofSize: 14, weight: .semibold), paragraph(before: 12, after: 8))
            case .phraseBoxes(let boxes):
                let tabs = (1..<columns).map { CGFloat($0) * columnWidth }
                let style = paragraph(after: 10, tabs: tabs)
                for rowStart in stride(from: 0, to: boxes.count, by: columns) {
                    let row = boxes[rowStart..<min(rowStart + columns, boxes.count)]
                    for (n, box) in row.enumerated() {
                        append(String(format: "%2d. ", box.number), mono, style)
                        if box.word.isEmpty {
                            append(String(repeating: "_", count: 14), mono, style)
                        } else {
                            append(box.word, mono, style, underline: true)
                        }
                        append(n == row.count - 1 ? "\n" : "\t", mono, style)
                    }
                }
            case .steps(let items):
                let style = paragraph(after: 5, first: 0, head: 18, tabs: [18])
                for (i, item) in items.enumerated() { append("\(i + 1).\t\(item)\n", body, style) }
            case .warning(let text):
                append(text + "\n", bold, paragraph(before: 14, after: 0))
            }
        }
        return out
    }
}

#if os(iOS)
extension EmergencyKitDocument {
    /// US Letter for the United States, A4 elsewhere (the print sheet scales to the paper chosen there).
    private static var pageRect: CGRect {
        Locale.current.measurementSystem == .us ? CGRect(x: 0, y: 0, width: 612, height: 792) : CGRect(x: 0, y: 0, width: 595, height: 842)
    }

    /// The kit as PDF data in memory, paginated: text that does not fit a page flows to the next one. Nothing is
    /// written to disk.
    @MainActor
    static func pdf(_ blocks: [Block]) -> Data {
        let page = pageRect
        let margin: CGFloat = 50
        let content = CGSize(width: page.width - 2 * margin, height: page.height - 2 * margin)
        let storage = NSTextStorage(attributedString: attributedText(blocks))
        let layout = NSLayoutManager()
        storage.addLayoutManager(layout)
        var containers: [NSTextContainer] = []
        // One container per page until every glyph is placed (the cap only stops a pathological loop).
        repeat {
            let container = NSTextContainer(size: content)
            container.lineFragmentPadding = 0
            layout.addTextContainer(container)
            layout.ensureLayout(for: container)
            containers.append(container)
        } while NSMaxRange(layout.glyphRange(for: containers[containers.count - 1])) < layout.numberOfGlyphs && containers.count < 20
        assert(NSMaxRange(layout.glyphRange(for: containers[containers.count - 1])) >= layout.numberOfGlyphs,
               "Emergency kit needs more than 20 pages; the rest would be cut off")
        let renderer = UIGraphicsPDFRenderer(bounds: page)
        return renderer.pdfData { context in
            for container in containers {
                context.beginPage()
                let glyphs = layout.glyphRange(for: container)
                let origin = CGPoint(x: margin, y: margin)
                layout.drawBackground(forGlyphRange: glyphs, at: origin)
                layout.drawGlyphs(forGlyphRange: glyphs, at: origin)
            }
        }
    }

    /// This iPhone's non-secret facts (the date and the app version).
    @MainActor
    static func phoneFacts() -> Facts {
        Facts(kind: .phone, date: Date().formatted(date: .long, time: .omitted),
              appVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "")
    }

    /// Opens the system print sheet (which also offers Save to Files and Share) on the kit, as PDF data in memory.
    /// The data is dropped when the sheet closes.
    @MainActor
    static func print(_ facts: Facts, words: [String]?) {
        print(blocks: build(facts, words: words))
    }

    /// The print sheet on any blocks (the kit, the vault health report); the job is named after the first title.
    @MainActor
    static func print(blocks: [Block]) {
        let title: String = { if case .title(let t)? = blocks.first { return t } else { return "" } }()
        let controller = UIPrintInteractionController.shared
        let info = UIPrintInfo(dictionary: nil)
        info.outputType = .general
        info.jobName = title
        controller.printInfo = info
        controller.printingItem = pdf(blocks)
        controller.present(animated: true) { controller, _, _ in
            controller.printingItem = nil
        }
    }
}
#endif

#if os(macOS)
extension EmergencyKitDocument {
    /// The non-secret facts this Mac's kit prints (this Mac, where the vault and the scheduled backups are, the date
    /// and version). The phrase and the passwords never pass through here. [schedule] gives the backup folders; nil
    /// (a window without it) leaves them out.
    @MainActor
    static func macFacts(schedule: BackupScheduleModel?) -> Facts {
        Facts(kind: .mac(machine: MacSyncEnvironment.deviceName(), vaultFolder: MacAppEnvironment.vaultDirectory().path,
                         backupFolders: schedule?.kitFolders() ?? []),
              date: Date().formatted(date: .long, time: .omitted), appVersion: SecurityModel.bundleVersion)
    }

    /// Opens the system print panel (which also offers Save as PDF) on a text view of the kit, black on white. The
    /// text view and the words are dropped when the panel closes. No file of ours is written.
    @MainActor
    static func print(_ facts: Facts, words: [String]?) {
        print(blocks: build(facts, words: words), jobTitle: String(localized: "Emergency kit"))
    }

    /// The print panel on any blocks (the kit, the vault health report).
    @MainActor
    static func print(blocks: [Block], jobTitle: String) {
        let info = (NSPrintInfo.shared.copy() as? NSPrintInfo) ?? NSPrintInfo()
        info.topMargin = 50; info.bottomMargin = 50; info.leftMargin = 50; info.rightMargin = 50
        info.isHorizontallyCentered = false
        info.isVerticallyCentered = false
        info.horizontalPagination = .fit
        info.verticalPagination = .automatic
        let width = info.paperSize.width - info.leftMargin - info.rightMargin
        let unbounded = CGFloat.greatestFiniteMagnitude
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 100))
        view.isEditable = false
        view.isVerticallyResizable = true
        view.isHorizontallyResizable = false
        view.minSize = NSSize(width: width, height: 0)
        view.maxSize = NSSize(width: width, height: unbounded)
        view.textContainerInset = .zero
        view.textContainer?.lineFragmentPadding = 0
        view.textContainer?.containerSize = NSSize(width: width, height: unbounded)
        view.textContainer?.widthTracksTextView = true
        view.drawsBackground = true
        view.backgroundColor = .white
        view.textStorage?.setAttributedString(attributedText(blocks))
        if let layout = view.layoutManager, let container = view.textContainer { layout.ensureLayout(for: container) }
        view.sizeToFit()
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.showsPrintPanel = true
        operation.showsProgressPanel = true
        operation.jobTitle = jobTitle
        operation.run()
    }
}
#endif
