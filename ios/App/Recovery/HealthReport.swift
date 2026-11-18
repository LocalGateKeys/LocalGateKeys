import Foundation
import LGKCore

/// The one-page vault health report (sub-plan 12, Windows `health_report.py`): facts about how the vault is protected
/// and kept, for the owner or an auditor. No item title, no secret, no username or website: only settings, dates,
/// counts and versions. Printed through the emergency kit's renderer (`EmergencyKitDocument`): a PDF in memory for
/// the iPhone's print sheet, the print panel (with Save as PDF) on the Mac. No file is written.
enum HealthReport {
    nonisolated static let title = String(localized: "Vault health report")
    nonisolated static let printLabel = String(localized: "Print vault health report")

    /// What the report states. Every value is non-secret.
    struct Input {
        /// Argon2id memory of the master password (Mac) or app password (iPhone) key derivation, in KiB.
        var kdfMemoryKiB: UInt32
        /// How the vault is unlocked, already worded ("Master password", "Touch ID", ...).
        var factors: [String]
        var lastBackup: Date?
        /// The restore test row's text (`RestoreTestModel.rowText`).
        var restoreTest: String
        var pairedDevices: Int
        var lastSync: Date?
        /// The access log state, already worded; nil when this device keeps none.
        var accessLog: String?
        /// When the offline breach filter was last updated; nil when none is installed.
        var breachFilterUpdated: Date?
        var build: String
        var isPro: Bool
        var now: Date = Date()
    }

    struct Row: Equatable {
        let label: String
        let value: String
    }

    static func rows(_ i: Input) -> [Row] {
        func date(_ d: Date?) -> String { d.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? String(localized: "Never") }
        func days(_ d: Date) -> Int { max(0, Int(i.now.timeIntervalSince(d) / 86_400)) }
        let backupAge = i.lastBackup.map { String(days($0)) } ?? String(localized: "No backup yet")
        let filter = i.breachFilterUpdated.map { String(days($0)) } ?? String(localized: "Not installed")
        return [
            Row(label: String(localized: "Key derivation memory"), value: String(localized: "\(Int(i.kdfMemoryKiB / 1024)) MiB")),
            Row(label: String(localized: "Unlock factors"), value: i.factors.joined(separator: ", ")),
            Row(label: String(localized: "Days since the last backup"), value: backupAge),
            Row(label: RestoreTestModel.title, value: i.restoreTest),
            Row(label: String(localized: "Paired devices"), value: String(i.pairedDevices)),
            Row(label: String(localized: "Last sync"), value: date(i.lastSync)),
            Row(label: String(localized: "Access log"), value: i.accessLog ?? String(localized: "Not kept on this device")),
            Row(label: String(localized: "Days since the breach filter update"), value: filter),
            Row(label: String(localized: "Build"), value: i.build),
            Row(label: String(localized: "Licence"), value: i.isPro ? "Pro" : String(localized: "Free plan")),
        ]
    }

    /// The report as the emergency kit's blocks (title, date, one fact per row, the no-secrets note).
    static func blocks(_ i: Input) -> [EmergencyKitDocument.Block] {
        [.title(title),
         .paragraph(String(localized: "Made on \(i.now.formatted(date: .long, time: .shortened))."))]
            + rows(i).map { EmergencyKitDocument.Block.fact(label: $0.label, values: [$0.value]) }
            + [.paragraph(String(localized: "This report holds no item titles and no secrets."))]
    }

    /// The report's facts on this device: the default Argon2id memory (`MasterKeyFile.KDFParams.default`, the Mac's
    /// master password and the iPhone's app password), the sync group's other devices and last sync, this build.
    /// No offline breach filter and no access log are kept on Apple devices, and the report says so.
    @MainActor
    static func input(factors: [String], lastBackup: Date?, restoreTest: String, sync: SyncCoordinator?,
                      build: String, isPro: Bool) -> Input {
        let devices = sync.map { s in
            Set(s.membership.members + s.membership.wifiPeers).subtracting([s.membership.deviceID ?? ""]).count
        } ?? 0
        let lastSync = sync?.lastSyncedAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        return Input(kdfMemoryKiB: MasterKeyFile.KDFParams.default.memoryKiB, factors: factors, lastBackup: lastBackup,
                     restoreTest: restoreTest, pairedDevices: devices, lastSync: lastSync, accessLog: nil,
                     breachFilterUpdated: nil, build: build, isPro: isPro)
    }
}
