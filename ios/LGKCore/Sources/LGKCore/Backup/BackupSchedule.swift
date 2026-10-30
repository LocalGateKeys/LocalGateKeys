import Crypto
import Foundation

/// A refused schedule step, with the message Windows (`backup_schedule.py`) gives. Never carries a password.
public struct BackupScheduleError: Error, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// Windows `backup_schedule.py`: when a scheduled backup is due, what it is called and which old ones go.
///
/// The schedule is a pure function of the clock, the settings and the last successful run, so a restart never
/// repeats a backup and any number of missed slots catch up once. Python works in naive local time; here every
/// function takes the `Calendar` (and its time zone) that stands for "local" (`Calendar.current` in the app).
/// Pinned by `tests/vectors/backup/schedule/schedule.json`.
public enum BackupSchedule {
    public static let frequencies = ["off", "daily", "weekly"]
    public static let keepChoices = [1, 2]
    public static let defaultTime = "12:00"
    /// Python `weekday()` order: Monday is 0.
    public static let weekdays = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    public static let scheduledDirName = "Scheduled"
    public static let stateFilename = "schedule-state.json"
    public static let minBackupPasswordLength = 12
    /// A failed run is retried at most this often while the vault stays unlocked.
    public static let retryAfter: TimeInterval = 30 * 60
    public static let filenamePrefix = "LocalGateKeys-scheduled-"
    public static let backupExtension = ".lgk"
    public static var timeHint: String { String(localized: "Use a 24-hour time such as 08:30.", bundle: .module) }

    // MARK: schedule

    /// `parse_time`: `H:MM` or `HH:MM`, 24-hour, surrounding white space ignored.
    public static func parseTime(_ value: String) throws -> (hour: Int, minute: Int) {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        func digits(_ s: Substring) -> Bool { s.unicodeScalars.allSatisfy { ("0"..."9").contains($0) } }
        guard parts.count == 2, (1...2).contains(parts[0].count), parts[1].count == 2, digits(parts[0]), digits(parts[1]),
              let h = Int(parts[0]), let m = Int(parts[1]), h <= 23, m <= 59 else { throw BackupScheduleError(timeHint) }
        return (h, m)
    }

    /// `validated_time`: the time as `HH:MM`, or `fallback` when it is not one.
    public static func validatedTime(_ value: String?, fallback: String = defaultTime) -> String {
        guard let value, let (h, m) = try? parseTime(value) else { return fallback }
        return String(format: "%02d:%02d", h, m)
    }

    /// Python `weekday()` (Monday 0) of `date` in `calendar`.
    public static func weekday(of date: Date, calendar: Calendar) -> Int {
        (calendar.component(.weekday, from: date) + 5) % 7
    }

    /// `latest_slot`: the most recent scheduled time at or before `now`; nil when off (or the time is invalid).
    public static func latestSlot(now: Date, frequency: String, time: String, weekday: Int = 0,
                                  calendar: Calendar = .current) -> Date? {
        guard frequency == "daily" || frequency == "weekly", let (h, m) = try? parseTime(time) else { return nil }
        func slot(daysBack: Int) -> Date? {
            guard let day = calendar.date(byAdding: .day, value: -daysBack, to: now) else { return nil }
            var c = calendar.dateComponents([.year, .month, .day], from: day)
            c.hour = h; c.minute = m; c.second = 0; c.nanosecond = 0
            return calendar.date(from: c)
        }
        if frequency == "daily" {
            guard let today = slot(daysBack: 0) else { return nil }
            return today <= now ? today : slot(daysBack: 1)
        }
        let back = ((Self.weekday(of: now, calendar: calendar) - weekday) % 7 + 7) % 7
        guard let candidate = slot(daysBack: back) else { return nil }
        return candidate <= now ? candidate : slot(daysBack: back + 7)
    }

    /// `is_due`: true when the latest slot has no successful backup at or after it. A week of missed daily runs makes
    /// one catch-up backup; a last success in the future (the clock moved back) is ignored.
    public static func isDue(now: Date, lastSuccess: Date?, frequency: String, time: String, weekday: Int = 0,
                             calendar: Calendar = .current) -> Bool {
        guard let slot = latestSlot(now: now, frequency: frequency, time: time, weekday: weekday, calendar: calendar) else {
            return false
        }
        guard let lastSuccess, lastSuccess <= now else { return true }
        return lastSuccess < slot
    }

    // MARK: state

    public static func stateURL(_ directory: URL) -> URL { directory.appendingPathComponent(stateFilename) }

    /// `read_last_success`: nil when missing, unreadable or not a number.
    public static func readLastSuccess(_ directory: URL) -> Date? {
        guard let data = try? Data(contentsOf: stateURL(directory)), data.count <= 4096,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let number = object["last_success"] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value.isFinite, abs(value) < 1e11 else { return nil }
        return Date(timeIntervalSince1970: value)
    }

    /// `write_last_success`: `{"version": 1, "last_success": <timestamp>}` written atomically (a time, never a secret).
    public static func writeLastSuccess(_ directory: URL, _ when: Date) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let text = "{\"version\": 1, \"last_success\": \(when.timeIntervalSince1970)}"
        try Data(text.utf8).write(to: stateURL(directory), options: .atomic)
    }

    // MARK: filenames and retention

    /// `profile_tag`: a short, stable, non-identifying tag so profiles can share a mirror folder.
    public static func profileTag(_ profileID: String) -> String {
        String(SHA256.hash(data: Array(profileID.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8))
    }

    static func isTag(_ tag: String) -> Bool {
        tag.utf8.count == 8 && tag.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// `scheduled_filename`: `LocalGateKeys-scheduled-<tag>-YYYYMMDD-HHMMSS[-n].lgk`, local time.
    public static func scheduledFilename(tag: String, when: Date, counter: Int = 0, calendar: Calendar = .current) throws -> String {
        guard isTag(tag) else { throw BackupScheduleError("Malformed profile tag") }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        var gregorian = Calendar(identifier: .gregorian)
        gregorian.timeZone = calendar.timeZone
        f.calendar = gregorian
        f.timeZone = calendar.timeZone
        f.dateFormat = "yyyyMMdd-HHmmss"
        return "\(filenamePrefix)\(tag)-\(f.string(from: when))\(counter != 0 ? "-\(counter)" : "")\(backupExtension)"
    }

    /// The timestamp and counter of an owned name (`_pattern`, case-insensitive), or nil.
    public static func parse(_ name: String, tag: String) -> (stamp: String, counter: Int)? {
        let lower = name.lowercased()
        let head = (filenamePrefix + tag + "-").lowercased()
        guard isTag(tag), lower.hasPrefix(head), lower.hasSuffix(backupExtension) else { return nil }
        let middle = lower.dropFirst(head.count).dropLast(backupExtension.count)
        let parts = middle.split(separator: "-", omittingEmptySubsequences: false)
        func digits(_ s: Substring, _ counts: ClosedRange<Int>) -> Bool {
            counts.contains(s.count) && s.unicodeScalars.allSatisfy { ("0"..."9").contains($0) }
        }
        guard parts.count == 2 || parts.count == 3, digits(parts[0], 8...8), digits(parts[1], 6...6) else { return nil }
        if parts.count == 3 {
            guard digits(parts[2], 1...3) else { return nil }
            return ("\(parts[0])-\(parts[1])", Int(parts[2]) ?? 0)
        }
        return ("\(parts[0])-\(parts[1])", 0)
    }

    /// `owned_backups`: this profile's scheduled backups in `directory` (regular files only), newest first.
    public static func ownedBackups(in directory: URL, tag: String) -> [URL] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return [] }
        var found: [(stamp: String, counter: Int, url: URL)] = []
        for name in names {
            guard let (stamp, counter) = parse(name, tag: tag) else { continue }
            let url = directory.appendingPathComponent(name)
            guard let type = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType,
                  type == .typeRegular else { continue }
            found.append((stamp, counter, url))
        }
        return found.sorted { ($0.stamp, $0.counter) > ($1.stamp, $1.counter) }.map(\.url)
    }

    /// `prune`: deletes this profile's scheduled backups beyond `keep` (at least 1), never `protect`, which counts as
    /// kept. Each deleted backup's own `.sha256.json` goes with it (the Mac writes one beside every backup).
    @discardableResult
    public static func prune(in directory: URL, tag: String, keep: Int, protect: URL?) -> [URL] {
        let keep = max(1, keep)
        var kept = protect == nil ? 0 : 1
        var removed: [URL] = []
        for url in ownedBackups(in: directory, tag: tag) {
            if let protect, url.lastPathComponent == protect.lastPathComponent { continue }
            if kept < keep { kept += 1; continue }
            guard (try? FileManager.default.removeItem(at: url)) != nil else { continue }
            removed.append(url)
            let manifest = url.appendingPathExtension("sha256.json")
            if (try? FileManager.default.attributesOfItem(atPath: manifest.path))?[.type] as? FileAttributeType == .typeRegular {
                try? FileManager.default.removeItem(at: manifest)
            }
        }
        return removed
    }

    /// `_unique_destination`: the first free name for `when` (counter 0-999).
    public static func uniqueDestination(in directory: URL, tag: String, when: Date, calendar: Calendar = .current) throws -> URL {
        for counter in 0..<1000 {
            let candidate = directory.appendingPathComponent(try scheduledFilename(tag: tag, when: when, counter: counter, calendar: calendar))
            if (try? FileManager.default.attributesOfItem(atPath: candidate.path)) == nil { return candidate }
        }
        throw BackupScheduleError("Too many scheduled backups share one timestamp")
    }
}
