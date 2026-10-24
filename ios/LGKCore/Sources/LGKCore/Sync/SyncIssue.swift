/// Something a run skipped or refused; `kind` is a stable code (desktop `runner.SyncIssue`), `detail` free text.
public struct SyncIssue: Hashable, Sendable, CustomStringConvertible {
    public let kind: String
    public let detail: String
    public init(_ kind: String, _ detail: String = "") { self.kind = kind; self.detail = detail }
    public var description: String { detail.isEmpty ? kind : "\(kind): \(detail)" }
}

/// Result of one run (desktop `runner.RunReport`).
public struct RunReport: Equatable, Sendable {
    public var applied = 0
    public var deleted = 0
    public var conflicts = 0
    /// Stored records that cannot be published (id, reason), sorted.
    public var skipped: [(String, String)] = []
    public var issues: [SyncIssue] = []
    /// This device's post-apply view (sorted by id) to publish, or nil when nothing should be published.
    public var ownStates: [ItemState]?
    /// Set by a transport that wrote its own file.
    public var wrote = false
    /// Licence bundles received in this run that verified.
    public var licenses: [JSONValue] = []
    /// The store content after the run (records and meta), committed by the transport; nil when unchanged/unknown.
    public var records: [String: JSONValue]?
    public var meta: [String: SyncMeta]?

    public init() {}

    public static func == (l: RunReport, r: RunReport) -> Bool {
        l.applied == r.applied && l.deleted == r.deleted && l.conflicts == r.conflicts
            && l.skipped.map { [$0.0, $0.1] } == r.skipped.map { [$0.0, $0.1] } && l.issues == r.issues
            && l.ownStates == r.ownStates && l.wrote == r.wrote && l.licenses == r.licenses
            && l.records == r.records && l.meta == r.meta
    }
}
