import Foundation

/// One item parsed from an import source, before it becomes a vault record.
public struct ImportCandidate: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case login(LoginFields)
        case passkey(PasskeyFields)
        case note(NoteFields)
        case card(CardFields)
        case identity(IdentityFields)
    }
    public var title: String
    public var kind: Kind
    /// Every web address of the item; a login's `LoginFields.url` is the first.
    public var urls: [String]
    /// Folder path in the source, `/`-separated ("" when none).
    public var folder: String
    public var tags: [String]
    public var customFields: [ImportCustomField]
    public var favourite: Bool
    /// Unix seconds, when the source records them.
    public var created: Int64?
    public var modified: Int64?
    /// 1-based row (CSV) or item number in the source, for messages.
    public var sourceRow: Int?

    public init(title: String, kind: Kind, urls: [String] = [], folder: String = "", tags: [String] = [],
                customFields: [ImportCustomField] = [], favourite: Bool = false, created: Int64? = nil,
                modified: Int64? = nil, sourceRow: Int? = nil) {
        self.title = title; self.kind = kind; self.folder = folder; self.tags = tags
        self.customFields = customFields; self.favourite = favourite; self.created = created
        self.modified = modified; self.sourceRow = sourceRow
        if urls.isEmpty, case .login(let f) = kind, !f.url.isEmpty { self.urls = [f.url] } else { self.urls = urls }
    }

    /// Two-factor key of an item that is not a login (1PUX and Proton Pass keep them on notes, cards and identities).
    private var otherTOTP: String?

    /// The item's two-factor `otpauth://` URI: a login's `LoginFields.otpauth`, otherwise its own stored value.
    public var totp: String? {
        get {
            if case .login(let f) = kind { return f.otpauth }
            return otherTOTP
        }
        set {
            if case .login(var f) = kind { f.otpauth = newValue; kind = .login(f) } else { otherTOTP = newValue }
        }
    }

    public var notes: String {
        switch kind {
        case .login(let f): return f.notes
        case .note(let f): return f.notes
        case .card(let f): return f.notes
        case .identity(let f): return f.notes
        case .passkey: return ""
        }
    }
}

public struct ImportCustomField: Sendable, Equatable {
    public var name: String
    public var value: String
    public var hidden: Bool
    public init(name: String, value: String, hidden: Bool) { self.name = name; self.value = value; self.hidden = hidden }
}

public struct NoteFields: Sendable, Equatable {
    public var notes: String
    public init(notes: String) { self.notes = notes }
}

/// Payment card values keyed `cardholder`, `number`, `expiry` (`MM/YYYY`), `cvv`, `pin`, `brand`; absent when empty.
public struct CardFields: Sendable, Equatable {
    public var notes: String
    public var values: [String: String]
    public init(notes: String, values: [String: String]) { self.notes = notes; self.values = values }
}

/// Identity values keyed as on Windows (`name`, `given_name`, `family_name`, `email`, `address_line1`, ...).
public struct IdentityFields: Sendable, Equatable {
    public var notes: String
    public var values: [String: String]
    public init(notes: String, values: [String: String]) { self.notes = notes; self.values = values }
}

public struct LoginFields: Sendable, Equatable {
    public var url: String
    public var username: String
    public var password: String
    public var notes: String
    public var otpauth: String?
    public init(url: String, username: String, password: String, notes: String, otpauth: String?) {
        self.url = url; self.username = username; self.password = password
        self.notes = notes; self.otpauth = otpauth
    }
}

public struct PasskeyFields: Sendable, Equatable {
    public var rpID: String
    public var userName: String
    public var userDisplayName: String
    public var userHandle: Data
    public var credentialID: Data
    public var pkcs8: Data
    public init(rpID: String, userName: String, userDisplayName: String,
                userHandle: Data, credentialID: Data, pkcs8: Data) {
        self.rpID = rpID; self.userName = userName; self.userDisplayName = userDisplayName
        self.userHandle = userHandle; self.credentialID = credentialID; self.pkcs8 = pkcs8
    }
}
