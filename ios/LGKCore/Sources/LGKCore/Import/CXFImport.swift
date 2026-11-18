import Foundation

/// Maps a Credential Exchange (CXF v1.0) `Account` to import candidates, line for line as Windows
/// (`importers/cxf.py`) and Android (`CxfImport.kt`) read it, so one file gives the same items and skip count:
///
/// * `basic-auth` -> a login (every `scope.urls` address, username, password); a second one is counted as unsupported;
/// * `totp` -> the item's login as an `otpauth://` URI; with no login, a login holding only the code (the import
///   review keeps it as a secure note); each further `totp` becomes another code-only login;
/// * `note` -> joined into the first login's notes, or a secure note when the item has no login or code;
/// * `passkey` -> a passkey candidate, ahead of the item's login;
/// * any other credential type is counted as unsupported. An item that is not an object is ignored.
///
/// Decoding is tolerant: anything malformed is counted as unsupported, never fatal.
public enum CXFImport {
    public enum CXFError: Error, Equatable { case notAnAccount }

    private static let maxCredentialIDBytes = 1023

    /// Rewrites each `\uD800`-`\uDFFF` escape that is not part of a high-low pair as `\uFFFD`; everything else is
    /// copied unchanged (an escaped backslash is skipped, so `\\ud800` stays text).
    static func replacingLoneSurrogateEscapes(_ data: Data) -> Data {
        let b = [UInt8](data)
        func unit(at i: Int) -> UInt16? {
            guard i + 5 < b.count, b[i] == 0x5C, b[i + 1] == 0x75 || b[i + 1] == 0x55 else { return nil }
            guard let s = String(bytes: b[(i + 2)...(i + 5)], encoding: .ascii) else { return nil }
            return UInt16(s, radix: 16)
        }
        var out = [UInt8](); out.reserveCapacity(b.count)
        let replacement = Array("\\ufffd".utf8)
        var i = 0
        while i < b.count {
            guard b[i] == 0x5C, i + 1 < b.count else { out.append(b[i]); i += 1; continue }
            guard let u = unit(at: i) else { out.append(b[i]); out.append(b[i + 1]); i += 2; continue }
            if (0xD800...0xDBFF).contains(u), let next = unit(at: i + 6), (0xDC00...0xDFFF).contains(next) {
                out.append(contentsOf: b[i..<(i + 12)]); i += 12
            } else if (0xD800...0xDFFF).contains(u) {
                out.append(contentsOf: replacement); i += 6
            } else {
                out.append(contentsOf: b[i..<(i + 6)]); i += 6
            }
        }
        return Data(out)
    }

    public static func candidates(fromAccountJSON data: Data) throws -> (candidates: [ImportCandidate], unsupported: Int) {
        // Foundation refuses a lone surrogate escape (`\ud800`); such a file imports with U+FFFD, as on Windows.
        let parsed = (try? JSONSerialization.jsonObject(with: data))
            ?? (try? JSONSerialization.jsonObject(with: replacingLoneSurrogateEscapes(data)))
        guard let root = parsed as? [String: Any],
              let items = root["items"] as? [Any] else { throw CXFError.notAnAccount }
        var out = [ImportCandidate]()
        var unsupported = 0
        for raw in items {
            guard let item = raw as? [String: Any] else { continue }   // ignored, as on Windows and Android
            let r = map(item)
            out += r.candidates
            unsupported += r.unsupported
        }
        return (out, unsupported)
    }

    private static func map(_ item: [String: Any]) -> (candidates: [ImportCandidate], unsupported: Int) {
        let title = text(item["title"], 512)
        let rawURLs = ((item["scope"] as? [String: Any])?["urls"] as? [Any]) ?? []
        let urls = Array(rawURLs.compactMap { $0 as? String }.filter { !$0.isEmpty }.prefix(50))
        guard let creds = item["credentials"] as? [Any] else { return ([], 0) }
        var logins = [[String: Any]](), totps = [[String: Any]](), notes = [String]()
        var out = [ImportCandidate]()
        var unsupported = 0
        for raw in creds {
            guard let c = raw as? [String: Any], let kind = c["type"] as? String else { unsupported += 1; continue }
            switch kind {
            case "basic-auth":
                if logins.isEmpty { logins.append(c) } else { unsupported += 1 }   // one login per item
            case "totp":
                totps.append(c)
            case "note":
                let content = text(c["content"], 64 * 1024)
                if !content.isEmpty { notes.append(content) }
            case "passkey":
                if let f = passkey(c) {
                    out.append(ImportCandidate(title: title.isEmpty ? f.rpID : title, kind: .passkey(f),
                                               urls: urls.isEmpty ? ["https://\(f.rpID)"] : urls))
                } else {
                    unsupported += 1
                }
            default:
                unsupported += 1
            }
        }
        let noteText = notes.joined(separator: "\n\n")
        let stamp = created(item)
        let loginSources: [[String: Any]] = logins.isEmpty ? (totps.isEmpty ? [] : [[:]]) : logins
        for (index, c) in loginSources.enumerated() {
            let username = text(c["username"], 512)
            let code = index < totps.count ? otpauth(totps[index], fallbackUsername: username) : ""
            let fields = LoginFields(url: urls.first ?? "", username: username, password: text(c["password"]),
                                     notes: index == 0 ? noteText : "", otpauth: code.isEmpty ? nil : code)
            out.append(ImportCandidate(title: title, kind: .login(fields), urls: urls, created: stamp))
        }
        for extra in totps.dropFirst(max(logins.count, 1)) {
            let code = otpauth(extra, fallbackUsername: "")
            let fields = LoginFields(url: urls.first ?? "", username: "", password: "", notes: "",
                                     otpauth: code.isEmpty ? nil : code)
            out.append(ImportCandidate(title: title, kind: .login(fields), urls: urls))
        }
        if !noteText.isEmpty, logins.isEmpty, totps.isEmpty {
            out.insert(ImportCandidate(title: title, kind: .note(NoteFields(notes: noteText))), at: 0)
        }
        return (out, unsupported)
    }

    /// Windows `_text`: an EditableField (`{"value": ...}`) or a bare string, at most `limit` characters; else "".
    private static func text(_ v: Any?, _ limit: Int = 4096) -> String {
        var value = v
        if let field = v as? [String: Any] { value = field["value"] }
        guard let s = value as? String else { return "" }
        return Py.prefix(s, limit)
    }

    /// Windows `_int`: a JSON integer (not a boolean or a float) within `low...high`, else `fallback`.
    /// Int64 throughout: `creationAt` can pass Int.max on the 32-bit Apple Watch (arm64_32).
    private static func int(_ v: Any?, _ fallback: Int64, _ low: Int64, _ high: Int64) -> Int64 {
        guard let n = v as? NSNumber,
              ["q", "i", "l", "s", "Q", "I", "L", "S"].contains(String(cString: n.objCType)) else { return fallback }
        let i = n.int64Value
        guard i >= low, i <= high else { return fallback }
        return i
    }

    /// Windows `_created`: `creationAt` as Unix seconds when it is a plausible date.
    private static func created(_ item: [String: Any]) -> Int64? {
        let stamp = int(item["creationAt"], 0, 1, 253_402_300_799)
        return stamp > 0 ? stamp : nil
    }

    /// Windows `_otpauth` through `totp_uri_from_secret`: "" when the code has no secret. An unreadable secret is
    /// kept: the import review moves it to a hidden field, as on Windows.
    private static func otpauth(_ t: [String: Any], fallbackUsername: String) -> String {
        let secret = text(t["secret"], 1024)
        if secret.isEmpty { return "" }
        let named = (t["algorithm"] as? String)?.uppercased() ?? ""
        let algorithm = ["SHA1", "SHA256", "SHA512"].contains(named) ? named : "SHA1"
        let issuer = text(t["issuer"], 256)
        let own = text(t["username"], 256)
        let username = own.isEmpty ? fallbackUsername : own
        let label = !issuer.isEmpty && !username.isEmpty ? "\(issuer):\(username)" : (username.isEmpty ? issuer : username)
        return ImportRules.totpURI(secret, label: label, issuer: issuer, digits: Int(int(t["digits"], 6, 6, 8)),
                                   period: Int(int(t["period"], 30, 1, 86400)), algorithm: algorithm)
    }

    /// Accepts base64url or standard base64, padded or not.
    private static func b64(_ s: String, maxBytes: Int) -> [UInt8]? {
        var t = Py.strip(s).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while t.hasSuffix("=") { t.removeLast() }
        return decodeBase64URL(t, maxBytes: maxBytes)
    }

    private static func passkey(_ p: [String: Any]) -> PasskeyFields? {
        let rp = Py.casefold(Py.strip(text(p["rpId"], 253)))   // as Windows and Android store it
        guard let cid = (p["credentialId"] as? String).flatMap({ b64($0, maxBytes: maxCredentialIDBytes) }),
              !cid.isEmpty, !rp.isEmpty,
              let keyText = p["key"] as? String,
              let der = b64(keyText, maxBytes: 4096),
              PasskeyKey(pkcs8B64URL: base64URLNoPad(der)) != nil
        else { return nil }
        var handle = [UInt8]()
        if let h = p["userHandle"], !(h is NSNull) {
            guard let hs = h as? String, let d = b64(hs, maxBytes: 64) else { return nil }
            handle = d
        }
        let own = text(p["username"], 256)
        let name = own.isEmpty ? text(p["userName"], 256) : own
        return PasskeyFields(rpID: rp, userName: name,
                             userDisplayName: text(p["userDisplayName"], 256),
                             userHandle: Data(handle), credentialID: Data(cid), pkcs8: Data(der))
    }
}
