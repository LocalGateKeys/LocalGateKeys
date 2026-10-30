import Foundation

/// Maps a Credential Exchange (CXF v1.0) `Account` to import candidates. Decoding is tolerant:
/// anything unrecognised or malformed is counted as unsupported, never fatal.
public enum CXFImport {
    public enum CXFError: Error, Equatable { case notAnAccount }

    private static let maxCredentialIDBytes = 1023

    public static func candidates(fromAccountJSON data: Data) throws -> (candidates: [ImportCandidate], unsupported: Int) {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let items = root["items"] as? [Any] else { throw CXFError.notAnAccount }
        var out = [ImportCandidate]()
        var unsupported = 0
        for raw in items {
            guard let item = raw as? [String: Any] else { unsupported += 1; continue }
            let r = map(item)
            out += r.candidates
            unsupported += r.unsupported
        }
        return (out, unsupported)
    }

    private static func map(_ item: [String: Any]) -> (candidates: [ImportCandidate], unsupported: Int) {
        let title = item["title"] as? String ?? ""
        let url = ((item["scope"] as? [String: Any])?["urls"] as? [Any])?.compactMap { $0 as? String }.first ?? ""
        let creds = (item["credentials"] as? [Any])?.compactMap { $0 as? [String: Any] } ?? []
        var basic: [String: Any]?, totp: [String: Any]?, note: [String: Any]?
        var passkeys = [[String: Any]]()
        var candidates = [ImportCandidate]()
        var unsupported = 0
        for c in creds {
            switch c["type"] as? String {
            case "basic-auth": if basic == nil { basic = c } else { unsupported += 1 }
            case "totp": if totp == nil { totp = c } else { unsupported += 1 }
            case "note": if note == nil { note = c } else { unsupported += 1 }
            case "passkey": passkeys.append(c)
            default: unsupported += 1
            }
        }
        if let basic {
            let username = fieldValue(basic["username"])
            var otpauthValue: String?
            if let totp {
                if let u = otpauth(totp, fallbackUsername: username) { otpauthValue = u } else { unsupported += 1 }
            }
            candidates.append(ImportCandidate(title: title, kind: .login(LoginFields(
                url: url, username: username, password: fieldValue(basic["password"]),
                notes: note.map { fieldValue($0["content"]) } ?? "",
                otpauth: otpauthValue))))
        } else if totp != nil || note != nil {
            unsupported += 1   // a TOTP or note with no login to attach to
        }
        for p in passkeys {
            if let f = passkey(p) { candidates.append(ImportCandidate(title: title, kind: .passkey(f))) }
            else { unsupported += 1 }
        }
        return (candidates, unsupported)
    }

    /// EditableField objects carry `value`; accept a bare string too.
    private static func fieldValue(_ v: Any?) -> String {
        if let s = v as? String { return s }
        return (v as? [String: Any])?["value"] as? String ?? ""
    }

    private static func otpauth(_ t: [String: Any], fallbackUsername: String) -> String? {
        guard let secret = t["secret"] as? String, !secret.isEmpty else { return nil }
        let period = (t["period"] as? NSNumber)?.intValue ?? 30
        let digits = (t["digits"] as? NSNumber)?.intValue ?? 6
        let algorithm = (t["algorithm"] as? String)?.uppercased() ?? "SHA1"
        let username = (t["username"] as? String) ?? fallbackUsername
        let issuer = t["issuer"] as? String ?? ""
        var allowed = CharacterSet.urlPathAllowed; allowed.remove(charactersIn: "/:?#&=%+")
        func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
        let label = issuer.isEmpty ? enc(username) : "\(enc(issuer)):\(enc(username))"
        let uri = "otpauth://totp/\(label)?secret=\(secret.uppercased())&period=\(period)&digits=\(digits)&algorithm=\(algorithm)"
        return (try? TOTP.parseOtpauthURI(uri)) == nil ? nil : uri
    }

    /// Accepts base64url or standard base64, padded or not.
    private static func b64(_ s: String, maxBytes: Int) -> [UInt8]? {
        var t = s.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while t.hasSuffix("=") { t.removeLast() }
        return decodeBase64URL(t, maxBytes: maxBytes)
    }

    private static func passkey(_ p: [String: Any]) -> PasskeyFields? {
        guard let cid = (p["credentialId"] as? String).flatMap({ b64($0, maxBytes: maxCredentialIDBytes) }),
              !cid.isEmpty,
              let rp = p["rpId"] as? String, !rp.isEmpty,
              let keyText = p["key"] as? String,
              let der = b64(keyText, maxBytes: 4096),
              PasskeyKey(pkcs8B64URL: base64URLNoPad(der)) != nil
        else { return nil }
        var handle = [UInt8]()
        if let h = p["userHandle"], !(h is NSNull) {
            guard let hs = h as? String, let d = b64(hs, maxBytes: 64) else { return nil }
            handle = d
        }
        let name = p["username"] as? String ?? p["userName"] as? String ?? ""
        return PasskeyFields(rpID: rp, userName: name,
                             userDisplayName: p["userDisplayName"] as? String ?? "",
                             userHandle: Data(handle), credentialID: Data(cid), pkcs8: Data(der))
    }
}
