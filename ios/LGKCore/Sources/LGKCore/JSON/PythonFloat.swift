/// Formats a finite Double exactly like Python 3's `repr(float)`.
enum PythonFloat {
    static func repr(_ value: Double) -> String {
        precondition(value.isFinite)
        var text = value.description          // shortest round-trip digits
        var negative = false
        if text.hasPrefix("-") { negative = true; text.removeFirst() }

        // Split Swift's text into significant digits and a scientific exponent.
        var mantissa = Substring(text)
        var exp = 0
        if let e = text.firstIndex(where: { $0 == "e" || $0 == "E" }) {
            mantissa = text[text.startIndex..<e]
            exp = Int(text[text.index(after: e)...].replacingPlus())!
        }
        var intPart = mantissa
        var fracPart = Substring("")
        if let dot = mantissa.firstIndex(of: ".") {
            intPart = mantissa[mantissa.startIndex..<dot]
            fracPart = mantissa[mantissa.index(after: dot)...]
        }
        var digits = Array(intPart + fracPart)
        var pointPos = intPart.count + exp      // decimal point position relative to digits
        // Strip leading zeros.
        while digits.count > 1, digits.first == "0" { digits.removeFirst(); pointPos -= 1 }
        // Strip trailing zeros.
        while digits.count > 1, digits.last == "0" { digits.removeLast() }
        if digits == ["0"] { return (negative ? "-" : "") + "0.0" }

        let sciExp = pointPos - 1
        var out = negative ? "-" : ""
        if sciExp < -4 || sciExp >= 16 {
            out.append(digits[0])
            if digits.count > 1 { out.append("."); out.append(contentsOf: digits[1...]) }
            out.append("e")
            out.append(sciExp < 0 ? "-" : "+")
            let mag = String(abs(sciExp))
            out.append(mag.count < 2 ? "0" + mag : mag)
        } else if pointPos <= 0 {
            out += "0." + String(repeating: "0", count: -pointPos) + String(digits)
        } else if pointPos >= digits.count {
            out += String(digits) + String(repeating: "0", count: pointPos - digits.count) + ".0"
        } else {
            out += String(digits[0..<pointPos]) + "." + String(digits[pointPos...])
        }
        return out
    }
}

private extension Substring {
    func replacingPlus() -> String { hasPrefix("+") ? String(dropFirst()) : String(self) }
}
