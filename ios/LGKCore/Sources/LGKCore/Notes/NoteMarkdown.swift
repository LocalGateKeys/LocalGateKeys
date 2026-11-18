import Foundation

/*
 * The Markdown subset for notes (display only). The grammar and the node shapes are pinned by
 * tests/vectors/markdown/cases.json and described in tests/vectors/markdown/README.md; this is a port of
 * webui/src/lib/markdown.js (and of the Kotlin NoteMarkdown) and must return the same nodes for every case.
 * Nothing here produces HTML or links. Text is handled as UTF-16 units so indices and lengths match JS and Kotlin.
 */

/// A block node. Decodes from the vector JSON (`{t:"h",level,c}`, `{t:"ul",items}`, ...).
public enum MDNode: Equatable, Sendable {
    case heading(level: Int, content: [MDInline])
    case paragraph([MDInline])
    case bullets([[MDInline]])
    /// Numbers are not kept: renderers number the items 1, 2, 3...
    case numbered([[MDInline]])
    case todos([MDTodoItem])
    case codeBlock(String)
    case rule
}

public struct MDTodoItem: Equatable, Sendable {
    public let done: Bool
    public let content: [MDInline]

    public init(done: Bool, content: [MDInline]) {
        self.done = done
        self.content = content
    }
}

/// An inline node. Empty `text` nodes are never emitted and adjacent ones are merged.
public enum MDInline: Equatable, Sendable {
    case text(String)
    case bold([MDInline])
    case italic([MDInline])
    case code(String)
    /// Shown as "text (url)", never clickable; kept even for `javascript:` URLs.
    case link(text: String, url: String)
}

// MARK: decoding the vector JSON

extension MDTodoItem: Decodable {
    private enum Keys: String, CodingKey { case done, c }

    public init(from decoder: Decoder) throws {
        let k = try decoder.container(keyedBy: Keys.self)
        self.init(done: try k.decode(Bool.self, forKey: .done), content: try k.decode([MDInline].self, forKey: .c))
    }
}

extension MDInline: Decodable {
    private enum Keys: String, CodingKey { case t, v, c, text, url }

    public init(from decoder: Decoder) throws {
        let k = try decoder.container(keyedBy: Keys.self)
        switch try k.decode(String.self, forKey: .t) {
        case "text": self = .text(try k.decode(String.self, forKey: .v))
        case "b": self = .bold(try k.decode([MDInline].self, forKey: .c))
        case "i": self = .italic(try k.decode([MDInline].self, forKey: .c))
        case "code": self = .code(try k.decode(String.self, forKey: .v))
        case "link": self = .link(text: try k.decode(String.self, forKey: .text), url: try k.decode(String.self, forKey: .url))
        default: throw DecodingError.dataCorruptedError(forKey: .t, in: k, debugDescription: "unknown inline node")
        }
    }
}

extension MDNode: Decodable {
    private enum Keys: String, CodingKey { case t, level, c, items, text }

    public init(from decoder: Decoder) throws {
        let k = try decoder.container(keyedBy: Keys.self)
        switch try k.decode(String.self, forKey: .t) {
        case "h": self = .heading(level: try k.decode(Int.self, forKey: .level), content: try k.decode([MDInline].self, forKey: .c))
        case "p": self = .paragraph(try k.decode([MDInline].self, forKey: .c))
        case "ul": self = .bullets(try k.decode([[MDInline]].self, forKey: .items))
        case "ol": self = .numbered(try k.decode([[MDInline]].self, forKey: .items))
        case "todo": self = .todos(try k.decode([MDTodoItem].self, forKey: .items))
        case "code": self = .codeBlock(try k.decode(String.self, forKey: .text))
        case "hr": self = .rule
        default: throw DecodingError.dataCorruptedError(forKey: .t, in: k, debugDescription: "unknown block node")
        }
    }
}

// MARK: the parser

public enum NoteMarkdown {
    /// Longer text is not parsed: it comes back as one paragraph (UTF-16 units).
    public static let maxChars = 20000

    private enum Kind { case todo, ul, ol }

    private struct Item {
        let kind: Kind
        let done: Bool
        let text: [UInt16]
    }

    /// The list being collected; it becomes a node when the list ends.
    private struct PendingList {
        let kind: Kind
        var plain: [[MDInline]] = []
        var todos: [MDTodoItem] = []

        init(kind: Kind) { self.kind = kind }

        func node() -> MDNode {
            switch kind {
            case .todo: return .todos(todos)
            case .ul: return .bullets(plain)
            case .ol: return .numbered(plain)
            }
        }
    }

    // ASCII markers as UTF-16 units.
    private static let nl: UInt16 = 10
    private static let tab: UInt16 = 9
    private static let space: UInt16 = 32
    private static let tick: UInt16 = 0x60
    private static let star: UInt16 = 0x2A
    private static let hash: UInt16 = 0x23
    private static let openBracket: UInt16 = 0x5B
    private static let closeBracket: UInt16 = 0x5D
    private static let openParen: UInt16 = 0x28
    private static let closeParen: UInt16 = 0x29
    private static let fence: [UInt16] = [0x60, 0x60, 0x60]
    private static let rulePattern: [UInt16] = [0x2D, 0x2D, 0x2D]
    private static let todoOpen: [UInt16] = [0x2D, 0x20, 0x5B, 0x20, 0x5D, 0x20]   // "- [ ] "
    private static let todoDoneLower: [UInt16] = [0x2D, 0x20, 0x5B, 0x78, 0x5D, 0x20]   // "- [x] "
    private static let todoDoneUpper: [UInt16] = [0x2D, 0x20, 0x5B, 0x58, 0x5D, 0x20]   // "- [X] "
    private static let dashSpace: [UInt16] = [0x2D, 0x20]
    private static let starSpace: [UInt16] = [0x2A, 0x20]
    private static let dotSpace: [UInt16] = [0x2E, 0x20]
    private static let doubleStar: [UInt16] = [0x2A, 0x2A]
    private static let singleStar: [UInt16] = [0x2A]

    /// Text -> block nodes. Never fails; any input gives a node list.
    public static func parse(_ text: String) -> [MDNode] {
        // \r\n and lone \r become \n.
        let raw = Array(text.utf16)
        var src: [UInt16] = []
        src.reserveCapacity(raw.count)
        var r = 0
        while r < raw.count {
            if raw[r] == 13 {
                src.append(nl)
                if r + 1 < raw.count && raw[r + 1] == nl { r += 1 }
            } else {
                src.append(raw[r])
            }
            r += 1
        }
        if src.count > maxChars { return [.paragraph([.text(string(src))])] }
        let lines = split(src)
        var out: [MDNode] = []
        var para: [[UInt16]] = []
        var list: PendingList?

        func flushPara() {
            if !para.isEmpty { out.append(.paragraph(parseInline(joinLines(para)))) }
            para.removeAll()
        }
        func flushList() {
            if let l = list { out.append(l.node()) }
            list = nil
        }

        var i = 0
        while i < lines.count {
            let line = lines[i]
            if startsWith(line, fence, at: 0) {
                flushPara()
                flushList()
                var body: [[UInt16]] = []
                i += 1
                while i < lines.count && !startsWith(lines[i], fence, at: 0) {
                    body.append(lines[i])
                    i += 1
                }
                out.append(.codeBlock(string(joinLines(body))))
                i += 1 // the closing fence line (or past the end when unclosed)
                continue
            }
            if isBlank(line) { flushPara(); flushList(); i += 1; continue }
            if line == rulePattern { flushPara(); flushList(); out.append(.rule); i += 1; continue }
            let level = headingLevel(line)
            if level > 0 {
                let rest = trim(Array(line[(level + 1)...]))
                if !rest.isEmpty {
                    flushPara()
                    flushList()
                    out.append(.heading(level: level, content: parseInline(rest)))
                    i += 1
                    continue
                }
            }
            if let item = listItem(line) {
                flushPara()
                let content = parseInline(trim(item.text))
                if list?.kind != item.kind {
                    flushList()
                    list = PendingList(kind: item.kind)
                }
                if item.kind == .todo {
                    list?.todos.append(MDTodoItem(done: item.done, content: content))
                } else {
                    list?.plain.append(content)
                }
                i += 1
                continue
            }
            flushList()
            para.append(line)
            i += 1
        }
        flushPara()
        flushList()
        return out
    }

    // MARK: helpers

    private static func string(_ units: [UInt16]) -> String { String(decoding: units, as: UTF16.self) }

    private static func joinLines(_ lines: [[UInt16]]) -> [UInt16] {
        var joined: [UInt16] = []
        for (n, l) in lines.enumerated() {
            if n > 0 { joined.append(nl) }
            joined.append(contentsOf: l)
        }
        return joined
    }

    /// Split on `\n`; a trailing `\n` leaves a final empty line.
    private static func split(_ s: [UInt16]) -> [[UInt16]] {
        var lines: [[UInt16]] = []
        var cur: [UInt16] = []
        for u in s {
            if u == nl {
                lines.append(cur)
                cur = []
            } else {
                cur.append(u)
            }
        }
        lines.append(cur)
        return lines
    }

    private static func startsWith(_ s: [UInt16], _ prefix: [UInt16], at: Int) -> Bool {
        if at < 0 || at + prefix.count > s.count { return false }
        for k in 0..<prefix.count where s[at + k] != prefix[k] { return false }
        return true
    }

    private static func isBlank(_ line: [UInt16]) -> Bool { line.allSatisfy { $0 == space || $0 == tab } }

    private static func trim(_ s: [UInt16]) -> [UInt16] {
        var a = 0
        var b = s.count
        while a < b && (s[a] == space || s[a] == tab) { a += 1 }
        while b > a && (s[b - 1] == space || s[b - 1] == tab) { b -= 1 }
        return Array(s[a..<b])
    }

    private static func isSpace(_ c: UInt16) -> Bool { c == space || c == tab || c == nl }

    /// 1-3 when the line starts with that many `#` and then a space, else 0. A line holding U+2028 or U+2029 is never
    /// a heading: the reference parser's regex `.` does not match them (tests/vectors/markdown/README.md).
    private static func headingLevel(_ line: [UInt16]) -> Int {
        if line.contains(0x2028) || line.contains(0x2029) { return 0 }
        var n = 0
        while n < line.count && line[n] == hash { n += 1 }
        return (n >= 1 && n <= 3 && n < line.count && line[n] == space) ? n : 0
    }

    private static func listItem(_ line: [UInt16]) -> Item? {
        if startsWith(line, todoOpen, at: 0) { return Item(kind: .todo, done: false, text: Array(line[6...])) }
        if startsWith(line, todoDoneLower, at: 0) || startsWith(line, todoDoneUpper, at: 0) {
            return Item(kind: .todo, done: true, text: Array(line[6...]))
        }
        if startsWith(line, dashSpace, at: 0) || startsWith(line, starSpace, at: 0) {
            return Item(kind: .ul, done: false, text: Array(line[2...]))
        }
        var n = 0
        while n < line.count && line[n] >= 0x30 && line[n] <= 0x39 { n += 1 }
        if n > 0 && startsWith(line, dotSpace, at: n) { return Item(kind: .ol, done: false, text: Array(line[(n + 2)...])) }
        return nil
    }

    // MARK: inline

    // One pass over an inline run: where code spans and links start and end, so no scan ever repeats.
    // skip[i] = index just past the code span or link that starts at i (0 = none); linkK[i] = the link's ']'.
    private struct Spans {
        let skip: [Int]
        let linkK: [Int]
    }

    private static func analyze(_ s: [UInt16]) -> Spans {
        let n = s.count
        var skip = [Int](repeating: 0, count: n + 1)
        var linkK = [Int](repeating: 0, count: n + 1)
        var nextTick = [Int](repeating: -1, count: n + 2)
        var nextClose = [Int](repeating: -1, count: n + 2)
        var nextSpace = [Int](repeating: -1, count: n + 2)
        var nextNewline = [Int](repeating: -1, count: n + 2)
        var bal = [Int](repeating: 0, count: n + 1)
        var back = n - 1
        while back >= 0 {
            let c = s[back]
            nextTick[back] = c == tick ? back : nextTick[back + 1]
            nextClose[back] = c == closeBracket ? back : nextClose[back + 1]
            nextSpace[back] = isSpace(c) ? back : nextSpace[back + 1]
            nextNewline[back] = c == nl ? back : nextNewline[back + 1]
            back -= 1
        }
        for i in 0..<n {
            bal[i + 1] = bal[i] + (s[i] == openParen ? 1 : (s[i] == closeParen ? -1 : 0))
        }
        // unbalanced[p] = index of the first ')' at or after p that no '(' at or after p balances, or -1.
        var unbalanced = [Int](repeating: -1, count: n + 1)
        var firstAt: [Int: Int] = [:]
        var p = n
        while p >= 0 {
            if let x = firstAt[bal[p] - 1] { unbalanced[p] = x - 1 }
            firstAt[bal[p]] = p
            p -= 1
        }
        for i in 0..<n {
            if s[i] == tick {
                let j = nextTick[i + 1]
                if j > i + 1 { skip[i] = j + 1 }
            } else if s[i] == openBracket {
                let k = nextClose[i + 1]
                if k < 0 || k == i + 1 || k + 1 >= n || s[k + 1] != openParen { continue }
                let nlIndex = nextNewline[i + 1]
                if nlIndex >= 0 && nlIndex < k { continue }
                let start = k + 2
                let j = unbalanced[start]
                let w = nextSpace[start]
                if j < 0 || j == start || (w >= 0 && w < j) { continue }
                skip[i] = j + 1
                linkK[i] = k
            }
        }
        return Spans(skip: skip, linkK: linkK)
    }

    // closer[j] = index of the closing marker at or after j, skipping code spans and links; -1 if none. A closer
    // must follow a non-space character. While looking for "*", a "**" pair is skipped as a unit. The scan's steps
    // do not depend on where it started, so the answer from every position is computed once.
    private static func closers(_ s: [UInt16], _ skip: [Int], _ marker: [UInt16]) -> [Int] {
        let n = s.count
        var res = [Int](repeating: -1, count: n + 3)
        var j = n - 1
        while j >= 0 {
            if skip[j] > 0 {
                res[j] = res[skip[j]]
            } else if marker.count == 1 && startsWith(s, doubleStar, at: j) {
                res[j] = res[j + 2]
            } else {
                res[j] = (j > 0 && startsWith(s, marker, at: j) && !isSpace(s[j - 1])) ? j : res[j + 1]
            }
            j -= 1
        }
        return res
    }

    private static func parseInline(_ s: [UInt16]) -> [MDInline] {
        var out: [MDInline] = []
        var buf: [UInt16] = []
        func flush() {
            if !buf.isEmpty { out.append(.text(string(buf))) }
            buf.removeAll(keepingCapacity: true)
        }
        let spans = analyze(s)
        let skip = spans.skip
        var boldTable: [Int]?
        var italicTable: [Int]?
        func closeAt(_ from: Int, double: Bool) -> Int {
            let table: [Int]
            if double {
                if boldTable == nil { boldTable = closers(s, skip, doubleStar) }
                table = boldTable ?? []
            } else {
                if italicTable == nil { italicTable = closers(s, skip, singleStar) }
                table = italicTable ?? []
            }
            // The opener itself is never the closer: continue from its own step.
            let next: Int
            if skip[from] > 0 {
                next = skip[from]
            } else if !double && startsWith(s, doubleStar, at: from) {
                next = from + 2
            } else {
                next = from + 1
            }
            return table[next]
        }
        var i = 0
        while i < s.count {
            let c = s[i]
            if c == tick {
                if skip[i] > 0 {
                    flush()
                    out.append(.code(string(Array(s[(i + 1)..<(skip[i] - 1)]))))
                    i = skip[i]
                    continue
                }
            } else if c == openBracket {
                if skip[i] > 0 {
                    flush()
                    let k = spans.linkK[i]
                    out.append(.link(text: string(Array(s[(i + 1)..<k])), url: string(Array(s[(k + 2)..<(skip[i] - 1)]))))
                    i = skip[i]
                    continue
                }
            } else if c == star {
                let double = startsWith(s, doubleStar, at: i)
                let width = double ? 2 : 1
                let open = i + width
                if open < s.count && !isSpace(s[open]) {
                    let close = closeAt(open, double: double)
                    if close > 0 {
                        flush()
                        let inner = parseInline(Array(s[open..<close]))
                        out.append(double ? .bold(inner) : .italic(inner))
                        i = close + width
                        continue
                    }
                }
            }
            buf.append(c)
            i += 1
        }
        flush()
        return out
    }
}
