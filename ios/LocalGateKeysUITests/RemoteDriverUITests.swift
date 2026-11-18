import XCTest

/// A remote-controlled UI session for checks that need two simulators at once (Wi-Fi sync between two iPhones,
/// updates over an older build). It runs only with `LGK_REMOTE_DIR` set (pass `TEST_RUNNER_LGK_REMOTE_DIR=<dir>` to
/// `xcodebuild test`): it then reads commands from `<dir>/cmd.<n>` (n = 1, 2, …), one per file, runs each and writes
/// `<dir>/res.<n>`. Screenshots are written to `<dir>/<name>.png`. One command per file, words split by tabs:
///   launch [arg…] [ENV:KEY=VALUE…]   launch the app (fresh process) with these arguments and environment
///   activate | terminate            bring the app forward / end it
///   target <bundle id>              later commands act on this app (`app` for LocalGateKeys)
///   tap <label> [index]             tap the element whose label is <label> (`~x` begins with x, `P:fmt` predicate)
///   tapxy <x> <y>                   tap at a normalised point of the target app
///   type <text>                     type into the focused field (`\n` for return)
///   field <n>                       tap the n-th text field, secure field or text view
///   wait <label> [seconds]          wait for the element; res says found or missing
///   labels | tree | shot <name>     list the labels / write the element tree / write a screenshot
///   swipe <up|down|left|right> | home | sleep <s> | quit
final class RemoteDriverUITests: XCTestCase {
    private var dir: URL!
    private var target: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = true
        let path = ProcessInfo.processInfo.environment["LGK_REMOTE_DIR"]
        try XCTSkipUnless(path != nil, "remote-controlled session only")
        dir = URL(fileURLWithPath: path!)
        executionTimeAllowance = 6 * 3600
    }

    @MainActor
    private func element(_ spec: String, _ index: Int = 0) -> XCUIElement {
        let predicate: NSPredicate
        if spec.hasPrefix("P:") {
            predicate = NSPredicate(format: String(spec.dropFirst(2)))
        } else if spec.hasPrefix("~") {
            predicate = NSPredicate(format: "label BEGINSWITH %@", String(spec.dropFirst()))
        } else {
            predicate = NSPredicate(format: "label == %@ OR identifier == %@", spec, spec)
        }
        return target.descendants(matching: .any).matching(predicate).element(boundBy: index)
    }

    @MainActor
    private func labels() -> String {
        guard let snap = try? target.snapshot() else { return "(no snapshot)" }
        var out: [String] = []
        func walk(_ s: XCUIElementSnapshot) {
            if !s.label.isEmpty || s.value != nil {
                let f = s.frame
                let value = (s.value as? String).map { " value=\($0)" } ?? ""
                out.append("\(s.elementType.rawValue)\t\(s.label)\(value)\t\(Int(f.minX)),\(Int(f.minY)),\(Int(f.width))x\(Int(f.height))")
            }
            s.children.forEach(walk)
        }
        walk(snap)
        return out.joined(separator: "\n")
    }

    @MainActor
    private func run(_ words: [String]) -> String {
        guard let op = words.first else { return "empty" }
        let arg = words.count > 1 ? words[1] : ""
        switch op {
        case "launch":
            let app = XCUIApplication()
            for w in words.dropFirst() {
                if w.hasPrefix("ENV:"), let eq = w.firstIndex(of: "=") {
                    app.launchEnvironment[String(w[w.index(w.startIndex, offsetBy: 4)..<eq])] = String(w[w.index(after: eq)...])
                } else {
                    app.launchArguments.append(w)
                }
            }
            app.launch()
            target = app
            return "launched"
        case "activate": target.activate(); return "activated"
        case "terminate": target.terminate(); return "terminated"
        case "target":
            target = arg == "app" ? XCUIApplication() : XCUIApplication(bundleIdentifier: arg)
            return "target \(arg)"
        case "tap":
            let e = element(arg, words.count > 2 ? Int(words[2]) ?? 0 : 0)
            guard e.waitForExistence(timeout: 5) else { return "missing \(arg)" }
            e.tap()
            return "tapped \(arg)"
        case "tapxy":
            let x = Double(words[1]) ?? 0.5, y = Double(words[2]) ?? 0.5
            target.coordinate(withNormalizedOffset: CGVector(dx: x, dy: y)).tap()
            return "tapped \(x),\(y)"
        case "type":
            // typeText without a focused field raises and would end the session.
            let focused = target.descendants(matching: .any).matching(NSPredicate(format: "hasKeyboardFocus == true")).firstMatch
            guard focused.exists else { return "nofocus" }
            focused.typeText(arg.replacingOccurrences(of: "\\n", with: "\n"))
            return "typed"
        case "field":
            // field <n>: tap the n-th text field, secure field or text view (in that order).
            let fields = target.descendants(matching: .any).matching(NSPredicate(format: "elementType IN %@",
                [XCUIElement.ElementType.textField.rawValue, XCUIElement.ElementType.secureTextField.rawValue,
                 XCUIElement.ElementType.textView.rawValue]))
            let e = fields.element(boundBy: Int(arg) ?? 0)
            guard e.waitForExistence(timeout: 5) else { return "missing field \(arg) of \(fields.count)" }
            e.tap()
            return "tapped field \(arg) of \(fields.count)"
        case "wait":
            let t = words.count > 2 ? Double(words[2]) ?? 10 : 10
            return element(arg).waitForExistence(timeout: t) ? "found \(arg)" : "missing \(arg)"
        case "labels": return labels()
        case "tree": return target.debugDescription
        case "shot":
            let png = XCUIScreen.main.screenshot().pngRepresentation
            try? png.write(to: dir.appendingPathComponent("\(arg).png"))
            let a = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
            a.name = arg; a.lifetime = .keepAlways
            add(a)
            return "shot \(arg)"
        case "swipe":
            switch arg {
            case "up": target.swipeUp()
            case "down": target.swipeDown()
            case "left": target.swipeLeft()
            default: target.swipeRight()
            }
            return "swiped \(arg)"
        case "home": XCUIDevice.shared.press(.home); return "home"
        case "sleep": sleep(UInt32(Int(arg) ?? 1)); return "slept"
        default: return "unknown \(op)"
        }
    }

    @MainActor
    func testRemoteSession() throws {
        target = XCUIApplication()
        // A session restarted after a failure goes on after the last answered command; the command that ended
        // the previous session is answered as crashed.
        let fm = FileManager.default
        var n = 1
        while fm.fileExists(atPath: dir.appendingPathComponent("res.\(n)").path) { n += 1 }
        if fm.fileExists(atPath: dir.appendingPathComponent("cmd.\(n)").path) {
            try? "crashed (session restarted)".write(to: dir.appendingPathComponent("res.\(n)"), atomically: true, encoding: .utf8)
            n += 1
        }
        let deadline = Date().addingTimeInterval(6 * 3600)
        while Date() < deadline {
            let cmd = dir.appendingPathComponent("cmd.\(n)")
            guard let text = try? String(contentsOf: cmd, encoding: .utf8) else {
                usleep(200_000)
                continue
            }
            let words = text.trimmingCharacters(in: .newlines).components(separatedBy: "\t")
            if words.first == "quit" {
                try? "bye".write(to: dir.appendingPathComponent("res.\(n)"), atomically: true, encoding: .utf8)
                return
            }
            let result = run(words)
            try? result.write(to: dir.appendingPathComponent("res.\(n)"), atomically: true, encoding: .utf8)
            n += 1
        }
    }
}
