import SwiftUI
import LGKCore
import AppSharedMac

/// Three random word positions the user types back before a new phrase is saved (Windows
/// `RecoveryPhraseChallenge`). Only the challenged words are kept, normalised like the phrase (NFKD, casefold, trimmed).
struct RecoveryPhraseChallenge {
    static let wordsToConfirm = 3
    /// 1-based, sorted.
    let positions: [Int]
    private let expected: [[UInt8]]

    init(phrase: String) throws {
        let words = phrase.split(whereSeparator: \.isWhitespace).map(String.init)
        guard words.count == BIP39.wordCount else { throw RecoveryPhraseError(String(localized: "A recovery phrase has exactly 24 words")) }
        var remaining = Array(1...words.count)
        var picks: [Int] = []
        for _ in 0..<Self.wordsToConfirm { picks.append(remaining.remove(at: Int.random(in: 0..<remaining.count))) }
        positions = picks.sorted()
        expected = positions.map { Self.normalise(words[$0 - 1]) }
    }

    static func normalise(_ word: String) -> [UInt8] {
        Array(Casefold.fold(word.decomposedStringWithCompatibilityMapping).trimmingCharacters(in: .whitespacesAndNewlines).utf8)
    }

    /// True when every answer matches its word; every word is compared in full (no early exit).
    func verify(_ answers: [String]) -> Bool {
        guard answers.count == positions.count else { return false }
        var matched = true
        for (want, answer) in zip(expected, answers.map(Self.normalise)) {
            var diff = want.count ^ answer.count
            for i in 0..<max(want.count, answer.count) {
                diff |= Int((i < want.count ? want[i] : 0) ^ (i < answer.count ? answer[i] : 0))
            }
            if diff != 0 { matched = false }
        }
        return matched
    }
}

/// Settings › Unlocking › Recovery phrase: the master password, then the 24 words (shown once, never copied or
/// stored), then three of them typed back; only then is the phrase saved. Copy from Windows `app/recovery.py`.
struct RecoveryPhraseSheet: View {
    static let intro = String(localized: "A 24-word recovery phrase can replace a forgotten master password. It is shown once, never stored by LocalGateKeys, and replaces any earlier phrase.")
    static let cardIntro = String(localized: "Write these 24 words down in order and keep them sealed, away from this Mac and your backups. Anyone with the phrase can open the vault. It is shown only now; LocalGateKeys does not store it and cannot show it again.")
    static let mismatch = String(localized: "Those words do not match the phrase in that order. Check your written copy and try again, or go back to the phrase.")
    static let confirmed = String(localized: "Recovery phrase confirmed. Keep the written copy sealed and separate from your backups; it is not stored anywhere by LocalGateKeys.")
    static let removeIntro = String(localized: "The recovery phrase will no longer open this vault. Backups made while it was set still open with it.")

    enum Mode { case create, remove }
    private enum Step { case password, words, confirm, done }

    let passwords: any MasterPasswordService
    let mode: Mode
    let onClose: () -> Void
    @Environment(\.macTheme) private var theme
    @State private var step = Step.password
    @State private var password = ""
    @State private var prepared: MacVault.PreparedRecovery?
    @State private var challenge: RecoveryPhraseChallenge?
    @State private var answers = ["", "", ""]
    @State private var message: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: MacTheme.gap) {
            Text(mode == .remove ? String(localized: "Remove recovery phrase") : String(localized: "Recovery phrase"))
                .font(.title3.weight(.semibold)).foregroundStyle(theme.text)
            switch step {
            case .password: passwordStep
            case .words: wordsStep
            case .confirm: confirmStep
            case .done:
                note(mode == .remove ? MacLockModel.phraseRemovedText : Self.confirmed)
                HStack { Spacer(); Button("Done", action: close).buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction) }
            }
        }
        .disabled(busy)
        .padding(24).frame(width: step == .words ? 520 : 400)
        .background(WashBackground())
        .onDisappear(perform: forget)
    }

    private var passwordStep: some View {
        Group {
            note(mode == .remove ? Self.removeIntro : Self.intro)
            SecureField("Master password", text: $password).glassField().onSubmit(submitPassword)
            MessageLine(text: message)
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(action: submitPassword) {
                    if busy { ProgressView().controlSize(.small) } else { Text(mode == .remove ? String(localized: "Remove") : String(localized: "Continue")) }
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(busy || password.isEmpty)
            }
        }
    }

    private var wordsStep: some View {
        Group {
            note(Self.cardIntro)
            let words = (prepared?.phrase ?? "").split(separator: " ").map(String.init)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), alignment: .leading), count: 4), spacing: 8) {
                ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                    HStack(spacing: 6) {
                        Text("\(index + 1).").font(.callout.monospacedDigit()).foregroundStyle(theme.textMuted)
                            .frame(width: 26, alignment: .trailing)
                        Text(word).font(.body.monospaced()).foregroundStyle(theme.text).textSelection(.disabled)
                    }
                }
            }
            .privacySensitive()
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 10).fill(theme.panelBorder.opacity(0.25)))
            HStack {
                Button("Cancel", action: close).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("I've written it down") {
                    answers = ["", "", ""]; message = nil
                    challenge = try? RecoveryPhraseChallenge(phrase: prepared?.phrase ?? "")
                    step = .confirm
                }
                .buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
            }
        }
    }

    private var confirmStep: some View {
        Group {
            note(String(localized: "Type these words from your written copy to confirm it."))
            ForEach(Array((challenge?.positions ?? []).enumerated()), id: \.offset) { index, position in
                TextField("Word \(position)", text: $answers[index]).glassField().autocorrectionDisabled()
            }
            MessageLine(text: message)
            HStack {
                Button("Back to the phrase") { message = nil; step = .words }.buttonStyle(GlassButtonStyle())
                Spacer()
                Button("Confirm", action: submitConfirm).buttonStyle(AccentButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(answers.contains { $0.trimmingCharacters(in: .whitespaces).isEmpty })
            }
        }
    }

    private func note(_ text: String) -> some View {
        Text(text).font(.callout).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
    }

    private func submitPassword() {
        guard !busy, !password.isEmpty else { return }
        let attempt = password, service = passwords, mode = self.mode
        busy = true; message = nil
        Task {
            defer { busy = false }
            do {
                if mode == .remove {
                    try await service.removeRecoveryPhrase(password: attempt)
                    step = .done
                } else {
                    prepared = try await service.prepareRecoveryPhrase(password: attempt)
                    step = .words
                }
                password = ""
            } catch is CancellationError {
                close()
            } catch {
                password = ""
                message = MacLockModel.describe(error, now: Date())
            }
        }
    }

    private func submitConfirm() {
        guard let challenge, let prepared else { return }
        guard challenge.verify(answers) else { message = Self.mismatch; return }
        let service = passwords
        busy = true
        Task {
            defer { busy = false }
            do {
                try await service.confirmRecoveryPhrase(prepared)
                forget()
                step = .done
            } catch is CancellationError {
                close()
            } catch {
                message = MacLockModel.describe(error, now: Date())
            }
        }
    }

    /// Drops the phrase and the typed words (Swift strings cannot be zeroed; this is the most that can be done).
    private func forget() {
        prepared = nil; challenge = nil; answers = ["", "", ""]; password = ""
    }

    private func close() { forget(); onClose() }
}
