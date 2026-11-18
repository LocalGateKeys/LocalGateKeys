import SwiftUI
import Observation
import LGKCore
import AppSharedMac

/// Settings › Developer (Windows Settings › Developer): the SSH agent switch, which SSH keys it offers (this Mac
/// only), the lines to paste into `~/.ssh/config`, the shell and Git (the sandboxed app can't write them), and the
/// plain-secrets scan.
@MainActor @Observable
final class DeveloperSettingsModel {
    struct KeyRow: Identifiable, Equatable {
        let id: String
        let title: String
        let fingerprint: String
        /// `type base64` without the comment, for Git's `key::`; nil when the agent can't offer the key.
        let publicKey: String?
        /// Why the agent can't offer it.
        let reason: String?
        var offered: Bool
    }

    let agent: MacSSHAgent
    let aiAgents: MacAgentGate
    private(set) var keys: [KeyRow] = []
    /// The key the Git lines name (an offered one).
    var gitKeyID: String?
    private(set) var copiedNote: String?

    init(agent: MacSSHAgent = .shared, aiAgents: MacAgentGate = .shared) { self.agent = agent; self.aiAgents = aiAgents }

    /// Settings › Developer › "Allow AI agents to use LocalGateKeys" (off by default; this Mac only).
    var aiAgentsOn: Bool {
        get { aiAgents.enabled }
        set { aiAgents.setEnabled(newValue) }
    }

    var aiAgentsTouchID: Bool {
        get { aiAgents.requireTouchID }
        set { aiAgents.setRequireTouchID(newValue) }
    }

    var aiAgentsStatusText: String {
        switch aiAgents.status {
        case .running: String(localized: "developer.agent.status.running", defaultValue: "Running")
        case .stopped: aiAgents.enabled ? String(localized: "developer.agent.status.stopped", defaultValue: "Stopped")
            : String(localized: "developer.agent.status.off", defaultValue: "Off")
        case .pathTooLong:
            String(localized: "developer.agent.status.pathTooLong",
                   defaultValue: "Not available: the socket path is longer than macOS allows (104 bytes). A shorter user name fixes this.")
        case .unavailable:
            String(localized: "developer.agents.status.unavailable",
                   defaultValue: "Not available: no app group folder, or another copy of LocalGateKeys serves it")
        }
    }

    var aiAgentsCommand: String { AgentSocketNames.addCommand }

    var agentOn: Bool {
        get { agent.enabled }
        set { agent.setEnabled(newValue); refresh() }
    }

    var statusText: String {
        switch agent.status {
        case .running: String(localized: "developer.agent.status.running", defaultValue: "Running")
        case .stopped: agent.enabled ? String(localized: "developer.agent.status.stopped", defaultValue: "Stopped")
            : String(localized: "developer.agent.status.off", defaultValue: "Off")
        case .pathTooLong:
            String(localized: "developer.agent.status.pathTooLong",
                   defaultValue: "Not available: the socket path is longer than macOS allows (104 bytes). A shorter user name fixes this.")
        case .unavailable:
            agent.socketPath == nil
                ? String(localized: "developer.agent.status.noContainer", defaultValue: "Not available in this build (no app group folder)")
                : String(localized: "developer.agent.status.unavailableMac", defaultValue: "Not available: another copy of LocalGateKeys serves the socket")
        }
    }

    /// Re-reads the vault's SSH key items (none while locked).
    func refresh() {
        let offered = Set(DeveloperSettings.offeredKeys(agent.defaults))
        keys = agent.sshItems().values.map { (item: VaultItem) -> KeyRow in
            let payload = item.record["payload"]?.objectValue ?? [:]
            let line = payload["public_key"]?.stringValue ?? ""
            // An encrypted PEM key can't be read on the Mac, even with its public half saved.
            let parsed = SSHKey.isEncryptedPEM(payload["private_key"]?.stringValue ?? "") ? nil : SSHKey.publicLineBlob(line)
            return KeyRow(id: item.id, title: item.title.isEmpty ? item.kindLabel : item.title,
                          fingerprint: payload["fingerprint"]?.stringValue ?? "",
                          publicKey: parsed.map { "\(SSHWire.blobType($0.blob)) \(Data($0.blob).base64EncodedString())" },
                          reason: parsed == nil ? Self.reason(payload) : nil, offered: offered.contains(item.id))
        }
        .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        let gitChoices = gitKeys
        if gitKeyID == nil || !gitChoices.contains(where: { $0.id == gitKeyID }) { gitKeyID = gitChoices.first?.id }
    }

    /// Windows `developer.reason.*`, for a key without a usable public half.
    static func reason(_ payload: [String: JSONValue]) -> String {
        let format = payload["key_format"]?.stringValue ?? ""
        let line = payload["public_key"]?.stringValue ?? ""
        if SSHKey.isEncryptedPEM(payload["private_key"]?.stringValue ?? "") {
            return String(localized: "developer.reason.format", defaultValue: "This key format is not supported by the agent")
        }
        if format == "putty" { return String(localized: "developer.reason.putty", defaultValue: "PuTTY (.ppk) keys are not supported by the agent") }
        if line.hasPrefix("sk-") { return String(localized: "developer.reason.sk", defaultValue: "Hardware security keys (sk-*) are not supported by the agent") }
        if format == "pem-dsa" || line.hasPrefix("ssh-dss") { return String(localized: "developer.reason.dsa", defaultValue: "DSA keys are not supported by the agent") }
        if !line.isEmpty { return String(localized: "developer.reason.type", defaultValue: "This key type is not supported by the agent") }
        let privateKey = payload["private_key"]?.stringValue ?? ""
        if privateKey.isEmpty { return String(localized: "developer.reason.no_private", defaultValue: "It has no private key") }
        // Without a passphrase nothing slow runs: an encrypted key stops at needsPassphrase.
        do {
            _ = try SSHKey.load(privateKey, passphrase: nil)
            return String(localized: "developer.err.noPublicKey", defaultValue: "This key has no public key.")
        } catch SSHKeyError.needsPassphrase {
            return String(localized: "developer.keys.needsPassphraseHint", defaultValue: "This key is encrypted. Save its passphrase with the key to offer it.")
        } catch {
            return String(localized: "developer.reason.format", defaultValue: "This key format is not supported by the agent")
        }
    }

    func setOffered(_ id: String, _ on: Bool) {
        DeveloperSettings.setOffered(id, on, defaults: agent.defaults)
        refresh()
    }

    var gitKeys: [KeyRow] { keys.filter { $0.offered && $0.publicKey != nil } }

    var identityAgentLine: String? { agent.socketPath.map { "IdentityAgent \"\($0)\"" } }

    var exportLine: String? { agent.socketPath.map { "export SSH_AUTH_SOCK=\"\($0)\"" } }

    var gitLines: String? {
        guard let key = gitKeys.first(where: { $0.id == gitKeyID })?.publicKey else { return nil }
        return ["git config --global gpg.format ssh", "git config --global user.signingkey \"key::\(key)\"",
                "git config --global commit.gpgsign true"].joined(separator: "\n")
    }

    func copy(_ text: String) {
        MacClipboard.shared.copy(text, concealed: false)
        copiedNote = String(localized: "developer.copied", defaultValue: "Copied. It contains no secret.")
    }
}

/// The rows inside the Developer card of Settings.
struct DeveloperSettingsView: View {
    @Bindable var model: DeveloperSettingsModel
    let isUnlocked: Bool
    let onScan: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            aiAgentRows
            divider
            row(String(localized: "developer.agent.title", defaultValue: "SSH agent"),
                detail: String(localized: "developer.agent.desc.mac", defaultValue: "Serves the keys you switch on below to ssh and Git on this Mac, from a private socket. Every signature asks you first. Off by default; this setting stays on this Mac.")
                    + "\n" + model.statusText) {
                Toggle("", isOn: $model.agentOn).toggleStyle(.switch).labelsHidden()
            }
            divider
            Text(String(localized: "developer.keys.title", defaultValue: "SSH keys in your vault"))
                .font(.system(size: 12, weight: .semibold)).foregroundStyle(theme.textMuted)
                .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 4)
            if !isUnlocked {
                note(MacSettingsModel.lockedMessage)
            } else if model.keys.isEmpty {
                note(String(localized: "developer.keys.empty.mac", defaultValue: "No SSH keys yet. Add one with New item › SSH key, or import one with the scan below."))
            }
            ForEach(model.keys) { key in
                row(key.title, detail: key.reason ?? key.fingerprint) {
                    Toggle(String(localized: "developer.keys.offer", defaultValue: "Offer to SSH"),
                           isOn: Binding(get: { key.offered }, set: { model.setOffered(key.id, $0) }))
                        .toggleStyle(.switch).controlSize(.small)
                        .disabled(key.publicKey == nil && !key.offered)
                }
            }
            divider
            Text(String(localized: "developer.setup.title.mac", defaultValue: "Set up this Mac"))
                .font(.system(size: 12, weight: .semibold)).foregroundStyle(theme.textMuted)
                .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 4)
            if let line = model.identityAgentLine {
                copyRow(String(localized: "developer.setup.sshConfig", defaultValue: "For ~/.ssh/config (ssh and git over SSH)"), line)
            }
            if let line = model.exportLine {
                copyRow(String(localized: "developer.setup.shell", defaultValue: "For your shell profile (ssh-keygen and Git signing read SSH_AUTH_SOCK)"), line)
            }
            if !model.gitKeys.isEmpty {
                row(String(localized: "developer.git.choose", defaultValue: "Key to sign with"), detail: nil) {
                    Picker("", selection: $model.gitKeyID) {
                        ForEach(model.gitKeys) { Text($0.title).tag(Optional($0.id)) }
                    }
                    .labelsHidden().fixedSize()
                }
            }
            if let lines = model.gitLines {
                copyRow(String(localized: "developer.git.title", defaultValue: "Git commit signing"), lines)
            } else {
                note(String(localized: "developer.git.noKey", defaultValue: "Switch on \u{201C}Offer to SSH\u{201D} for a key first."))
            }
            note(String(localized: "developer.setup.forwarding.mac", defaultValue: "Agent forwarding is not served: do not use ssh -A with this agent."))
            if let copied = model.copiedNote { note(copied) }
            divider
            row(String(localized: "developer.scan.rowTitle", defaultValue: "Scan for plain secrets"),
                detail: String(localized: "developer.scan.desc", defaultValue: "Find SSH keys and .env files stored as plain text, and import them into your vault.")) {
                Button(String(localized: "developer.scan.button", defaultValue: "Scan…"), action: onScan)
                    .buttonStyle(PillButtonStyle(primary: false)).disabled(!isUnlocked)
            }
        }
        .onAppear { model.refresh() }
        .onChange(of: isUnlocked) { _, _ in model.refresh() }
    }

    /// AI agents (Pro): the switch, Touch ID for approvals, and the command that adds `lgk mcp` to an MCP client.
    @ViewBuilder private var aiAgentRows: some View {
        row(String(localized: "developer.agents.title", defaultValue: "Allow AI agents to use LocalGateKeys"),
            detail: String(localized: "developer.agents.desc.mac", defaultValue: "AI agents such as Claude Code can ask to sign in to a site for you through lgk mcp. You approve every request here; only logins you allowed for AI agents can be used. Needs Pro. Off by default; this setting stays on this Mac.")
                + "\n" + model.aiAgentsStatusText) {
            Toggle("", isOn: $model.aiAgentsOn).toggleStyle(.switch).labelsHidden()
        }
        if model.aiAgentsOn {
            row(String(localized: "developer.agents.touchID", defaultValue: "Require Touch ID for each approval"),
                detail: String(localized: "developer.agents.touchID.desc", defaultValue: "Approve once then asks for Touch ID, or your master password when Touch ID is not available.")) {
                Toggle("", isOn: $model.aiAgentsTouchID).toggleStyle(.switch).labelsHidden()
            }
            copyRow(String(localized: "developer.agents.command", defaultValue: "Add LocalGateKeys to Claude Code (Terminal)"),
                    model.aiAgentsCommand)
            note(String(localized: "developer.agents.safari", defaultValue: "Sign-ins are filled in Safari: turn on the LocalGateKeys extension, then click the LocalGateKeys icon in the sign-in field when the agent asks."))
        }
    }

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    private func note(_ text: String) -> some View {
        Text(text).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 14).padding(.vertical, 6)
    }

    private func row<C: View>(_ title: String, detail: String?, @ViewBuilder _ control: () -> C) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13)).foregroundStyle(theme.text)
                if let detail, !detail.isEmpty {
                    Text(detail).font(.system(size: 11)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            control()
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func copyRow(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 12)).foregroundStyle(theme.text)
            HStack(alignment: .top, spacing: 8) {
                Text(text).font(.system(size: 11, design: .monospaced)).foregroundStyle(theme.textMuted)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button(String(localized: "Copy")) { model.copy(text) }.buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }
}
