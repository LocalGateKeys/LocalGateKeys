import SwiftUI
import AppKit
import LGKCore

/// The approval for an AI agent's request, in a floating panel styled like the command palette (Windows
/// `AgentApproval.svelte`). It names the agent, its program and the site, and shows the agent's purpose as a quote:
/// text the agent wrote, which cannot approve anything. "Approve once" is the only yes.
@MainActor
final class AgentApprovalPanel {
    private var window: NSPanel?

    func show(_ gate: MacAgentGate) {
        let panel = window ?? makePanel(gate)
        window = panel
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    func hide() { window?.orderOut(nil) }

    private func makePanel(_ gate: MacAgentGate) -> NSPanel {
        let panel = AgentKeyPanel(contentRect: NSRect(x: 0, y: 0, width: 460, height: 320),
                                  styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        let host = NSHostingController(rootView: AgentApprovalCard(gate: gate).macThemed())
        host.sizingOptions = [.preferredContentSize]
        panel.contentViewController = host
        return panel
    }
}

/// A titled panel that takes key focus (the master password field) without a close button.
private final class AgentKeyPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

struct AgentApprovalCard: View {
    let gate: MacAgentGate
    @State private var password = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let request = gate.pending?.request {
                content(request)
            }
        }
        .padding(20)
        .frame(width: 460, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .foregroundStyle(theme.text)
    }

    @ViewBuilder
    private func content(_ request: AgentApprovalRequest) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "sparkles").foregroundStyle(theme.accent)
            Text(request.action == .list
                 ? String(localized: "agents.approve.listTitle", defaultValue: "An AI agent asks to see your sign-in sites")
                 : String(localized: "agents.approve.signInTitle", defaultValue: "An AI agent asks to sign in for you"))
                .font(.system(size: 15, weight: .semibold))
        }
        VStack(alignment: .leading, spacing: 4) {
            row(String(localized: "agents.approve.agent", defaultValue: "Agent"), request.agent)
            row(String(localized: "agents.approve.program", defaultValue: "Program"),
                request.process.isEmpty ? String(localized: "ssh_agent.unknownProgram", defaultValue: "a program") : request.process)
            if request.action == .signIn {
                row(String(localized: "agents.approve.site", defaultValue: "Site"), request.site)
            }
        }
        if request.action == .signIn {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "agents.approve.purposeLabel", defaultValue: "The agent's reason, in its own words:"))
                    .font(.system(size: 12)).foregroundStyle(theme.textMuted)
                Text(verbatim: "\u{201C}\(request.purpose.isEmpty ? "…" : request.purpose)\u{201D}")
                    .font(.system(size: 13).italic()).textSelection(.disabled).lineLimit(6)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        Text(explanation(request)).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            .fixedSize(horizontal: false, vertical: true)
        if gate.needsPassword {
            SecureField(String(localized: "Master password"), text: $password).glassField().onSubmit(approve)
        }
        if let message = gate.message {
            Text(message).font(.system(size: 12.5)).foregroundStyle(theme.danger)
        }
        HStack {
            Spacer()
            Button(String(localized: "agents.approve.deny", defaultValue: "Deny")) { gate.deny() }
                .keyboardShortcut(.cancelAction)
            // Never the default button: Return alone does not approve.
            Button(String(localized: "agents.approve.once", defaultValue: "Approve once"), action: approve)
                .disabled(gate.busy || (gate.needsPassword && password.isEmpty))
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label).font(.system(size: 12)).foregroundStyle(theme.textMuted).frame(width: 64, alignment: .leading)
            Text(verbatim: value).font(.system(size: 13, weight: .medium)).lineLimit(2)
        }
    }

    private func explanation(_ request: AgentApprovalRequest) -> String {
        switch (request.action, request.method) {
        case (.list, _):
            String(localized: "agents.approve.listBody",
                   defaultValue: "It sees the titles and domains of the logins you allowed for AI agents, never user names or passwords. You allow this once for this agent session.")
        case (.signIn, .passkey):
            String(localized: "agents.approve.passkeyBody",
                   defaultValue: "This login uses a passkey: no password is filled. Choose the site's passkey sign-in and confirm it in the passkey dialog.")
        case (.signIn, .password):
            String(localized: "agents.approve.passwordBody",
                   defaultValue: "Approve once allows one sign-in in the next 5 minutes. Then click the LocalGateKeys icon in the site's sign-in field and pick the login: the page receives the password, where the page and browser automation can read it.")
        }
    }

    private func approve() {
        let typed = password
        password = ""
        Task { await gate.approve(password: typed) }
    }
}
