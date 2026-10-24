#if DEBUG
import SwiftUI
import AppShared

/// DEBUG builds only (Settings › Developer): the AutoFill extension's trace from the app group
/// (`Diagnostics/autofill-trace.log`), newest at the bottom. Holds no secrets (`AutoFillTrace`).
struct AutoFillTraceView: View {
    let writer: AutoFillTraceWriter
    @State private var text = ""

    init(writer: AutoFillTraceWriter = .shared) { self.writer = writer }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Text(text.isEmpty ? "No trace yet. Use AutoFill in Safari, then come back." : text)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                Color.clear.frame(height: 1).id("end")
            }
            .onAppear { reload(); proxy.scrollTo("end", anchor: .bottom) }
            .refreshable { reload() }
        }
        .navigationTitle("AutoFill trace")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button("Clear") { writer.clear(); reload() }
                ShareLink(item: text.isEmpty ? "(empty AutoFill trace)" : text) { Label("Share", systemImage: "square.and.arrow.up") }
            }
        }
    }

    private func reload() { text = writer.read() }
}
#endif
