using System.Runtime.InteropServices;
using LocalGateKeys.PasskeyProvider.Com;
using System.Globalization;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Diagnostics;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider;

/// <summary>
/// Entry point (see <see cref="Cli"/>). MTA: the COM server must take <c>CancelOperation</c> while a ceremony
/// call is still waiting on another thread.
/// </summary>
internal static partial class Program
{
    private const uint AttachParentProcess = unchecked((uint)-1);

    [MTAThread]
    private static int Main(string[] args)
    {
        var com = Cli.IsComActivation(args);
        // First thing: one line saying how the process was started (fixed words), so a device log shows a start
        // even if anything later fails.
        ProviderLog.Shared.Write(new OperationRecord("process_start", Guid.Empty, com ? "com" : "cli", HResults.SOk,
                                                     Detail: "args_" + Math.Min(args.Length, 9).ToString(CultureInfo.InvariantCulture)));
        try
        {
            // A WinExe has no console. Started from a terminal, borrow the parent's so --state can print; started by
            // the app with redirected pipes, stdout already works.
            if (!com && !Console.IsOutputRedirected)
                _ = AttachConsole(AttachParentProcess);
            var context = new CliContext(Console.Out, WebAuthnApi.Instance, ProviderIds.Clsid,
                                         BuildGate.IsCurrentSystemSupported, () => ComServerHost.Run(ProviderIds.Clsid),
                                         ct => MetadataSync.Query(PipeClient.ForInstalledProvider(), AppLauncher.Shared)(ct));
            return Cli.Run(args, context);
        }
        catch (Exception ex)
        {
            ProviderLog.Shared.Write(new OperationRecord("process_crash", Guid.Empty, "failed", ex.HResult,
                                                         Detail: ProviderLog.TypeWord(ex)));
            return Cli.Failed;
        }
    }

    [LibraryImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AttachConsole(uint processId);
}
