using System.Runtime.InteropServices;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>Lets the app's dialog come to the front over the caller (note section 9; U14).</summary>
public interface IForegroundGrant
{
    void AllowAgent();
}

/// <summary>
/// <c>AllowSetForegroundWindow(state.pid)</c>, best effort: whether a COM-activated provider holds foreground
/// rights to pass on is UNVERIFIED (U14). The pid comes from the SID-checked agent state; failure changes nothing.
/// </summary>
public sealed partial class ForegroundGrant : IForegroundGrant
{
    public static ForegroundGrant Instance { get; } = new();

    public void AllowAgent()
    {
        try
        {
            var pid = AgentState.LoadDefault().Pid;
            if (pid > 0)
                _ = AllowSetForegroundWindow((uint)pid);
        }
        catch (Exception)
        {
            // App not running or state unreadable: the pipe call reports that.
        }
    }

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);
}
