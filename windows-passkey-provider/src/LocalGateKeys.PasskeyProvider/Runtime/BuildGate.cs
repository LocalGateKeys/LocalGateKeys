using Microsoft.Win32;

namespace LocalGateKeys.PasskeyProvider.Runtime;

/// <summary>
/// Windows builds with the plugin passkey API: 26100 or 26200 with UBR 6725 or later, or any later build
/// (Global Constraints of sub-plan 04).
/// </summary>
public static class BuildGate
{
    public const int MinimumUbr = 6725;

    public static bool IsSupported(int build, int ubr) => build switch
    {
        > 26200 => true,
        26100 or 26200 => ubr >= MinimumUbr,
        _ => false,
    };

    public static bool IsCurrentSystemSupported()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var build = int.TryParse(key?.GetValue("CurrentBuildNumber") as string, out var b) ? b : 0;
            var ubr = key?.GetValue("UBR") is int u ? u : 0;
            return IsSupported(build, ubr);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
