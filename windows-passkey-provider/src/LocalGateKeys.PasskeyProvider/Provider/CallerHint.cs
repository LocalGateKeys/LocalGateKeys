using System.Runtime.InteropServices;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>Turns the request's <c>hWnd</c> into a display hint. Never used for policy (note section 5.2).</summary>
public interface ICallerHints
{
    CallerHint? From(nint hWnd);
}

/// <summary>
/// The image file name of the process that owns the window (<c>GetWindowThreadProcessId</c>,
/// <c>QueryFullProcessImageNameW</c>) and the window title (<c>GetWindowTextW</c>), each truncated, control
/// characters removed. Any failure leaves that part out.
/// </summary>
public sealed partial class CallerHints : ICallerHints
{
    public const int MaxImageChars = 64;
    public const int MaxTitleChars = 128;

    public static CallerHints Instance { get; } = new();

    public CallerHint? From(nint hWnd)
    {
        if (hWnd == 0)
            return null;
        try
        {
            var image = Clean(ImageName(hWnd), MaxImageChars);
            var title = Clean(Title(hWnd), MaxTitleChars);
            return image is null && title is null ? null : new CallerHint(image, title);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Drops control characters, trims, truncates; empty becomes null.</summary>
    public static string? Clean(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
            return null;
        var kept = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (kept.Length > max)
            kept = kept[..max];
        if (kept.Length > 0 && char.IsHighSurrogate(kept[^1]))
            kept = kept[..^1];
        return kept.Length == 0 ? null : kept;
    }

    private static unsafe string? ImageName(nint hWnd)
    {
        if (GetWindowThreadProcessId(hWnd, out var pid) == 0 || pid == 0)
            return null;
        using var process = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (process.IsInvalid)
            return null;
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        fixed (char* p = buffer)
        {
            if (!NativeMethods.QueryFullProcessImageName(process, 0, p, ref size))
                return null;
        }
        return Path.GetFileName(new string(buffer, 0, (int)size));
    }

    // For a window of another process GetWindowTextW reads the stored caption without sending WM_GETTEXT, so a hung
    // caller cannot block this call (GetWindowTextW documentation, Remarks).
    private static unsafe string? Title(nint hWnd)
    {
        var buffer = stackalloc char[MaxTitleChars + 1];
        var length = GetWindowTextW(hWnd, buffer, MaxTitleChars + 1);
        return length <= 0 ? null : new string(buffer, 0, length);
    }

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetWindowThreadProcessId(nint hWnd, out uint processId);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int GetWindowTextW(nint hWnd, char* text, int maxCount);
}
