using Microsoft.Win32.SafeHandles;

namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>Decides whether the pipe server's process is the LocalGateKeys app (design note section 5.1).</summary>
public interface IServerImageCheck
{
    bool IsTrustedServer(int pid);

    /// <summary>Null when trusted; else the failed sub-check (a fixed word) for the diagnostics log.</summary>
    string? Refusal(int pid) => IsTrustedServer(pid) ? null : "untrusted";
}

/// <summary>Package identity reads, injectable so tests can fake a packaged provider.</summary>
public interface IPackageFamilyReader
{
    /// <summary>
    /// This process's package family name, or null only when it has no package identity
    /// (<c>APPMODEL_ERROR_NO_PACKAGE</c>). Any other failure throws, so the caller fails closed.
    /// </summary>
    string? Current();

    /// <summary>The package family name of an opened process, or null when it has none (or on any error).</summary>
    string? OfProcess(SafeProcessHandle process);
}

/// <summary><c>GetCurrentPackageFamilyName</c> / <c>GetPackageFamilyName</c> (appmodel.h).</summary>
public sealed class PackageFamilyReader : IPackageFamilyReader
{
    public static readonly PackageFamilyReader Instance = new();

    /// <summary>The <c>GetCurrentPackageFamilyName</c> call shape, replaceable in tests.</summary>
    internal unsafe delegate int CurrentFamilyCall(ref uint length, char* buffer);

    private readonly CurrentFamilyCall _current;

    internal unsafe PackageFamilyReader(CurrentFamilyCall? current = null)
    {
        _current = current ?? ((ref uint length, char* buffer) =>
            NativeMethods.GetCurrentPackageFamilyName(ref length, buffer));
    }

    public unsafe string? Current()
    {
        uint length = 0;
        var first = _current(ref length, null);
        if (first == NativeMethods.AppModelErrorNoPackage)
            return null;  // truly unpackaged: the only null answer
        if (first != NativeMethods.ErrorInsufficientBuffer || length == 0)
            throw new InvalidOperationException("GetCurrentPackageFamilyName failed: " + first);
        var buffer = new char[length];
        fixed (char* chars = buffer)
        {
            var second = _current(ref length, chars);
            if (second != 0)
                throw new InvalidOperationException("GetCurrentPackageFamilyName failed: " + second);
        }
        return Terminated(buffer) ?? throw new InvalidOperationException("empty package family name");
    }

    public unsafe string? OfProcess(SafeProcessHandle process)
    {
        uint length = 0;
        if (NativeMethods.GetPackageFamilyName(process, ref length, null) != NativeMethods.ErrorInsufficientBuffer
            || length == 0)
            return null;  // includes APPMODEL_ERROR_NO_PACKAGE
        var buffer = new char[length];
        fixed (char* chars = buffer)
        {
            if (NativeMethods.GetPackageFamilyName(process, ref length, chars) != 0)
                return null;
        }
        return Terminated(buffer);
    }

    private static string? Terminated(char[] buffer)
    {
        var end = Array.IndexOf(buffer, '\0');
        var value = new string(buffer, 0, end < 0 ? buffer.Length : end);
        return value.Length == 0 ? null : value;
    }
}

/// <summary>
/// The server pin in reverse of the agent's <c>system_passkey</c> pin: the server process image must be
/// <c>LocalGateKeys.exe</c> in the provider's parent directory, with the same Authenticode signer as the provider
/// (an unsigned provider is accepted only when packaged, where the package family pin below stands in for the signer,
/// or in a Debug build; see <see cref="Authenticode.SameSigner"/>). When the provider runs with package
/// identity, the server must run with the same package family too: a copy of the app started by path (no
/// identity) is refused. An unpackaged provider (tests, development) keeps the path and signer rule.
/// </summary>
public sealed class ServerImageCheck : IServerImageCheck
{
    public const string AgentImageName = "LocalGateKeys.exe";

    private readonly string _expectedPath;
    private readonly string? _selfSigner;
    private readonly IPackageFamilyReader _families;

    /// <param name="expectedServerPath">The only accepted server image.</param>
    /// <param name="selfPath">This provider's own image, whose signer the server must share.</param>
    /// <param name="families">Package identity reads; the real OS calls when null.</param>
    public ServerImageCheck(string expectedServerPath, string selfPath, IPackageFamilyReader? families = null)
    {
        _expectedPath = Path.GetFullPath(expectedServerPath);
        _selfSigner = Authenticode.SignerThumbprint(selfPath);
        _families = families ?? PackageFamilyReader.Instance;
    }

    public static ServerImageCheck ForInstalledProvider()
    {
        var self = Environment.ProcessPath ?? throw new InvalidOperationException("no process path");
        return new ServerImageCheck(ExpectedServerPathFor(self), self);
    }

    /// <summary><c>&lt;install dir&gt;\LocalGateKeys.exe</c> for <c>&lt;install dir&gt;\PasskeyProvider\...exe</c>.</summary>
    public static string ExpectedServerPathFor(string providerPath) =>
        Path.GetFullPath(Path.Join(Path.GetDirectoryName(Path.GetFullPath(providerPath))!, "..", AgentImageName));

    public bool IsTrustedServer(int pid) => Refusal(pid) is null;

    /// <summary>The first failed sub-check: <c>pid</c>, <c>open</c>, <c>image</c>, <c>path</c>,
    /// <c>package_family</c>, <c>signer</c> or <c>error</c>; null when the server is trusted.</summary>
    public string? Refusal(int pid)
    {
        if (pid <= 0)
            return "pid";
        try
        {
            // The handle keeps the pid from being reused while its image and identity are checked.
            using var process = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false,
                                                          (uint)pid);
            if (process.IsInvalid)
                return "open";
            var image = ImagePath(process);
            if (image is null)
                return "image";
            if (!string.Equals(Path.GetFullPath(image), _expectedPath, StringComparison.OrdinalIgnoreCase))
                return "path";
            if (!SamePackageFamily(process, out var packaged))
                return "package_family";
            return Authenticode.SameSigner(_selfSigner, Authenticode.SignerThumbprint(image), packaged) ? null : "signer";
        }
        catch (Exception)
        {
            return "error";  // fail closed
        }
    }

    /// <param name="packaged">True only when this provider has package identity and the peer's family matched.</param>
    private bool SamePackageFamily(SafeProcessHandle process, out bool packaged)
    {
        packaged = false;
        try
        {
            var own = _families.Current();
            if (own is null)
                return true;  // unpackaged provider: path and signer only
            var peer = _families.OfProcess(process);
            packaged = peer is not null && string.Equals(peer, own, StringComparison.Ordinal);
            return packaged;
        }
        catch (Exception)
        {
            return false;  // fail closed
        }
    }

    private static unsafe string? ImagePath(SafeProcessHandle process)
    {
        const int capacity = 32768;
        var buffer = new char[capacity];
        var size = (uint)capacity;
        fixed (char* chars = buffer)
        {
            if (!NativeMethods.QueryFullProcessImageName(process, 0, chars, ref size))
                return null;
        }
        return size == 0 ? null : new string(buffer, 0, (int)size);
    }
}
