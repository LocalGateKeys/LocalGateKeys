using System.Diagnostics;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Runtime;

public interface IProcessLauncher
{
    /// <summary>Starts the app the first time it is called; true only when that call started it.</summary>
    bool StartAgentOnce();
}

/// <summary>
/// Starts <c>&lt;install dir&gt;\LocalGateKeys.exe --background</c> at most once per provider process, and only
/// when it carries the provider's own signer (the same rule as the server pin).
/// </summary>
public sealed class AppLauncher : IProcessLauncher
{
    private static readonly Lazy<AppLauncher> SharedInstance = new(() => Create(Environment.ProcessPath));

    /// <summary>Never throws: without a usable own path the launcher simply never starts anything.</summary>
    internal static AppLauncher Create(string? self)
    {
        try
        {
            if (string.IsNullOrEmpty(self))
                return Inert();
            var selfSigner = Authenticode.SignerThumbprint(self);
            // Packaged: the app sits in the same read-only package; the server pin then checks its package family.
            var packaged = PackageFamilyReader.Instance.Current() is not null;
            return new AppLauncher(AgentPathFor(self), Start,
                                   path => Authenticode.SameSigner(selfSigner, Authenticode.SignerThumbprint(path), packaged));
        }
        catch (Exception)
        {
            return Inert();
        }
    }

    private static AppLauncher Inert() => new(string.Empty, _ => false, _ => false);

    private readonly string _agentPath;
    private readonly Func<string, bool> _start;
    private readonly Func<string, bool> _trusted;
    private int _attempted;

    internal AppLauncher(string agentPath, Func<string, bool> start, Func<string, bool> trusted)
    {
        _agentPath = agentPath;
        _start = start;
        _trusted = trusted;
    }

    /// <summary>The one launcher of this process.</summary>
    public static AppLauncher Shared => SharedInstance.Value;

    public static string AgentPathFor(string providerPath) => ServerImageCheck.ExpectedServerPathFor(providerPath);

    public static ProcessStartInfo StartInfoFor(string agentPath)
    {
        var info = new ProcessStartInfo(agentPath)
        {
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(agentPath)!,
        };
        info.ArgumentList.Add("--background");
        return info;
    }

    public bool StartAgentOnce()
    {
        if (Interlocked.Exchange(ref _attempted, 1) != 0)
            return false;
        try
        {
            return File.Exists(_agentPath) && _trusted(_agentPath) && _start(_agentPath);
        }
        catch (Exception)
        {
            return false;  // the caller's pipe retry ends as "not running"
        }
    }

    private static bool Start(string agentPath)
    {
        using var process = Process.Start(StartInfoFor(agentPath));
        return process is not null;
    }
}
