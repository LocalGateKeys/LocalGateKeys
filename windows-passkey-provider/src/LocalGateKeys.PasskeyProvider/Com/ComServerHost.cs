using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using LocalGateKeys.PasskeyProvider.Diagnostics;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Com;

/// <summary>
/// The out-of-process COM server (<c>-PluginActivated</c>). The main thread is MTA, so calls arrive on RPC worker
/// threads and a <c>CancelOperation</c> is served while a ceremony waits. The class object is registered with
/// <c>CoRegisterClassObject(CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE)</c> only: no registry writes here; the COM
/// class itself is declared by the MSIX manifest (Task 8).
/// <para>
/// Lifetime: the process ends 60 s after the last call, but only while no call runs, no <c>LockServer</c> lock is
/// held and no outside COM reference to the provider object remains (standard local-server rules, so a proxy
/// Windows still holds is never cut off). Ending revokes the class object first, then checks once more that no
/// call or reference slipped in; if one did, it registers again and keeps serving.
/// </para>
/// </summary>
internal static partial class ComServerHost
{
    private const uint ClsctxLocalServer = 0x4;
    private const uint RegclsMultipleUse = 1;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan SettleTime = TimeSpan.FromMilliseconds(250);

    public static int Run(Guid clsid)
    {
        var idle = new IdleTracker();
        // One line per activation: shows on a device whether Windows started the provider at all, and whether it
        // runs with package identity (needed for the pipe pins).
        ProviderLog.Shared.Write(new OperationRecord("server_start", Guid.Empty, "ok", HResults.SOk,
                                                     Detail: PackagedWord()));
        // Nothing slow before CoRegisterClassObject: DCOM gives a launched server a limited time to register
        // (event 10010). The pipe client and launcher check Authenticode signers when built, so they are lazy.
        var authenticator = new PluginAuthenticator(
            clsid, WebAuthnApi.Instance, new LazyPipeConnector(PipeClient.ForInstalledProvider),
            new LazyLauncher(() => AppLauncher.Shared), CallerHints.Instance, ForegroundGrant.Instance, idle,
            ProviderTimings.Default, ProviderLog.Shared);
        return Serve(clsid, authenticator, idle, IdleTracker.DefaultIdle);
    }

    private static string PackagedWord()
    {
        try
        {
            return PackageFamilyReader.Instance.Current() is null ? "unpackaged" : "packaged";
        }
        catch (Exception)
        {
            return "package_unknown";
        }
    }

    /// <summary>The two ole32 calls, replaceable in tests.</summary>
    internal interface IClassRegistrar
    {
        int Register(Guid clsid, nint unknown, out uint cookie);
        void Revoke(uint cookie);
    }

    private sealed class Ole32Registrar : IClassRegistrar
    {
        public static readonly Ole32Registrar Instance = new();

        public int Register(Guid clsid, nint unknown, out uint cookie) =>
            CoRegisterClassObject(clsid, unknown, ClsctxLocalServer, RegclsMultipleUse, out cookie);

        public void Revoke(uint cookie) => _ = CoRevokeClassObject(cookie);
    }

    internal static int Serve(Guid clsid, object authenticator, IdleTracker idle, TimeSpan idleExit,
                              IClassRegistrar? registrar = null)
    {
        registrar ??= Ole32Registrar.Instance;
        var wrappers = new StrategyBasedComWrappers();
        var factory = new ClassFactory(authenticator, idle, wrappers);
        var factoryUnknown = wrappers.GetOrCreateComInterfaceForObject(factory, CreateComInterfaceFlags.None);
        // This host's own reference to the provider's COM object, so outside references can be counted.
        var providerUnknown = wrappers.GetOrCreateComInterfaceForObject(authenticator, CreateComInterfaceFlags.None);
        try
        {
            while (true)
            {
                var registered = registrar.Register(clsid, factoryUnknown, out var cookie);
                if (registered != HResults.SOk)
                {
                    ProviderLog.Shared.Write(new OperationRecord("server_register", Guid.Empty, "failed", registered));
                    return 1;
                }
                while (!idle.IsIdle(idleExit, OutsideReferences(providerUnknown)))
                    Thread.Sleep(PollInterval);
                registrar.Revoke(cookie);
                Thread.Sleep(SettleTime);  // a CreateInstance racing the revoke has either landed or been refused
                if (idle.IsQuiet(OutsideReferences(providerUnknown)))
                    return 0;
            }
        }
        finally
        {
            Marshal.Release(providerUnknown);
            Marshal.Release(factoryUnknown);
        }
    }

    /// <summary>
    /// References to the provider object other than <paramref name="ownReference"/>'s: AddRef/Release report the
    /// new count, and this host holds exactly one.
    /// </summary>
    internal static int OutsideReferences(nint ownReference)
    {
        var count = Marshal.AddRef(ownReference);
        Marshal.Release(ownReference);
        return count - 2;  // minus this host's reference and the probe's own AddRef
    }

    [LibraryImport("ole32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int CoRegisterClassObject(in Guid rclsid, nint pUnk, uint dwClsContext, uint flags,
                                                     out uint lpdwRegister);

    [LibraryImport("ole32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int CoRevokeClassObject(uint dwRegister);
}
