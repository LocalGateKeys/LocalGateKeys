using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Com;

/// <summary>
/// Hands out the process's one <see cref="IPluginAuthenticator"/> object (source-generated COM wrappers), so all
/// COM objects share the transaction table. No aggregation; only IUnknown and IPluginAuthenticator.
/// </summary>
[GeneratedComClass]
internal sealed unsafe partial class ClassFactory : IClassFactory
{
    public static readonly Guid IidIUnknown = new("00000000-0000-0000-C000-000000000046");
    public static readonly Guid IidIPluginAuthenticator = new("d26bcf6f-b54c-43ff-9f06-d5bf148625f7");  // pluginauthenticator.idl

    private readonly object _authenticator;
    private readonly IdleTracker _idle;
    private readonly ComWrappers _wrappers;

    public ClassFactory(object authenticator, IdleTracker idle, ComWrappers wrappers)
    {
        _authenticator = authenticator;
        _idle = idle;
        _wrappers = wrappers;
    }

    public int CreateInstance(void* outer, Guid* riid, void** ppvObject)
    {
        _idle.Touch();
        if (ppvObject is null)
            return HResults.EInvalidArg;
        *ppvObject = null;
        if (outer is not null)
            return HResults.ClassENoAggregation;
        if (riid is null)
            return HResults.EInvalidArg;
        var iid = *riid;
        if (iid != IidIUnknown && iid != IidIPluginAuthenticator)
            return HResults.ENoInterface;
        try
        {
            var unknown = _wrappers.GetOrCreateComInterfaceForObject(_authenticator, CreateComInterfaceFlags.None);
            try
            {
                var hr = Marshal.QueryInterface(unknown, iid, out var instance);
                if (hr == HResults.SOk)
                    *ppvObject = (void*)instance;
                return hr;
            }
            finally
            {
                Marshal.Release(unknown);
            }
        }
        catch (Exception)
        {
            return HResults.EFail;
        }
    }

    public int LockServer(int fLock)
    {
        _idle.LockServer(fLock != 0);
        return HResults.SOk;
    }
}
