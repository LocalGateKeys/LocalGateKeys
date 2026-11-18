using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace LocalGateKeys.PasskeyProvider.Interop;

/// <summary>
/// <c>IPluginAuthenticator</c>, IID <c>d26bcf6f-b54c-43ff-9f06-d5bf148625f7</c>, version 1.0, from
/// <c>pluginauthenticator.idl</c> / <c>pluginauthenticator.h</c> (Windows SDK 10.0.26100.0, MIDL_INTERFACE). Vtable
/// order after IUnknown: MakeCredential, GetAssertion, CancelOperation, GetLockStatus. The response of the two
/// ceremonies is <c>[out, retval] PWEBAUTHN_PLUGIN_OPERATION_RESPONSE</c>: a caller-allocated structure the server
/// fills. The deprecated <c>EXPERIMENTAL_IPluginAuthenticator</c> (e6466e9a-...) is deliberately not implemented.
/// Every method returns its HRESULT itself (PreserveSig); none throws across the COM boundary.
/// </summary>
[GeneratedComInterface]
[Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
internal unsafe partial interface IPluginAuthenticator
{
    [PreserveSig]
    int MakeCredential(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response);

    [PreserveSig]
    int GetAssertion(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response);

    [PreserveSig]
    int CancelOperation(WebAuthnPluginCancelOperationRequest* request);

    /// <param name="lockStatus">PLUGIN_LOCK_STATUS: <see cref="PluginLockStatus"/>.</param>
    [PreserveSig]
    int GetLockStatus(int* lockStatus);
}

/// <summary>Standard COM <c>IClassFactory</c> (unknwn.idl), IID 00000001-0000-0000-C000-000000000046.</summary>
[GeneratedComInterface]
[Guid("00000001-0000-0000-C000-000000000046")]
internal unsafe partial interface IClassFactory
{
    [PreserveSig]
    int CreateInstance(void* outer, Guid* riid, void** ppvObject);

    [PreserveSig]
    int LockServer(int fLock);
}
