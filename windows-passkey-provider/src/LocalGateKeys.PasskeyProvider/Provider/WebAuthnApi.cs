using System.Runtime.InteropServices;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>A CoTaskMem buffer from a webauthn.dll encoder; whoever receives it owns it.</summary>
public readonly record struct EncodedResponse(nint Buffer, uint Length);

/// <summary>What <c>--register</c> hands to <c>WebAuthNPluginAddAuthenticator</c>.</summary>
public sealed record AuthenticatorRegistration(
    Guid Clsid, string Name, string PluginRpId, string LightLogoSvgBase64, string DarkLogoSvgBase64,
    byte[] AuthenticatorInfo);

/// <summary>
/// The webauthn.dll calls the provider makes, behind one interface so tests use a fake. Every method returns an
/// HRESULT and never throws; a missing webauthn.dll or export (older Windows) is <see cref="HResults.ENotImpl"/>.
/// </summary>
public interface IWebAuthnApi
{
    int GetOperationSigningPublicKey(Guid clsid, out byte[] publicKey);
    int DecodeMakeCredential(byte[] encoded, out MakeCredentialInput? input);
    int DecodeGetAssertion(byte[] encoded, out GetAssertionInput? input);
    int EncodeMakeCredentialResponse(AttestationOutput output, out EncodedResponse response);
    int EncodeGetAssertionResponse(AssertionOutput output, out EncodedResponse response);
    int GetAuthenticatorState(Guid clsid, out int state);
    int AddAuthenticator(AuthenticatorRegistration registration);
    int RemoveAuthenticator(Guid clsid);
    int RemoveAllCredentials(Guid clsid);
    int AddCredentials(Guid clsid, IReadOnlyList<CredentialDetail> credentials);
}

/// <summary>The real webauthn.dll (System32 only; see <see cref="WebAuthnPluginNative"/>).</summary>
public sealed unsafe class WebAuthnApi : IWebAuthnApi
{
    public static WebAuthnApi Instance { get; } = new();

    private static int Guarded(Func<int> call)
    {
        try
        {
            return call();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return HResults.ENotImpl;
        }
        catch (CtapMappingException)
        {
            return HResults.EInvalidArg;
        }
        catch (Exception)
        {
            return HResults.EFail;
        }
    }

    public int GetOperationSigningPublicKey(Guid clsid, out byte[] publicKey)
    {
        byte[] key = [];
        var hr = Guarded(() =>
        {
            uint cb = 0;
            byte* pb = null;
            var result = WebAuthnPluginNative.WebAuthNPluginGetOperationSigningPublicKey(clsid, &cb, &pb);
            try
            {
                if (result == HResults.SOk && pb is not null && cb is > 0 and <= 64 * 1024)
                    key = new ReadOnlySpan<byte>(pb, (int)cb).ToArray();
                else if (result == HResults.SOk)
                    result = HResults.NteBadSignature;
            }
            finally
            {
                if (pb is not null)
                    WebAuthnPluginNative.WebAuthNPluginFreePublicKeyResponse(pb);
            }
            return result;
        });
        publicKey = key;
        return hr;
    }

    public int DecodeMakeCredential(byte[] encoded, out MakeCredentialInput? input)
    {
        MakeCredentialInput? decoded = null;
        var hr = Guarded(() =>
        {
            WebAuthnCtapCborMakeCredentialRequest* request = null;
            fixed (byte* p = encoded)
            {
                var result = WebAuthnPluginNative.WebAuthNDecodeMakeCredentialRequest((uint)encoded.Length, p, &request);
                try
                {
                    if (result != HResults.SOk)
                        return result;
                    decoded = CtapMapping.ReadMakeCredential(request);
                    return HResults.SOk;
                }
                finally
                {
                    if (request is not null)
                        WebAuthnPluginNative.WebAuthNFreeDecodedMakeCredentialRequest(request);
                }
            }
        });
        input = hr == HResults.SOk ? decoded : null;
        return hr == HResults.SOk && decoded is null ? HResults.EInvalidArg : hr;
    }

    public int DecodeGetAssertion(byte[] encoded, out GetAssertionInput? input)
    {
        GetAssertionInput? decoded = null;
        var hr = Guarded(() =>
        {
            WebAuthnCtapCborGetAssertionRequest* request = null;
            fixed (byte* p = encoded)
            {
                var result = WebAuthnPluginNative.WebAuthNDecodeGetAssertionRequest((uint)encoded.Length, p, &request);
                try
                {
                    if (result != HResults.SOk)
                        return result;
                    decoded = CtapMapping.ReadGetAssertion(request);
                    return HResults.SOk;
                }
                finally
                {
                    if (request is not null)
                        WebAuthnPluginNative.WebAuthNFreeDecodedGetAssertionRequest(request);
                }
            }
        });
        input = hr == HResults.SOk ? decoded : null;
        return hr == HResults.SOk && decoded is null ? HResults.EInvalidArg : hr;
    }

    public int EncodeMakeCredentialResponse(AttestationOutput output, out EncodedResponse response)
    {
        var encoded = default(EncodedResponse);
        var hr = Guarded(() => CtapMapping.WithNativeAttestation(output, attestation =>
        {
            uint cb = 0;
            byte* pb = null;
            var result = WebAuthnPluginNative.WebAuthNEncodeMakeCredentialResponse(attestation, &cb, &pb);
            return Take(result, cb, pb, out encoded);
        }));
        response = encoded;
        return hr;
    }

    public int EncodeGetAssertionResponse(AssertionOutput output, out EncodedResponse response)
    {
        var encoded = default(EncodedResponse);
        var hr = Guarded(() => CtapMapping.WithNativeAssertion(output, assertion =>
        {
            uint cb = 0;
            byte* pb = null;
            var result = WebAuthnPluginNative.WebAuthNEncodeGetAssertionResponse(assertion, &cb, &pb);
            return Take(result, cb, pb, out encoded);
        }));
        response = encoded;
        return hr;
    }

    private static int Take(int result, uint cb, byte* pb, out EncodedResponse encoded)
    {
        encoded = default;
        if (result == HResults.SOk && pb is not null && cb > 0)
        {
            encoded = new EncodedResponse((nint)pb, cb);
            return HResults.SOk;
        }
        if (pb is not null)
            Marshal.FreeCoTaskMem((nint)pb);  // CoTaskMem per the sample ([S4]); never returned half-built
        return result == HResults.SOk ? HResults.EFail : result;
    }

    public int GetAuthenticatorState(Guid clsid, out int state)
    {
        var value = AuthenticatorState.Disabled;
        var hr = Guarded(() =>
        {
            int s;
            var result = WebAuthnPluginNative.WebAuthNPluginGetAuthenticatorState(clsid, &s);
            value = s;
            return result;
        });
        state = value;
        return hr;
    }

    public int AddAuthenticator(AuthenticatorRegistration registration) => Guarded(() =>
    {
        var clsid = registration.Clsid;
        fixed (char* name = registration.Name)
        fixed (char* rpId = registration.PluginRpId)
        fixed (char* light = registration.LightLogoSvgBase64)
        fixed (char* dark = registration.DarkLogoSvgBase64)
        fixed (byte* info = registration.AuthenticatorInfo)
        {
            var options = new WebAuthnPluginAddAuthenticatorOptions
            {
                pwszAuthenticatorName = name,
                rclsid = &clsid,
                pwszPluginRpId = rpId,
                pwszLightThemeLogoSvg = light,
                pwszDarkThemeLogoSvg = dark,
                cbAuthenticatorInfo = (uint)registration.AuthenticatorInfo.Length,
                pbAuthenticatorInfo = info,
                cSupportedRpIds = 0,  // all RPs
                ppwszSupportedRpIds = null,
            };
            WebAuthnPluginAddAuthenticatorResponse* response = null;
            var result = WebAuthnPluginNative.WebAuthNPluginAddAuthenticator(&options, &response);
            // The operation-signing key in the response is not kept: every request reads it again at run time.
            if (response is not null)
                WebAuthnPluginNative.WebAuthNPluginFreeAddAuthenticatorResponse(response);
            return result;
        }
    });

    public int RemoveAuthenticator(Guid clsid) =>
        Guarded(() => WebAuthnPluginNative.WebAuthNPluginRemoveAuthenticator(clsid));

    public int RemoveAllCredentials(Guid clsid) =>
        Guarded(() => WebAuthnPluginNative.WebAuthNPluginAuthenticatorRemoveAllCredentials(clsid));

    /// <summary>Metadata cache entries (IDs and names only). Every buffer is pinned for the call and freed after.</summary>
    public int AddCredentials(Guid clsid, IReadOnlyList<CredentialDetail> credentials) => Guarded(() =>
    {
        if (credentials.Count == 0)
            return HResults.SOk;
        var handles = new List<GCHandle>(credentials.Count * 6);
        try
        {
            var details = new WebAuthnPluginCredentialDetails[credentials.Count];
            for (var i = 0; i < credentials.Count; i++)
            {
                var entry = credentials[i];
                details[i] = new WebAuthnPluginCredentialDetails
                {
                    cbCredentialId = (uint)entry.CredentialId.Length,
                    pbCredentialId = (byte*)Pin(entry.CredentialId),
                    pwszRpId = (char*)Pin(entry.RpId),
                    pwszRpName = (char*)Pin(entry.RpName),
                    cbUserId = (uint)entry.UserId.Length,
                    pbUserId = (byte*)Pin(entry.UserId),
                    pwszUserName = (char*)Pin(entry.UserName),
                    pwszUserDisplayName = (char*)Pin(entry.UserDisplayName),
                };
            }
            fixed (WebAuthnPluginCredentialDetails* first = details)
                return WebAuthnPluginNative.WebAuthNPluginAuthenticatorAddCredentials(clsid, (uint)details.Length, first);
        }
        finally
        {
            foreach (var handle in handles)
                handle.Free();
        }

        // A pinned string's data is NUL-terminated (the runtime guarantees it, as for `fixed (char* p = text)`).
        nint Pin(object value)
        {
            var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
            handles.Add(handle);
            return handle.AddrOfPinnedObject();
        }
    });
}
