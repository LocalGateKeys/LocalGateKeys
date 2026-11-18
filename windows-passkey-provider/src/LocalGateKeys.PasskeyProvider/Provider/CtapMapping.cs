using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>A decoded <c>authenticatorMakeCredential</c> request, copied out of webauthn.dll memory.</summary>
public sealed record MakeCredentialInput(
    byte[] RpId, byte[] ClientDataHash, string? RpName, byte[] UserId, string? UserName, string? UserDisplayName,
    IReadOnlyList<int> Algorithms, IReadOnlyList<byte[]> ExcludeCredentials, int Up, int Uv, int ResidentKey);

/// <summary>A decoded <c>authenticatorGetAssertion</c> request, copied out of webauthn.dll memory.</summary>
public sealed record GetAssertionInput(
    byte[] RpId, byte[] ClientDataHash, IReadOnlyList<byte[]> AllowCredentials, int Up, int Uv);

/// <summary>What the provider encodes for a create: authenticator data with the attested credential, fmt none.</summary>
public sealed record AttestationOutput(byte[] AuthenticatorData);

/// <summary>What the provider encodes for a get.</summary>
public sealed record AssertionOutput(byte[] CredentialId, byte[] AuthenticatorData, byte[] Signature, byte[] UserHandle);

public sealed class CtapMappingException(string message) : Exception(message);

internal unsafe delegate T NativeFunc<TStruct, out T>(TStruct* value) where TStruct : unmanaged;

/// <summary>
/// Decoded CTAP structures to pipe requests and app replies to response structures (design note section 5.2).
/// Reads of native memory are bounded; anything outside the bounds is an invalid request. Replies are checked
/// against the request (RP ID hash, flags, AAGUID, credential ID, allow list) so a mixed-up reply never reaches
/// Windows.
/// </summary>
public static class CtapMapping
{
    public const int ClientDataHashLength = 32;
    public const int MaxRpIdBytes = 253;
    public const int MaxUserIdBytes = 64;          // WEBAUTHN_MAX_USER_ID_LENGTH (webauthn.h)
    public const int MaxCredentialIdBytes = 1023;  // passkeys.py limit
    public const int MaxListEntries = 256;
    public const int MaxAlgorithms = 64;
    public const int MaxStringChars = 1024;

    private const byte FlagUp = 0x01;
    private const byte FlagUv = 0x04;
    private const byte FlagAt = 0x40;
    private const int RpIdHashLength = 32;
    private const int FlagsAndCounter = 5;
    private const int AaguidLength = 16;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false,
                                                          throwOnInvalidBytes: true);

    // -- native -> managed ----------------------------------------------------------------------------------

    internal static unsafe MakeCredentialInput ReadMakeCredential(WebAuthnCtapCborMakeCredentialRequest* r)
    {
        if (r is null || r->dwVersion < WebAuthnVersions.CtapCborMakeCredentialRequest)
            throw new CtapMappingException("make credential request missing");
        var rp = r->pRpInformation;
        var user = r->pUserInformation;
        if (rp is null || user is null)
            throw new CtapMappingException("rp or user missing");
        var options = r->pAuthenticatorOptions;
        return new MakeCredentialInput(
            Bytes(r->pbRpId, r->cbRpId, 1, MaxRpIdBytes, "rp id"),
            Bytes(r->pbClientDataHash, r->cbClientDataHash, ClientDataHashLength, ClientDataHashLength, "client data hash"),
            String(rp->pwszName),
            Bytes(user->pbId, user->cbId, 1, MaxUserIdBytes, "user id"),
            String(user->pwszName),
            String(user->pwszDisplayName),
            Algorithms(r->WebAuthNCredentialParameters),
            CredentialIds(r->CredentialList),
            options is null ? 0 : options->lUp,
            options is null ? 0 : options->lUv,
            options is null ? 0 : options->lRequireResidentKey);
    }

    internal static unsafe GetAssertionInput ReadGetAssertion(WebAuthnCtapCborGetAssertionRequest* r)
    {
        if (r is null || r->dwVersion < WebAuthnVersions.CtapCborGetAssertionRequest)
            throw new CtapMappingException("get assertion request missing");
        var options = r->pAuthenticatorOptions;
        return new GetAssertionInput(
            Bytes(r->pbRpId, r->cbRpId, 1, MaxRpIdBytes, "rp id"),
            Bytes(r->pbClientDataHash, r->cbClientDataHash, ClientDataHashLength, ClientDataHashLength, "client data hash"),
            CredentialIds(r->CredentialList),
            options is null ? 0 : options->lUp,
            options is null ? 0 : options->lUv);
    }

    private static unsafe byte[] Bytes(byte* p, uint length, int min, int max, string what)
    {
        if (length < min || length > max || (length > 0 && p is null))
            throw new CtapMappingException(what + " has the wrong length");
        return new ReadOnlySpan<byte>(p, (int)length).ToArray();
    }

    private static unsafe string? String(char* p)
    {
        if (p is null)
            return null;
        for (var i = 0; i <= MaxStringChars; i++)
        {
            if (p[i] == '\0')
                return new string(p, 0, i);
        }
        throw new CtapMappingException("string too long");
    }

    private static unsafe int[] Algorithms(WebAuthnCoseCredentialParameters list)
    {
        if (list.cCredentialParameters > MaxAlgorithms || (list.cCredentialParameters > 0 && list.pCredentialParameters is null))
            throw new CtapMappingException("too many algorithms");
        var result = new List<int>();
        for (var i = 0; i < list.cCredentialParameters; i++)
        {
            var parameter = list.pCredentialParameters[i];
            if (String(parameter.pwszCredentialType) == WebAuthnStrings.CredentialTypePublicKey)
                result.Add(parameter.lAlg);
        }
        return [.. result];
    }

    private static unsafe byte[][] CredentialIds(WebAuthnCredentialList list)
    {
        if (list.cCredentials > MaxListEntries || (list.cCredentials > 0 && list.ppCredentials is null))
            throw new CtapMappingException("credential list too long");
        var result = new List<byte[]>();
        for (var i = 0; i < list.cCredentials; i++)
        {
            var credential = list.ppCredentials[i];
            if (credential is null)
                throw new CtapMappingException("credential entry missing");
            if (String(credential->pwszCredentialType) != WebAuthnStrings.CredentialTypePublicKey)
                continue;
            result.Add(Bytes(credential->pbId, credential->cbId, 1, MaxCredentialIdBytes, "credential id"));
        }
        return [.. result];
    }

    // -- managed -> pipe request ----------------------------------------------------------------------------

    public const string UvRequired = "required";
    public const string UvDiscouraged = "discouraged";

    /// <summary>
    /// <c>lUv</c> is +1 TRUE, 0 not defined, -1 FALSE. Only an explicit -1 ("discouraged") skips user verification.
    /// Anything else, including 0 (the relying party said "preferred", or did not say), is sent as "required":
    /// the provider can always verify (the app's Hello or master password check), and WebAuthn has the
    /// authenticator verify for "preferred" whenever it can. The system protocol knows only these two values, and
    /// the app treats "required" as it treats "preferred" (verify; a failed or cancelled check answers nothing).
    /// </summary>
    public static string UserVerification(int lUv) => lUv == -1 ? UvDiscouraged : UvRequired;

    public static CreateSystemRequest ToRequest(MakeCredentialInput input, CallerHint? caller)
    {
        var rpId = RpIdText(input.RpId);
        return new CreateSystemRequest(
            rpId, input.RpName ?? rpId, B64(input.UserId), input.UserName ?? string.Empty,
            input.UserDisplayName ?? string.Empty, B64(input.ClientDataHash), input.Algorithms,
            input.ExcludeCredentials.Select(B64).ToArray(), input.ResidentKey == 1, UserVerification(input.Uv),
            caller);
    }

    public static GetSystemRequest ToRequest(GetAssertionInput input, CallerHint? caller) =>
        new(RpIdText(input.RpId), B64(input.ClientDataHash), input.AllowCredentials.Select(B64).ToArray(),
            UserVerification(input.Uv), caller);

    private static string RpIdText(byte[] rpId)
    {
        try
        {
            return StrictUtf8.GetString(rpId);
        }
        catch (DecoderFallbackException)
        {
            throw new CtapMappingException("rp id is not UTF-8");
        }
    }

    // -- app reply -> response ------------------------------------------------------------------------------

    public static AttestationOutput ReadCreateReply(JsonObject reply, MakeCredentialInput input)
    {
        CreateSystemReply parsed;
        try
        {
            parsed = SystemMessages.ReadCreateReply(reply);
        }
        catch (PipeProtocolException)
        {
            throw new CtapMappingException("create reply has the wrong shape");
        }
        if (parsed.AttestationFormat != WebAuthnStrings.AttestationTypeNone)
            throw new CtapMappingException("unexpected attestation format");
        var credentialId = Unb64(parsed.CredentialId);
        var authData = Unb64(parsed.AuthenticatorData);
        CheckAuthData(authData, input.RpId, attested: true, UserVerification(input.Uv) == UvRequired);
        var at = RpIdHashLength + FlagsAndCounter;
        if (!authData.AsSpan(at, AaguidLength).SequenceEqual(ProviderIds.AaguidBytes()))
            throw new CtapMappingException("wrong aaguid");
        var length = (authData[at + AaguidLength] << 8) | authData[at + AaguidLength + 1];
        var idStart = at + AaguidLength + 2;
        if (length != credentialId.Length || credentialId.Length is 0 or > MaxCredentialIdBytes
            || authData.Length < idStart + length || !authData.AsSpan(idStart, length).SequenceEqual(credentialId))
            throw new CtapMappingException("credential id does not match the authenticator data");
        return new AttestationOutput(authData);
    }

    public static AssertionOutput ReadGetReply(JsonObject reply, GetAssertionInput input)
    {
        GetSystemReply parsed;
        try
        {
            parsed = SystemMessages.ReadGetReply(reply);
        }
        catch (PipeProtocolException)
        {
            throw new CtapMappingException("get reply has the wrong shape");
        }
        var credentialId = Unb64(parsed.CredentialId);
        var authData = Unb64(parsed.AuthenticatorData);
        var signature = Unb64(parsed.Signature);
        var userHandle = Unb64(parsed.UserHandle);
        CheckAuthData(authData, input.RpId, attested: false, UserVerification(input.Uv) == UvRequired);
        if (credentialId.Length is 0 or > MaxCredentialIdBytes || signature.Length == 0 || userHandle.Length > MaxUserIdBytes)
            throw new CtapMappingException("reply field has the wrong length");
        if (input.AllowCredentials.Count > 0 && !input.AllowCredentials.Any(id => id.AsSpan().SequenceEqual(credentialId)))
            throw new CtapMappingException("credential not in the allow list");
        // A discoverable get (empty allow list) must name the account: CTAP 2.1 requires the user entity then.
        if (input.AllowCredentials.Count == 0 && userHandle.Length == 0)
            throw new CtapMappingException("user handle missing for a discoverable credential");
        return new AssertionOutput(credentialId, authData, signature, userHandle);
    }

    /// <summary>UP is always required; UV whenever verification was asked of the app (see <see cref="UserVerification"/>).</summary>
    private static void CheckAuthData(byte[] authData, byte[] rpId, bool attested, bool userVerified)
    {
        var minimum = RpIdHashLength + FlagsAndCounter + (attested ? AaguidLength + 2 : 0);
        if (authData.Length < minimum)
            throw new CtapMappingException("authenticator data too short");
        if (!authData.AsSpan(0, RpIdHashLength).SequenceEqual(SHA256.HashData(rpId)))
            throw new CtapMappingException("authenticator data is for another rp id");
        var flags = authData[RpIdHashLength];
        if ((flags & FlagUp) == 0 || ((flags & FlagAt) != 0) != attested)
            throw new CtapMappingException("authenticator data flags");
        if (userVerified && (flags & FlagUv) == 0)
            throw new CtapMappingException("user not verified");
    }

    // -- response structures --------------------------------------------------------------------------------

    /// <summary>
    /// Fills <c>WEBAUTHN_CREDENTIAL_ATTESTATION</c> as the Microsoft sample does ([S4]): current version, format
    /// "none", the authenticator data, no attestation statement (<c>cbAttestation = 0</c>); everything else zero.
    /// The pointers are valid only inside <paramref name="use"/>.
    /// </summary>
    internal static unsafe T WithNativeAttestation<T>(AttestationOutput output, NativeFunc<WebAuthnCredentialAttestation, T> use)
    {
        fixed (char* format = WebAuthnStrings.AttestationTypeNone)
        fixed (byte* authData = output.AuthenticatorData)
        {
            var attestation = new WebAuthnCredentialAttestation
            {
                dwVersion = WebAuthnVersions.CredentialAttestation,
                pwszFormatType = format,
                cbAuthenticatorData = (uint)output.AuthenticatorData.Length,
                pbAuthenticatorData = authData,
                cbAttestation = 0,
                pbAttestation = null,
            };
            return use(&attestation);
        }
    }

    /// <summary>
    /// Fills <c>WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE</c> as the sample does ([S4]): assertion at the current
    /// version, credential of type public-key, the user entity with only the user handle, one credential.
    /// </summary>
    internal static unsafe T WithNativeAssertion<T>(AssertionOutput output, NativeFunc<WebAuthnCtapCborGetAssertionResponse, T> use)
    {
        fixed (char* type = WebAuthnStrings.CredentialTypePublicKey)
        fixed (byte* credentialId = output.CredentialId)
        fixed (byte* authData = output.AuthenticatorData)
        fixed (byte* signature = output.Signature)
        fixed (byte* userHandle = output.UserHandle)
        {
            var user = new WebAuthnUserEntityInformation
            {
                dwVersion = WebAuthnVersions.UserEntityInformation,
                cbId = (uint)output.UserHandle.Length,
                pbId = userHandle,
            };
            var response = new WebAuthnCtapCborGetAssertionResponse
            {
                WebAuthNAssertion = new WebAuthnAssertion
                {
                    dwVersion = WebAuthnVersions.Assertion,
                    cbAuthenticatorData = (uint)output.AuthenticatorData.Length,
                    pbAuthenticatorData = authData,
                    cbSignature = (uint)output.Signature.Length,
                    pbSignature = signature,
                    Credential = new WebAuthnCredential
                    {
                        dwVersion = WebAuthnVersions.Credential,
                        cbId = (uint)output.CredentialId.Length,
                        pbId = credentialId,
                        pwszCredentialType = type,
                    },
                    cbUserId = (uint)output.UserHandle.Length,
                    pbUserId = output.UserHandle.Length == 0 ? null : userHandle,
                },
                pUserInformation = output.UserHandle.Length == 0 ? null : &user,
                dwNumberOfCredentials = 1,
            };
            return use(&response);
        }
    }

    // -- base64url (no padding, as passkeys.py) -------------------------------------------------------------

    public static string B64(byte[] value) => Base64Url.EncodeToString(value);

    /// <summary>Strict: only the canonical unpadded form is accepted.</summary>
    public static byte[] Unb64(string value)
    {
        byte[] decoded;
        try
        {
            decoded = Base64Url.DecodeFromChars(value);
        }
        catch (FormatException)
        {
            throw new CtapMappingException("not base64url");
        }
        if (Base64Url.EncodeToString(decoded) != value)
            throw new CtapMappingException("not canonical base64url");
        return decoded;
    }
}
