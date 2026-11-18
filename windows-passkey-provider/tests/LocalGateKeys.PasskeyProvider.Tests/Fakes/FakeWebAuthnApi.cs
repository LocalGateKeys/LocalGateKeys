using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests.Fakes;

/// <summary>A scripted webauthn.dll: a test P-256 operation-signing key, canned decodes, CoTaskMem encodes.</summary>
internal sealed class FakeWebAuthnApi : IWebAuthnApi, IDisposable
{
    public ECDsa SigningKey { get; }

    /// <summary>P-256 by default; the device's operation key (Windows 26300) is P-384.</summary>
    public FakeWebAuthnApi(ECCurve? curve = null) =>
        SigningKey = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
    public int KeyHr { get; set; } = HResults.SOk;
    /// <summary>Runs inside every key fetch (to make it slow or block).</summary>
    public Action? OnKey { get; set; }
    public MakeCredentialInput? MakeCredential { get; set; }
    public GetAssertionInput? GetAssertion { get; set; }
    public int StateHr { get; set; } = HResults.NteNotFound;
    public int State { get; set; }
    public int AddHr { get; set; } = HResults.SOk;
    public int RemoveHr { get; set; } = HResults.SOk;
    public int RemoveAllHr { get; set; } = HResults.SOk;

    public ConcurrentQueue<string> Calls { get; } = new();

    /// <summary>The managed thread id of every call, to check where webauthn.dll would have been called.</summary>
    public ConcurrentQueue<(string Call, int Thread)> Threads { get; } = new();

    private void Record(string call)
    {
        Calls.Enqueue(call);
        Threads.Enqueue((call, Environment.CurrentManagedThreadId));
    }
    public AuthenticatorRegistration? Registered { get; private set; }
    public AttestationOutput? EncodedAttestation { get; private set; }
    public AssertionOutput? EncodedAssertion { get; private set; }
    public static readonly byte[] EncodedMarker = [0x00, 0xA1, 0x01, 0x02];

    public byte[] PublicKeyBlob() => EcdsaBlob(SigningKey);

    /// <summary>
    /// A CNG BCRYPT_ECCKEY_BLOB as WebAuthNPluginGetOperationSigningPublicKey returns it: magic, cbKey, X, Y.
    /// ECS1 (P-256, 72 bytes), ECS3 (P-384, 104 bytes, the device's), ECS5 (P-521, 140 bytes).
    /// </summary>
    public static byte[] EcdsaBlob(ECDsa key)
    {
        var p = key.ExportParameters(false);
        var size = p.Q.X!.Length;
        uint magic = key.KeySize switch
        {
            256 => 0x31534345u,  // BCRYPT_ECDSA_PUBLIC_P256_MAGIC "ECS1"
            384 => 0x33534345u,  // BCRYPT_ECDSA_PUBLIC_P384_MAGIC "ECS3"
            521 => 0x35534345u,  // BCRYPT_ECDSA_PUBLIC_P521_MAGIC "ECS5"
            _ => throw new ArgumentException("curve"),
        };
        var blob = new byte[8 + 2 * size];
        BitConverter.GetBytes(magic).CopyTo(blob, 0);
        BitConverter.GetBytes((uint)size).CopyTo(blob, 4);
        p.Q.X.CopyTo(blob, 8);
        p.Q.Y!.CopyTo(blob, 8 + size);
        return blob;
    }

    public byte[] Sign(byte[] data) =>
        SigningKey.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public int GetOperationSigningPublicKey(Guid clsid, out byte[] publicKey)
    {
        Record("key");
        OnKey?.Invoke();
        publicKey = KeyHr == HResults.SOk ? PublicKeyBlob() : [];
        return KeyHr;
    }

    public int DecodeMakeCredential(byte[] encoded, out MakeCredentialInput? input)
    {
        Record("decode_make");
        input = MakeCredential;
        return input is null ? HResults.EInvalidArg : HResults.SOk;
    }

    public int DecodeGetAssertion(byte[] encoded, out GetAssertionInput? input)
    {
        Record("decode_get");
        input = GetAssertion;
        return input is null ? HResults.EInvalidArg : HResults.SOk;
    }

    public int EncodeMakeCredentialResponse(AttestationOutput output, out EncodedResponse response)
    {
        Record("encode_make");
        EncodedAttestation = output;
        response = Marker();
        return HResults.SOk;
    }

    public int EncodeGetAssertionResponse(AssertionOutput output, out EncodedResponse response)
    {
        Record("encode_get");
        EncodedAssertion = output;
        response = Marker();
        return HResults.SOk;
    }

    private static EncodedResponse Marker()
    {
        var buffer = Marshal.AllocCoTaskMem(EncodedMarker.Length);
        Marshal.Copy(EncodedMarker, 0, buffer, EncodedMarker.Length);
        return new EncodedResponse(buffer, (uint)EncodedMarker.Length);
    }

    public int GetAuthenticatorState(Guid clsid, out int state)
    {
        Record("state");
        state = State;
        return StateHr;
    }

    public int AddAuthenticator(AuthenticatorRegistration registration)
    {
        Record("add");
        Registered = registration;
        return AddHr;
    }

    public int RemoveAuthenticator(Guid clsid)
    {
        Record("remove");
        return RemoveHr;
    }

    public int RemoveAllCredentials(Guid clsid)
    {
        Record("remove_all");
        return RemoveAllHr;
    }

    public int AddCredentialsHr { get; set; } = HResults.SOk;
    public IReadOnlyList<CredentialDetail>? AddedCredentials { get; private set; }

    public int AddCredentials(Guid clsid, IReadOnlyList<CredentialDetail> credentials)
    {
        Record("add_credentials");
        AddedCredentials = credentials;
        return AddCredentialsHr;
    }

    public void Dispose() => SigningKey.Dispose();
}

internal sealed class FakeCallerHints : ICallerHints
{
    public CallerHint? From(nint hWnd) => hWnd == 0 ? null : new CallerHint("msedge.exe", "Sign in - Example");
}

internal sealed class FakeForeground : IForegroundGrant
{
    public int Calls;
    public void AllowAgent() => Interlocked.Increment(ref Calls);
}
