using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>
/// The pure decode and encode helpers of this PC's real webauthn.dll, run through the managed layouts: an end-to-end
/// check of the structure copies. No registration, state or credential function is called here.
/// Skipped (passes trivially) where webauthn.dll lacks the plugin exports.
/// </summary>
public class RealWebAuthnDllTests
{
    private static bool Available()
    {
        if (!NativeLibrary.TryLoad("webauthn.dll", typeof(RealWebAuthnDllTests).Assembly,
                                   DllImportSearchPath.System32, out var handle))
            return false;
        if (!NativeLibrary.TryGetExport(handle, "WebAuthNDecodeGetAssertionRequest", out _)
            || !NativeLibrary.TryGetExport(handle, "WebAuthNEncodeGetAssertionResponse", out _))
            return false;
        // Windows Server (the CI runner) has the exports but the wrapper answers "not implemented".
        return WebAuthnApi.Instance.DecodeGetAssertion(GetAssertionCbor(), out _) != HResults.ENotImpl;
    }

    private static readonly byte[] Hash = SHA256.HashData("client data"u8.ToArray());

    private static byte[] Text(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        return [(byte)(0x60 | bytes.Length), .. bytes];
    }

    private static byte[] Bytes(byte[] value) =>
        value.Length < 24 ? [(byte)(0x40 | value.Length), .. value] : [0x58, (byte)value.Length, .. value];

    /// <summary>authenticatorGetAssertion parameters (CTAP 2.1 section 6.2), canonical CBOR.</summary>
    private static byte[] GetAssertionCbor() =>
    [
        0xA4,
        0x01, .. Text("example.test"),
        0x02, .. Bytes(Hash),
        0x03, 0x81, 0xA2, .. Text("id"), .. Bytes(ProviderHarness.CredentialId), .. Text("type"), .. Text("public-key"),
        0x05, 0xA1, .. Text("uv"), 0xF5,
    ];

    /// <summary>authenticatorMakeCredential parameters (CTAP 2.1 section 6.1), canonical CBOR.</summary>
    private static byte[] MakeCredentialCbor() =>
    [
        0xA5,
        0x01, .. Bytes(Hash),
        0x02, 0xA2, .. Text("id"), .. Text("example.test"), .. Text("name"), .. Text("Example"),
        0x03, 0xA3, .. Text("id"), .. Bytes(ProviderHarness.UserId), .. Text("name"), .. Text("ada"),
        .. Text("displayName"), .. Text("Ada"),
        0x04, 0x82, 0xA2, .. Text("alg"), 0x26, .. Text("type"), .. Text("public-key"),
        0xA2, .. Text("alg"), 0x39, 0x01, 0x00, .. Text("type"), .. Text("public-key"),
        0x07, 0xA2, .. Text("rk"), 0xF5, .. Text("uv"), 0xF5,
    ];

    [Fact]
    public void DecodeGetAssertion()
    {
        if (!Available())
            return;
        var hr = WebAuthnApi.Instance.DecodeGetAssertion(GetAssertionCbor(), out var input);
        Assert.Equal(HResults.SOk, hr);
        Assert.Equal("example.test", Encoding.UTF8.GetString(input!.RpId));
        Assert.Equal(Hash, input.ClientDataHash);
        Assert.Equal(ProviderHarness.CredentialId, Assert.Single(input.AllowCredentials));
        Assert.Equal(1, input.Uv);
    }

    [Fact]
    public void DecodeMakeCredential()
    {
        if (!Available())
            return;
        var hr = WebAuthnApi.Instance.DecodeMakeCredential(MakeCredentialCbor(), out var input);
        Assert.Equal(HResults.SOk, hr);
        Assert.Equal("example.test", Encoding.UTF8.GetString(input!.RpId));
        Assert.Equal(Hash, input.ClientDataHash);
        Assert.Equal("Example", input.RpName);
        Assert.Equal(ProviderHarness.UserId, input.UserId);
        Assert.Equal("ada", input.UserName);
        Assert.Equal("Ada", input.UserDisplayName);
        Assert.Equal([-7, -257], input.Algorithms);
        Assert.Empty(input.ExcludeCredentials);
        Assert.Equal(1, input.Uv);
        Assert.Equal(1, input.ResidentKey);
    }

    [Fact]
    public void DecodeRejectsGarbage()
    {
        if (!Available())
            return;
        Assert.NotEqual(HResults.SOk, WebAuthnApi.Instance.DecodeGetAssertion([0xFF, 0x00, 0x13], out var input));
        Assert.Null(input);
    }

    [Fact]
    public void EncodeGetAssertionResponse()
    {
        if (!Available())
            return;
        var output = new AssertionOutput(ProviderHarness.CredentialId, ProviderHarness.AuthData(attested: false),
                                         [1, 2, 3, 4], ProviderHarness.UserId);
        Assert.Equal(HResults.SOk, WebAuthnApi.Instance.EncodeGetAssertionResponse(output, out var encoded));
        Assert.NotEqual(0, encoded.Buffer);
        var bytes = new byte[encoded.Length];
        Marshal.Copy(encoded.Buffer, bytes, 0, bytes.Length);
        Marshal.FreeCoTaskMem(encoded.Buffer);  // CoTaskMem, as the sample's unique_cotaskmem_ptr
        Assert.Contains((byte)0xA0, bytes.Take(2).Select(b => (byte)(b & 0xE0)));  // a CBOR map near the start
    }

    [Fact]
    public void EncodeMakeCredentialResponse()
    {
        if (!Available())
            return;
        var output = new AttestationOutput(ProviderHarness.AuthData(attested: true));
        Assert.Equal(HResults.SOk, WebAuthnApi.Instance.EncodeMakeCredentialResponse(output, out var encoded));
        var bytes = new byte[encoded.Length];
        Marshal.Copy(encoded.Buffer, bytes, 0, bytes.Length);
        Marshal.FreeCoTaskMem(encoded.Buffer);
        var text = Encoding.ASCII.GetString(bytes);
        Assert.Contains("none", text);
    }
}
