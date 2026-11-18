using System.Security.Cryptography;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>
/// The operation-signing key in every format webauthn.dll may hand over. The first device test (Windows build 26300)
/// logged <c>key_magic_33534345_104</c>: an ECS3 (ECDSA P-384) blob of 8 + 2 x 48 bytes. The sample and
/// KeePassPasskey hash with SHA-256 for any key, and the signature is r||s of twice the coordinate size.
/// </summary>
public class EcdsaCurveTests
{
    private static readonly byte[] Data = ProviderHarness.Encoded;

    public static TheoryData<string> Curves => new() { "P-256", "P-384", "P-521" };

    private static ECDsa Key(string curve) => ECDsa.Create(curve switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        _ => ECCurve.NamedCurves.nistP521,
    });

    private static byte[] Sign(ECDsa key, HashAlgorithmName hash, DSASignatureFormat format = DSASignatureFormat.IeeeP1363FixedFieldConcatenation) =>
        key.SignData(Data, hash, format);

    [Fact]
    public void DeviceShapedP384BlobIsAccepted()
    {
        using var key = Key("P-384");
        var blob = FakeWebAuthnApi.EcdsaBlob(key);
        Assert.Equal(104, blob.Length);
        Assert.Equal(new byte[] { 0x45, 0x43, 0x53, 0x33 }, blob[..4]);  // "ECS3", as the device's registration response
        Assert.Equal("key_ecs3_104", RequestSignature.KeyKind(blob));
        var signature = Sign(key, HashAlgorithmName.SHA256);
        Assert.Equal(96, signature.Length);
        Assert.True(RequestSignature.Verify(blob, Data, signature));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void Sha256SignatureVerifies(string curve)
    {
        using var key = Key(curve);
        Assert.True(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, Sign(key, HashAlgorithmName.SHA256)));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void TheHashIsAlwaysSha256(string curve)
    {
        // As the sample (BCRYPT_SHA256_ALG_HANDLE) and KeePassPasskey (SHA256.HashData): never the curve's hash.
        using var key = Key(curve);
        var blob = FakeWebAuthnApi.EcdsaBlob(key);
        Assert.False(RequestSignature.Verify(blob, Data, Sign(key, HashAlgorithmName.SHA384)));
        Assert.False(RequestSignature.Verify(blob, Data, Sign(key, HashAlgorithmName.SHA512)));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void TamperedOrMisshapedSignaturesFail(string curve)
    {
        using var key = Key(curve);
        var blob = FakeWebAuthnApi.EcdsaBlob(key);
        var signature = Sign(key, HashAlgorithmName.SHA256);
        var flipped = (byte[])signature.Clone();
        flipped[^1] ^= 1;
        Assert.False(RequestSignature.Verify(blob, Data, flipped));
        Assert.False(RequestSignature.Verify(blob, Data, signature[..^1]));
        Assert.False(RequestSignature.Verify(blob, Data, [.. signature, 0]));
        Assert.False(RequestSignature.Verify(blob, Data, Sign(key, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)));
        var data = (byte[])Data.Clone();
        data[0] ^= 1;
        Assert.False(RequestSignature.Verify(blob, data, signature));
        using var other = Key(curve);
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(other), Data, signature));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void MalformedBlobsFail(string curve)
    {
        using var key = Key(curve);
        var blob = FakeWebAuthnApi.EcdsaBlob(key);
        var signature = Sign(key, HashAlgorithmName.SHA256);
        Assert.False(RequestSignature.Verify(blob[..^1], Data, signature));
        var size = (byte[])blob.Clone();
        BitConverter.GetBytes(BitConverter.ToUInt32(blob, 4) + 1).CopyTo(size, 4);
        Assert.False(RequestSignature.Verify(size, Data, signature));
        var offCurve = (byte[])blob.Clone();
        offCurve[^1] ^= 1;
        Assert.False(RequestSignature.Verify(offCurve, Data, signature));
        // The same bytes under the matching ECDH magic ("ECK1"/"ECK3"/"ECK5") are refused.
        var ecdh = (byte[])blob.Clone();
        ecdh[2] = 0x4B;
        Assert.False(RequestSignature.Verify(ecdh, Data, signature));
    }

    [Fact]
    public void ACurveMismatchFails()
    {
        // A P-384 key blob relabelled as P-256 (or the reverse) never verifies.
        using var p384 = Key("P-384");
        var blob = FakeWebAuthnApi.EcdsaBlob(p384);
        var relabelled = (byte[])blob.Clone();
        relabelled[3] = 0x31;  // "ECS1"
        Assert.False(RequestSignature.Verify(relabelled, Data, Sign(p384, HashAlgorithmName.SHA256)));
    }

    [Theory]
    [InlineData(0x32534345u)]  // "ECS2": BCRYPT_ECDSA_PRIVATE_P256_MAGIC (a private blob)
    [InlineData(0x50444345u)]  // "ECDP": generic ECDSA public (no curve in the blob)
    [InlineData(0x33504345u)]  // unknown
    public void UnknownMagicsFailClosed(uint magic)
    {
        using var key = Key("P-384");
        var blob = FakeWebAuthnApi.EcdsaBlob(key);
        BitConverter.GetBytes(magic).CopyTo(blob, 0);
        Assert.False(RequestSignature.Verify(blob, Data, Sign(key, HashAlgorithmName.SHA256)));
    }

    [Fact]
    public void CurveOrdersComeFromTheStandard()
    {
        Assert.Equal(new System.Numerics.BigInteger(
                         Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
                         isUnsigned: true, isBigEndian: true), RequestSignature.EcdsaOrder(64));
        // FIPS 186-4 D.1.2.4 (P-384) n.
        Assert.Equal(new System.Numerics.BigInteger(Convert.FromHexString(
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
                         isUnsigned: true, isBigEndian: true), RequestSignature.EcdsaOrder(96));
        Assert.NotNull(RequestSignature.EcdsaOrder(132));
        Assert.Null(RequestSignature.EcdsaOrder(256));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void MalleatedTwinIsAReplay(string curve)
    {
        using var key = Key(curve);
        var signature = Sign(key, HashAlgorithmName.SHA256);
        var twin = PluginAuthenticatorTests.Malleate(signature);
        Assert.NotEqual(signature, twin);
        Assert.True(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, twin));
        Assert.Equal(ReplayCache.Canonical(signature), ReplayCache.Canonical(twin));
        var cache = new ReplayCache();
        Assert.True(cache.TryAccept(signature));
        Assert.False(cache.TryAccept(twin));
    }

    [Fact]
    public void P384ProviderRunsTheWholeCeremony()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()),
                                                curve: ECCurve.NamedCurves.nistP384);
        Assert.Equal(104, harness.Api.PublicKeyBlob().Length);
        var signature = harness.GoodSignature();
        Assert.Equal(HResults.SOk, harness.Call(create: true, signature).Hr);
        Assert.Equal(HResults.NteBadSignature,
                     harness.Call(create: true, PluginAuthenticatorTests.Malleate(signature), Guid.NewGuid()).Hr);
        Assert.Single(harness.Pipe.Sent);
        Assert.Equal("ok", harness.Log.Records.First().Outcome);
    }
}
