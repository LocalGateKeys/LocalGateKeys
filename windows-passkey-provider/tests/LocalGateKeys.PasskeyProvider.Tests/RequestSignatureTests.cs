using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public partial class RequestSignatureTests
{
    private static readonly byte[] Data = "encoded ctap request"u8.ToArray();

    private static byte[] Sign(ECDsa key, byte[] data) =>
        key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    [Fact]
    public void GoodSignaturePasses()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.True(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, Sign(key, Data)));
    }

    [Fact]
    public void FlippedSignatureByteFails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = Sign(key, Data);
        signature[10] ^= 0x01;
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, signature));
    }

    [Fact]
    public void FlippedDataByteFails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = Sign(key, Data);
        var data = (byte[])Data.Clone();
        data[0] ^= 0x80;
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), data, signature));
    }

    [Fact]
    public void WrongKeyFails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(other), Data, Sign(key, Data)));
    }

    [Fact]
    public void EmptySignatureFails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, []));
    }

    [Fact]
    public void DerSignatureIsNotAccepted()
    {
        // NCryptVerifySignature (the sample's call) takes r||s for ECDSA; a DER form is something else.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = key.SignData(Data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(RequestSignature.Verify(FakeWebAuthnApi.EcdsaBlob(key), Data, der));
    }

    [Fact]
    public void MalformedKeyBlobsFail()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = Sign(key, Data);
        var blob = FakeWebAuthnApi.EcdsaBlob(key);

        Assert.False(RequestSignature.Verify([], Data, signature));
        Assert.False(RequestSignature.Verify(blob[..^1], Data, signature));                 // truncated
        Assert.False(RequestSignature.Verify([.. blob, 0], Data, signature));               // trailing byte
        var ecdh = (byte[])blob.Clone();
        BitConverter.GetBytes(0x314B4345u).CopyTo(ecdh, 0);                                 // ECDH P-256 magic
        Assert.False(RequestSignature.Verify(ecdh, Data, signature));
        var size = (byte[])blob.Clone();
        BitConverter.GetBytes(48u).CopyTo(size, 4);                                         // cbKey not 32
        Assert.False(RequestSignature.Verify(size, Data, signature));
        var offCurve = (byte[])blob.Clone();
        offCurve[^1] ^= 0x01;                                                               // Y not on the curve
        Assert.False(RequestSignature.Verify(offCurve, Data, signature));
    }

    private static byte[] RsaBlob(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        var blob = new List<byte>();
        blob.AddRange(BitConverter.GetBytes(0x31415352u));  // BCRYPT_RSAPUBLIC_MAGIC
        blob.AddRange(BitConverter.GetBytes((uint)rsa.KeySize));
        blob.AddRange(BitConverter.GetBytes((uint)p.Exponent!.Length));
        blob.AddRange(BitConverter.GetBytes((uint)p.Modulus!.Length));
        blob.AddRange(BitConverter.GetBytes(0u));
        blob.AddRange(BitConverter.GetBytes(0u));
        blob.AddRange(p.Exponent);
        blob.AddRange(p.Modulus);
        return [.. blob];
    }

    [Fact]
    public void RsaPssPassesAndPkcs1Fails()
    {
        using var rsa = RSA.Create(2048);
        var blob = RsaBlob(rsa);
        var pss = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var pkcs1 = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(RequestSignature.Verify(blob, Data, pss));
        Assert.False(RequestSignature.Verify(blob, Data, pkcs1));
        pss[5] ^= 0x01;
        Assert.False(RequestSignature.Verify(blob, Data, pss));
    }

    [Fact]
    public void ShortRsaKeyFails()
    {
        using var rsa = RSA.Create(1024);
        var pss = rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.False(RequestSignature.Verify(RsaBlob(rsa), Data, pss));
    }

    [Fact]
    public void RsaLimitsAgreeWithTheSignatureLimit()
    {
        Assert.Equal(8192, RequestSignature.MaxRsaBits);
        Assert.Equal(RequestSignature.MaxSignatureLength, RequestSignature.MaxRsaBits / 8);
        // A blob claiming 8200 bits (a 1025-byte signature) is refused before any verification.
        var modulus = new byte[1025];
        modulus[0] = 0x80;
        modulus[^1] = 0x01;
        var blob = new List<byte>();
        foreach (var value in new uint[] { 0x31415352, 8200, 3, 1025, 0, 0 })
            blob.AddRange(BitConverter.GetBytes(value));
        blob.AddRange(new byte[] { 1, 0, 1 });
        blob.AddRange(modulus);
        Assert.False(RequestSignature.Verify([.. blob], Data, new byte[1024]));
    }

    [Theory]
    [InlineData(2048, 222)]
    [InlineData(3072, 350)]
    public void PssSaltLengthsAreHashLengthAndMaximum(int bits, int maximum) =>
        Assert.Equal([32, maximum], RequestSignature.PssSaltLengths(bits));

    /// <summary>Signs with CNG's own PSS and an explicit salt length (.NET only offers the hash length).</summary>
    private static unsafe byte[] SignPss(RSACng rsa, byte[] data, int salt)
    {
        var hash = SHA256.HashData(data);
        var signature = new byte[rsa.KeySize / 8];
        fixed (char* algorithm = "SHA256")
        fixed (byte* pHash = hash)
        fixed (byte* pSignature = signature)
        {
            var padding = new PssPadding { AlgId = algorithm, Salt = (uint)salt };
            var status = NCryptSignHash(rsa.Key.Handle, &padding, pHash, (uint)hash.Length, pSignature,
                                        (uint)signature.Length, out var written, 8 /* BCRYPT_PAD_PSS */);
            Assert.Equal(0, status);
            Assert.Equal(signature.Length, (int)written);
        }
        return signature;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct PssPadding
    {
        public char* AlgId;
        public uint Salt;
    }

    [LibraryImport("ncrypt.dll")]
    private static unsafe partial int NCryptSignHash(Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle key, void* padding,
                                              byte* hash, uint hashLength, byte* signature, uint signatureLength,
                                              out uint written, uint flags);

    [Fact]
    public void RsaPssWithMaximumSaltPassesAndOtherSaltsFail()
    {
        using var rsa = new RSACng(2048);
        var blob = RsaBlob(rsa);
        Assert.True(RequestSignature.Verify(blob, Data, SignPss(rsa, Data, 32)));
        Assert.True(RequestSignature.Verify(blob, Data, SignPss(rsa, Data, 222)));
        Assert.False(RequestSignature.Verify(blob, Data, SignPss(rsa, Data, 20)));
        Assert.False(RequestSignature.Verify(blob, Data, SignPss(rsa, Data, 0)));
    }

    // -- PluginAuthenticator: nothing reaches the pipe without a valid signature ------------------------------

    public static TheoryData<bool> Ceremonies => new() { true, false };

    [Theory]
    [MemberData(nameof(Ceremonies))]
    public void BadSignatureIsRejectedBeforeDecodeAndPipe(bool create)
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        var signature = harness.GoodSignature();
        signature[0] ^= 0x01;

        var (hr, response) = harness.Call(create, signature);

        Assert.Equal(HResults.NteBadSignature, hr);
        Assert.Null(response);
        Assert.Empty(harness.Pipe.Sent);
        Assert.Equal(0, harness.Launcher.Calls);
        Assert.Equal(0, harness.Foreground.Calls);
        Assert.Equal(["key"], harness.Api.Calls.ToArray());  // no decode, no encode
    }

    [Theory]
    [MemberData(nameof(Ceremonies))]
    public void EmptySignatureIsRejected(bool create)
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        Assert.Equal(HResults.NteBadSignature, harness.Call(create, []).Hr);
        Assert.Empty(harness.Pipe.Sent);
    }

    [Theory]
    [MemberData(nameof(Ceremonies))]
    public void SignatureFromAnotherKeyIsRejected(bool create)
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Equal(HResults.NteBadSignature, harness.Call(create, Sign(other, ProviderHarness.Encoded)).Hr);
        Assert.Empty(harness.Pipe.Sent);
    }

    [Theory]
    [MemberData(nameof(Ceremonies))]
    public void MissingSigningKeyRejects(bool create)
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Api.KeyHr = HResults.NteNotFound;
        Assert.Equal(HResults.NteBadSignature, harness.Call(create, harness.GoodSignature()).Hr);
        Assert.Empty(harness.Pipe.Sent);
    }

    [Fact]
    public async Task CancelWithBadSignatureCancelsNothing()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(), ProviderHarness.ShortTimings);
        var call = Task.Run(() => harness.Call(create: true, null));
        WaitFor(() => harness.Pipe.Of("passkey_create_system").Length == 1);

        var bad = harness.Api.Sign(ProviderHarness.Encoded);
        bad[3] ^= 0x01;
        Assert.Equal(HResults.NteBadSignature, harness.Cancel(bad));
        Assert.Equal(HResults.NteBadSignature, harness.Cancel([]));
        // A signature over the transaction id instead of the request does not verify either.
        Assert.Equal(HResults.NteBadSignature, harness.Cancel(harness.Api.Sign(ProviderHarness.Txn.ToByteArray())));
        Assert.Empty(harness.Pipe.Of("passkey_cancel_system"));

        // The ceremony is still pending: it ends at its own timer, not by the forged cancel.
        var (hr, _) = await call;
        Assert.Equal(HResults.Timeout, hr);
    }

    [Fact]
    public async Task ValidCancelReachesTheApp()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(), ProviderHarness.LongTimings);
        var watch = Stopwatch.StartNew();
        var call = Task.Run(() => harness.Call(create: false, null));
        WaitFor(() => harness.Pipe.Of("passkey_get_system").Length == 1);

        Assert.Equal(HResults.SOk, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));

        var (hr, response) = await call;
        Assert.Equal(HResults.Cancelled, hr);
        Assert.Null(response);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10));
        var cancel = Assert.Single(harness.Pipe.Of("passkey_cancel_system"));
        Assert.Equal(ProviderHarness.TxnText, (string?)cancel["transaction_id"]);
    }

    [Fact]
    public void CancelOfUnknownTransactionIsNotFound()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent());
        Assert.Equal(HResults.NteNotFound, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));
        Assert.Empty(harness.Pipe.Sent);
    }

    [Fact]
    public void CancelSignedDataIsTheEncodedRequest()
    {
        // UNVERIFIED (U15) in one place: PluginAuthenticator.CancelSignedData.
        Assert.True(PluginAuthenticator.CancelSignedData(ProviderHarness.Encoded).SequenceEqual(ProviderHarness.Encoded));
    }

    internal static void WaitFor(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(10))
                throw new TimeoutException("condition not reached");
            Thread.Sleep(10);
        }
    }

    [Fact]
    public void ReplyIsNotTrustedWithoutTheRequestSignature()
    {
        // Sanity: the same harness answers a correctly signed request (so the rejections above are the signature).
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        Assert.Equal(HResults.SOk, harness.Call(create: true, null).Hr);
        Assert.Single(harness.Pipe.Sent);
    }
}
