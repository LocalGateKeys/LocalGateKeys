using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>
/// Checks <c>pbRequestSignature</c>, the only proof that a call came from Windows (design note section 9).
/// <para>
/// The key comes from <c>WebAuthNPluginGetOperationSigningPublicKey</c> at run time. Its format follows the
/// Microsoft sample ([S4] PluginAuthenticatorImpl.cpp, <c>VerifySignatureHelper</c>): a CNG
/// <c>BCRYPT_PUBLIC_KEY_BLOB</c> imported with <c>NCryptImportKey</c>, SHA-256 over the encoded request, then
/// <c>NCryptVerifySignature</c>: no padding for ECDSA (so the signature is IEEE P1363 r||s) and PSS for an RSA key.
/// Accepted here: the ECDSA public blobs <c>BCRYPT_ECDSA_PUBLIC_P256_MAGIC</c> (ECS1), <c>..._P384_MAGIC</c> (ECS3)
/// and <c>..._P521_MAGIC</c> (ECS5), and <c>BCRYPT_RSAPUBLIC_MAGIC</c> with a 2048- to 8192-bit modulus (so a
/// signature always fits <see cref="MaxSignatureLength"/>). Anything else, an empty or malformed signature, or a blob
/// of the wrong length fails: unverifiable means rejected.
/// </para>
/// <para>
/// The hash is SHA-256 for every key, whatever the curve: the sample hashes with <c>BCRYPT_SHA256_ALG_HANDLE</c>
/// before <c>NCryptVerifySignature</c> for any key type, and KeePassPasskey ([S10]) does the same
/// (<c>SHA256.HashData</c>, then <c>ECDsaCng.VerifyHash</c>) and enforces the result. The first device test
/// (Windows build 26300) showed an ECS3 (P-384) operation key; its signature is then 96 bytes r||s. DER is not
/// accepted: the sample passes the raw signature to <c>NCryptVerifySignature</c>, which takes r||s only.
/// </para>
/// <para>
/// RSA-PSS salt: the sample passes <c>cbSalt = 32</c> (the SHA-256 length). Which salt a TPM-held key signs with is
/// UNVERIFIED (part of U15's owner check): TPM 2.0 signers may use the largest salt the key allows. Exactly these
/// two lengths are accepted, each verified by CNG itself (<c>BCryptVerifySignature</c>, <c>BCRYPT_PAD_PSS</c>);
/// any other salt fails closed.
/// </para>
/// </summary>
public static partial class RequestSignature
{
    public const int MaxSignatureLength = 1024;
    public const int MinRsaBits = 2048;
    public const int MaxRsaBits = MaxSignatureLength * 8;
    public const int HashLength = 32;

    private const uint EcdsaPublicP256Magic = 0x31534345;  // BCRYPT_ECDSA_PUBLIC_P256_MAGIC "ECS1" (bcrypt.h)
    private const uint EcdsaPublicP384Magic = 0x33534345;  // BCRYPT_ECDSA_PUBLIC_P384_MAGIC "ECS3" (bcrypt.h)
    private const uint EcdsaPublicP521Magic = 0x35534345;  // BCRYPT_ECDSA_PUBLIC_P521_MAGIC "ECS5" (bcrypt.h)
    private const uint RsaPublicMagic = 0x31415352;        // BCRYPT_RSAPUBLIC_MAGIC "RSA1" (bcrypt.h)
    private const int EccHeader = 8;                       // BCRYPT_ECCKEY_BLOB { ULONG Magic; ULONG cbKey; }
    private const int RsaHeader = 24;                      // BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2

    /// <summary>One accepted ECDSA curve: its blob coordinate size (cbKey) and its .NET curve.</summary>
    private sealed record EcdsaCurve(int Coordinate, ECCurve Curve);

    private static EcdsaCurve? CurveFor(uint magic) => magic switch
    {
        EcdsaPublicP256Magic => new EcdsaCurve(32, ECCurve.NamedCurves.nistP256),
        EcdsaPublicP384Magic => new EcdsaCurve(48, ECCurve.NamedCurves.nistP384),
        EcdsaPublicP521Magic => new EcdsaCurve(66, ECCurve.NamedCurves.nistP521),
        _ => null,
    };

    public static bool Verify(ReadOnlySpan<byte> keyBlob, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (keyBlob.Length < 4 || signature.IsEmpty || signature.Length > MaxSignatureLength)
            return false;
        try
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(keyBlob) switch
            {
                RsaPublicMagic => VerifyRsa(keyBlob, data, signature),
                var magic when CurveFor(magic) is { } curve => VerifyEcdsa(keyBlob, curve, data, signature),
                _ => false,
            };
        }
        catch (Exception)
        {
            // CryptographicException, or PlatformNotSupportedException for a point that is not on the curve.
            return false;
        }
    }

    private static bool VerifyEcdsa(ReadOnlySpan<byte> blob, EcdsaCurve curve, ReadOnlySpan<byte> data,
                                    ReadOnlySpan<byte> signature)
    {
        var size = curve.Coordinate;
        if (blob.Length != EccHeader + 2 * size || BinaryPrimitives.ReadUInt32LittleEndian(blob[4..]) != size
            || signature.Length != 2 * size)
            return false;
        var parameters = new ECParameters
        {
            Curve = curve.Curve,
            Q = new ECPoint
            {
                X = blob.Slice(EccHeader, size).ToArray(),
                Y = blob.Slice(EccHeader + size, size).ToArray(),
            },
        };
        using var ecdsa = ECDsa.Create(parameters);  // rejects a point that is not on the curve
        // SHA-256 for every curve, as the sample and KeePassPasskey (see the class remarks).
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// The group order n of the ECDSA curve whose r||s signatures are <paramref name="signatureLength"/> bytes long
    /// (64: P-256, 96: P-384, 132: P-521), or null for any other length (RSA signatures are 256 bytes or more).
    /// Taken from .NET's explicit curve parameters, so no constant is typed in by hand.
    /// </summary>
    public static System.Numerics.BigInteger? EcdsaOrder(int signatureLength) => signatureLength switch
    {
        64 => P256Order.Value,
        96 => P384Order.Value,
        132 => P521Order.Value,
        _ => null,
    };

    private static readonly Lazy<System.Numerics.BigInteger> P256Order = new(() => Order(ECCurve.NamedCurves.nistP256));
    private static readonly Lazy<System.Numerics.BigInteger> P384Order = new(() => Order(ECCurve.NamedCurves.nistP384));
    private static readonly Lazy<System.Numerics.BigInteger> P521Order = new(() => Order(ECCurve.NamedCurves.nistP521));

    private static System.Numerics.BigInteger Order(ECCurve named)
    {
        using var key = ECDsa.Create(named);
        var order = key.ExportExplicitParameters(false).Curve.Order!;
        return new System.Numerics.BigInteger(order, isUnsigned: true, isBigEndian: true);
    }

    /// <summary>
    /// The key blob's kind and length as one fixed word (diagnostics only; a public key's type is not secret):
    /// <c>key_ecs1_72</c>, <c>key_rsa1_&lt;bytes&gt;</c>, or <c>key_magic_&lt;hex&gt;_&lt;bytes&gt;</c> for any other
    /// CNG magic (for example ECDP generic or ECK1 ECDH, which this provider refuses).
    /// </summary>
    public static string KeyKind(ReadOnlySpan<byte> keyBlob)
    {
        if (keyBlob.Length < 4)
            return "key_short_" + keyBlob.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var length = keyBlob.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return BinaryPrimitives.ReadUInt32LittleEndian(keyBlob) switch
        {
            EcdsaPublicP256Magic => "key_ecs1_" + length,
            EcdsaPublicP384Magic => "key_ecs3_" + length,
            EcdsaPublicP521Magic => "key_ecs5_" + length,
            RsaPublicMagic => "key_rsa1_" + length,
            var magic => "key_magic_" + magic.ToString("x8", System.Globalization.CultureInfo.InvariantCulture) + "_" + length,
        };
    }

    /// <summary>The two accepted PSS salt lengths for a modulus of <paramref name="bits"/> bits with SHA-256.</summary>
    public static int[] PssSaltLengths(int bits)
    {
        var emLength = (bits - 1 + 7) / 8;                 // RFC 8017 9.1: emLen = ceil((modBits - 1) / 8)
        var maximum = emLength - HashLength - 2;
        return maximum == HashLength ? [HashLength] : [HashLength, maximum];
    }

    private static bool VerifyRsa(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (blob.Length < RsaHeader)
            return false;
        var bits = BinaryPrimitives.ReadUInt32LittleEndian(blob[4..]);
        var cbExp = BinaryPrimitives.ReadUInt32LittleEndian(blob[8..]);
        var cbMod = BinaryPrimitives.ReadUInt32LittleEndian(blob[12..]);
        var cbP1 = BinaryPrimitives.ReadUInt32LittleEndian(blob[16..]);
        var cbP2 = BinaryPrimitives.ReadUInt32LittleEndian(blob[20..]);
        if (bits < MinRsaBits || bits > MaxRsaBits || cbP1 != 0 || cbP2 != 0 || cbExp is 0 or > 8
            || cbMod != (bits + 7) / 8 || blob.Length != RsaHeader + cbExp + cbMod || signature.Length != cbMod)
            return false;
        var hash = SHA256.HashData(data);
        foreach (var salt in PssSaltLengths((int)bits))
        {
            if (BCryptPssVerify(blob, hash, signature, salt))
                return true;
        }
        return false;
    }

    private static unsafe bool BCryptPssVerify(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> hash,
                                               ReadOnlySpan<byte> signature, int salt)
    {
        nint algorithm = 0;
        nint key = 0;
        try
        {
            if (BCryptOpenAlgorithmProvider(out algorithm, "RSA", null, 0) != 0)
                return false;
            fixed (byte* pBlob = blob)
            fixed (byte* pHash = hash)
            fixed (byte* pSignature = signature)
            fixed (char* sha256 = "SHA256")
            {
                if (BCryptImportKeyPair(algorithm, 0, "RSAPUBLICBLOB", out key, pBlob, (uint)blob.Length, 0) != 0)
                    return false;
                var padding = new BCryptPssPaddingInfo { pszAlgId = sha256, cbSalt = (uint)salt };
                return BCryptVerifySignature(key, &padding, pHash, (uint)hash.Length, pSignature,
                                             (uint)signature.Length, BCryptPadPss) == 0;
            }
        }
        finally
        {
            if (key != 0)
                _ = BCryptDestroyKey(key);
            if (algorithm != 0)
                _ = BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    }

    private const uint BCryptPadPss = 0x00000008;  // BCRYPT_PAD_PSS (bcrypt.h)

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct BCryptPssPaddingInfo     // BCRYPT_PSS_PADDING_INFO (bcrypt.h)
    {
        public char* pszAlgId;
        public uint cbSalt;
    }

    [LibraryImport("bcrypt.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptOpenAlgorithmProvider(out nint algorithm, string algId, string? implementation,
                                                           uint flags);

    [LibraryImport("bcrypt.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int BCryptImportKeyPair(nint algorithm, nint importKey, string blobType, out nint key,
                                                          byte* input, uint inputLength, uint flags);

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int BCryptVerifySignature(nint key, void* paddingInfo, byte* hash, uint hashLength,
                                                            byte* signature, uint signatureLength, uint flags);

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptDestroyKey(nint key);

    [LibraryImport("bcrypt.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int BCryptCloseAlgorithmProvider(nint algorithm, uint flags);
}
