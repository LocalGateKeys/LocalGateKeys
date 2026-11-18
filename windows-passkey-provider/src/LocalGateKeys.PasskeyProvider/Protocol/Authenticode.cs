using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>
/// Embedded Authenticode signer of a file (<c>_authenticode_thumbprint</c> in <c>pipe_transport.py</c>): the
/// SHA-256 thumbprint of the signer certificate when <c>WinVerifyTrust</c> says the signature is valid, else null.
/// No revocation lookup (offline, no network on the sign-in path).
/// </summary>
public static class Authenticode
{
    public static string? SignerThumbprint(string path)
    {
        try
        {
            if (!File.Exists(path) || !Verify(path))
                return null;
#pragma warning disable SYSLIB0057 // the signer certificate of a signed file, not a certificate file
            using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return signer.GetCertHashString(HashAlgorithmName.SHA256);
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>A development (Debug) build may run unsigned and unpackaged; a release build never may.</summary>
#if DEBUG
    internal const bool UnsignedUnpackagedSelfAllowed = true;
#else
    internal const bool UnsignedUnpackagedSelfAllowed = false;
#endif

    /// <summary>
    /// The pin rule shared with the agent (<c>_frozen_checks</c>): a signed self requires the same signer on the
    /// other side. When the own signer cannot be read (unsigned, or <c>WinVerifyTrust</c> failed), the check fails
    /// closed, except when <paramref name="packaged"/> (the caller already required the peer's package family to
    /// equal its own: Store and test packages carry only the package signature, their exes are unsigned) or in a
    /// Debug build.
    /// </summary>
    public static bool SameSigner(string? self, string? other, bool packaged) =>
        self is null
            ? packaged || UnsignedUnpackagedSelfAllowed
            : other is not null && CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(self), System.Text.Encoding.ASCII.GetBytes(other));

    private static unsafe bool Verify(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var file = new NativeMethods.WintrustFileInfo
            {
                StructSize = (uint)sizeof(NativeMethods.WintrustFileInfo),
                FilePath = pathPtr,
            };
            var data = new NativeMethods.WintrustData
            {
                StructSize = (uint)sizeof(NativeMethods.WintrustData),
                UiChoice = NativeMethods.WtdUiNone,
                RevocationChecks = NativeMethods.WtdRevokeNone,
                UnionChoice = NativeMethods.WtdChoiceFile,
                FileInfo = (IntPtr)(&file),
                StateAction = NativeMethods.WtdStateActionVerify,
                ProvFlags = NativeMethods.WtdRevocationCheckNone | NativeMethods.WtdCacheOnlyUrlRetrieval,
            };
            var action = NativeMethods.WintrustActionGenericVerifyV2;
            var result = NativeMethods.WinVerifyTrust(new IntPtr(-1), &action, &data);
            data.StateAction = NativeMethods.WtdStateActionClose;
            NativeMethods.WinVerifyTrust(new IntPtr(-1), &action, &data);
            return result == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
        }
    }
}
