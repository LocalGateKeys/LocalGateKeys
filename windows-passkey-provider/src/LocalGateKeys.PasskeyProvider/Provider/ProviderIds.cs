namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>Fixed identities of the provider. Never change any of them: Windows keys the registration on the CLSID.</summary>
public static class ProviderIds
{
    /// <summary>The COM class Windows activates (MSIX manifest <c>com:Class Id</c>, Task 8). Fixed forever.</summary>
    public static readonly Guid Clsid = new("f1d767c8-6f3e-43a6-953c-d3c1f7a8c414");

    /// <summary>Same AAGUID as the extension path (<c>passkeys.AAGUID</c>, src/localvault/passkeys.py).</summary>
    public const string AaguidText = "b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41";

    /// <summary>The AAGUID in RFC 4122 byte order, as Python's <c>uuid.UUID(...).bytes</c>.</summary>
    public static byte[] AaguidBytes() => Convert.FromHexString(AaguidText.Replace("-", "", StringComparison.Ordinal));

    public const string PluginRpId = "localgatekeys.app";
    public const string Name = "LocalGateKeys";
}
