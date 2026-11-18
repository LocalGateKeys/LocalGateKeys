using System.Reflection;
using LocalGateKeys.PasskeyProvider.Provider;

namespace LocalGateKeys.PasskeyProvider.Commands;

/// <summary>
/// The CTAP2 <c>authenticatorGetInfo</c> response handed to <c>WebAuthNPluginAddAuthenticator</c>:
/// <c>{1: ["FIDO_2_0", "FIDO_2_1"], 3: aaguid, 4: {"rk": true, "up": true, "uv": true}}</c> in CTAP2 canonical CBOR
/// (integer keys ascending; text keys by length, then bytewise).
/// </summary>
public static class GetInfo
{
    public static readonly string[] Versions = ["FIDO_2_0", "FIDO_2_1"];

    public static byte[] Build(byte[] aaguid)
    {
        if (aaguid.Length != 16)
            throw new ArgumentException("an AAGUID is 16 bytes", nameof(aaguid));
        var cbor = new List<byte> { 0xA3 };                       // map(3)
        cbor.Add(0x01);                                           // 1: versions
        cbor.Add((byte)(0x80 | Versions.Length));                 // array(2)
        foreach (var version in Versions)
            Text(cbor, version);
        cbor.Add(0x03);                                           // 3: aaguid
        cbor.Add(0x50);                                           // bytes(16)
        cbor.AddRange(aaguid);
        cbor.Add(0x04);                                           // 4: options
        cbor.Add(0xA3);                                           // map(3)
        foreach (var option in new[] { "rk", "up", "uv" })
        {
            Text(cbor, option);
            cbor.Add(0xF5);                                       // true
        }
        return [.. cbor];
    }

    private static void Text(List<byte> cbor, string value)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(value);
        if (bytes.Length > 23)
            throw new ArgumentException("short strings only", nameof(value));
        cbor.Add((byte)(0x60 | bytes.Length));
        cbor.AddRange(bytes);
    }

    public static byte[] ForProvider() => Build(ProviderIds.AaguidBytes());

    /// <summary>Base64 of an embedded SVG logo (<c>assets/provider-light.svg</c> or <c>provider-dark.svg</c>).</summary>
    public static string LogoBase64(bool dark)
    {
        var name = dark ? "LocalGateKeys.PasskeyProvider.provider-dark.svg" : "LocalGateKeys.PasskeyProvider.provider-light.svg";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
                           ?? throw new InvalidOperationException("logo resource missing");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return Convert.ToBase64String(buffer.ToArray());
    }
}
