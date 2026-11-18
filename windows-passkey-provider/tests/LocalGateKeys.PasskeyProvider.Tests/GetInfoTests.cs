using System.Text;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Provider;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class GetInfoTests
{
    [Fact]
    public void ExactCanonicalCbor()
    {
        // {1: ["FIDO_2_0", "FIDO_2_1"], 3: h'b7d2a6f01c4e4a5b9e3d5a1f7c2e8d41', 4: {"rk": true, "up": true, "uv": true}}
        const string expected =
            "A3" +
            "01" + "82" + "68" + "4649444F5F325F30" + "68" + "4649444F5F325F31" +
            "03" + "50" + "B7D2A6F01C4E4A5B9E3D5A1F7C2E8D41" +
            "04" + "A3" + "62" + "726B" + "F5" + "62" + "7570" + "F5" + "62" + "7576" + "F5";
        Assert.Equal(expected, Convert.ToHexString(GetInfo.ForProvider()));
    }

    [Fact]
    public void AaguidMatchesThePythonConstant()
    {
        // passkeys.AAGUID = uuid.UUID("b7d2a6f0-1c4e-4a5b-9e3d-5a1f7c2e8d41").bytes (RFC 4122 order).
        Assert.Equal("B7D2A6F01C4E4A5B9E3D5A1F7C2E8D41", Convert.ToHexString(ProviderIds.AaguidBytes()));
    }

    [Fact]
    public void FixedIdentities()
    {
        Assert.Equal(new Guid("f1d767c8-6f3e-43a6-953c-d3c1f7a8c414"), ProviderIds.Clsid);
        Assert.Equal("localgatekeys.app", ProviderIds.PluginRpId);
        Assert.Equal("LocalGateKeys", ProviderIds.Name);
    }

    [Fact]
    public void RejectsWrongAaguidLength() => Assert.Throws<ArgumentException>(() => GetInfo.Build(new byte[15]));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LogosAreBase64Svg(bool dark)
    {
        var svg = Encoding.UTF8.GetString(Convert.FromBase64String(GetInfo.LogoBase64(dark)));
        Assert.StartsWith("<svg xmlns=\"http://www.w3.org/2000/svg\"", svg);
        Assert.DoesNotContain("\r", svg);
        Assert.DoesNotContain("<script", svg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LightAndDarkDiffer() => Assert.NotEqual(GetInfo.LogoBase64(false), GetInfo.LogoBase64(true));
}
