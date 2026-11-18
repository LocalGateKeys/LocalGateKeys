using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class CliTests
{
    private static readonly Guid TestClsid = ProviderHarness.TestClsid;

    private static (int Code, JsonObject Output, FakeWebAuthnApi Api, int ComRuns) Run(
        string[] args, bool buildSupported = true, Action<FakeWebAuthnApi>? setup = null)
    {
        var api = new FakeWebAuthnApi();
        setup?.Invoke(api);
        var output = new StringWriter();
        var comRuns = 0;
        var context = new CliContext(output, api, TestClsid, () => buildSupported, () =>
        {
            comRuns++;
            return 0;
        });
        var code = Cli.Run(args, context);
        var text = output.ToString();
        var json = text.Length == 0 ? new JsonObject() : JsonNode.Parse(text)!.AsObject();
        return (code, json, api, comRuns);
    }

    [Fact]
    public void StateOfAnUnregisteredClsidIsNotRegistered()
    {
        var (code, output, api, _) = Run(["--state"]);
        Assert.Equal(0, code);
        Assert.True(JsonNode.DeepEquals(
            new JsonObject { ["ok"] = true, ["build_supported"] = true, ["state"] = "not_registered" }, output));
        Assert.Equal(["state"], api.Calls.ToArray());
    }

    [Theory]
    [InlineData(1, "enabled")]
    [InlineData(0, "disabled")]
    public void StateRegistered(int state, string expected)
    {
        var (code, output, _, _) = Run(["--state"], setup: api =>
        {
            api.StateHr = HResults.SOk;
            api.State = state;
        });
        Assert.Equal(0, code);
        Assert.Equal(expected, (string?)output["state"]);
    }

    [Fact]
    public void StateOnAnOldBuildCallsNothing()
    {
        var (code, output, api, _) = Run(["--state"], buildSupported: false);
        Assert.Equal(0, code);
        Assert.Equal("unsupported_build", (string?)output["state"]);
        Assert.False((bool)output["build_supported"]!);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void StateErrorShowsTheHResult()
    {
        var (code, output, _, _) = Run(["--state"], setup: api => api.StateHr = unchecked((int)0x80090029));
        Assert.Equal(1, code);
        Assert.Equal("0x80090029", (string?)output["hresult"]);
    }

    [Fact]
    public void RegisterPassesTheProviderIdentity()
    {
        var (code, output, api, _) = Run(["--register"]);
        Assert.Equal(0, code);
        Assert.True((bool)output["ok"]!);
        var registration = api.Registered!;
        Assert.Equal(TestClsid, registration.Clsid);
        Assert.Equal("LocalGateKeys", registration.Name);
        Assert.Equal("localgatekeys.app", registration.PluginRpId);
        Assert.Equal(GetInfo.ForProvider(), registration.AuthenticatorInfo);
        Assert.Equal(GetInfo.LogoBase64(dark: false), registration.LightLogoSvgBase64);
        Assert.Equal(GetInfo.LogoBase64(dark: true), registration.DarkLogoSvgBase64);
        Assert.Equal(["add"], api.Calls.ToArray());
    }

    [Fact]
    public void RegisterOnAnOldBuildIsRefused()
    {
        var (code, output, api, _) = Run(["--register"], buildSupported: false);
        Assert.Equal(1, code);
        Assert.Equal("unsupported_build", (string?)output["error"]);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void RegisterFailureReportsTheHResult()
    {
        var (code, output, _, _) = Run(["--register"], setup: api => api.AddHr = unchecked((int)0x80090029));
        Assert.Equal(1, code);
        Assert.Equal("register_failed", (string?)output["error"]);
        Assert.Equal("0x80090029", (string?)output["hresult"]);
    }

    [Fact]
    public void UnregisterRemovesCredentialsThenTheAuthenticator()
    {
        var (code, output, api, _) = Run(["--unregister"]);
        Assert.Equal(0, code);
        Assert.True((bool)output["ok"]!);
        Assert.Equal(["remove_all", "remove"], api.Calls.ToArray());
    }

    [Fact]
    public void UnregisterWhenAlreadyGoneIsOk()
    {
        var (code, _, _, _) = Run(["--unregister"], setup: api =>
        {
            api.RemoveAllHr = HResults.NteNotFound;
            api.RemoveHr = HResults.NteNotFound;
        });
        Assert.Equal(0, code);
    }

    [Fact]
    public void UnregisterStillRemovesTheAuthenticatorWhenCredentialsFail()
    {
        var (code, output, api, _) = Run(["--unregister"], setup: api => api.RemoveAllHr = HResults.EFail);
        Assert.Equal(1, code);
        Assert.Equal(["remove_all", "remove"], api.Calls.ToArray());
        Assert.Equal("0x80004005", (string?)output["hresult"]);
    }

    [Fact]
    public void PluginActivatedRunsTheComServer()
    {
        var (code, _, api, comRuns) = Run(["-PluginActivated"]);
        Assert.Equal(0, code);
        Assert.Equal(1, comRuns);
        Assert.Empty(api.Calls);
    }

    // Device bug 2026-11-09: COM launches the server as "-PluginActivated -Embedding"; the old exact one-argument
    // check printed "usage" and exited, so the class was never registered (DCOM event 10010).
    [Theory]
    [InlineData("-PluginActivated", "-Embedding")]
    [InlineData("-PluginActivated", "/Embedding")]
    [InlineData("-Embedding", "-PluginActivated")]
    [InlineData("-pluginactivated", "-EMBEDDING")]
    [InlineData("-Embedding")]
    [InlineData("/Embedding")]
    public void ComLaunchLinesRunTheComServer(params string[] args)
    {
        var (code, output, api, comRuns) = Run(args);
        Assert.Equal(0, code);
        Assert.Equal(1, comRuns);
        Assert.Empty(api.Calls);
        Assert.Empty(output);  // nothing printed: a COM launch has no console to read it
    }

    [Theory]
    [InlineData("--register", "-x")]
    [InlineData("--state", "--state")]
    [InlineData("PluginActivated")]
    [InlineData("--PluginActivated")]
    public void OtherLinesAreNotComLaunches(params string[] args)
    {
        Assert.False(Cli.IsComActivation(args));
        var (code, _, _, comRuns) = Run(args);
        Assert.Equal(2, code);
        Assert.Equal(0, comRuns);
    }

    [Theory]
    [InlineData]
    [InlineData("--bogus")]
    [InlineData("--state", "--register")]
    public void UsageErrors(params string[] args)
    {
        var (code, output, api, comRuns) = Run(args);
        Assert.Equal(2, code);
        Assert.Equal("usage", (string?)output["error"]);
        Assert.Empty(api.Calls);
        Assert.Equal(0, comRuns);
    }

    [Fact]
    public void SyncWithoutAQueryIsUnavailable()
    {
        var (code, output, api, _) = Run(["--sync"]);
        Assert.Equal(1, code);
        Assert.Equal("unavailable", (string?)output["error"]);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void OutputNeverCarriesKeyMaterial()
    {
        var (_, output, api, _) = Run(["--register"]);
        Assert.DoesNotContain(Convert.ToBase64String(api.PublicKeyBlob()), output.ToJsonString());
        Assert.Equal(["ok"], output.Select(p => p.Key).ToArray());
    }
}
