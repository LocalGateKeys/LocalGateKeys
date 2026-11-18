using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Commands;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class MetadataSyncTests
{
    private static JsonObject Entry(string credentialId = "AQID", string userId = "dQ", string rpId = "example.com",
                                    string userName = "ann") => new()
    {
        ["credential_id"] = credentialId, ["rp_id"] = rpId, ["rp_name"] = "Example", ["user_id"] = userId,
        ["user_name"] = userName, ["user_display_name"] = "Ann",
    };

    private static (int Code, JsonObject Output, FakeWebAuthnApi Api) Sync(
        OperationResult reply, bool buildSupported = true, Action<FakeWebAuthnApi>? setup = null)
    {
        var api = new FakeWebAuthnApi();
        setup?.Invoke(api);
        using var output = new StringWriter();
        var context = new CliContext(output, api, ProviderHarness.TestClsid, () => buildSupported, () => 0,
                                     _ => Task.FromResult(reply));
        var code = Cli.Run(["--sync"], context);
        return (code, JsonNode.Parse(output.ToString())!.AsObject(), api);
    }

    private static OperationResult Credentials(params JsonObject[] entries) =>
        new(HResults.SOk, new JsonObject { ["ok"] = true, ["credentials"] = new JsonArray(entries) });

    [Fact]
    public void ReplacesTheCacheWithTheAppsNames()
    {
        var (code, output, api) = Sync(Credentials(Entry(), Entry("BAUG", "dg", "b.example", "bob")));
        Assert.Equal(0, code);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["ok"] = true, ["count"] = 2 }, output));
        Assert.Equal(["remove_all", "add_credentials"], api.Calls.ToArray());
        var first = api.AddedCredentials![0];
        Assert.Equal(new byte[] { 1, 2, 3 }, first.CredentialId);
        Assert.Equal(new byte[] { 0x75 }, first.UserId);
        Assert.Equal(("example.com", "Example", "ann", "Ann"), (first.RpId, first.RpName, first.UserName,
                                                               first.UserDisplayName));
    }

    [Fact]
    public void AnEmptyVaultEmptiesTheCache()
    {
        var (code, output, api) = Sync(Credentials());
        Assert.Equal(0, code);
        Assert.Equal(0, (int)output["count"]!);
        Assert.Equal(["remove_all"], api.Calls.ToArray());
    }

    [Theory]
    [InlineData(HResults.NteDeviceNotFound)]  // app not running: never started for a sync
    [InlineData(HResults.NteUserCancelled)]   // locked / disabled answers
    [InlineData(HResults.Timeout)]
    public void WhenTheAppCannotAnswerTheCacheStays(int hr)
    {
        var (code, output, api) = Sync(new OperationResult(hr, null));
        Assert.Equal(1, code);
        Assert.Equal("query_failed", (string?)output["error"]);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void AMalformedReplyLeavesTheCache()
    {
        var (code, output, api) = Sync(new OperationResult(HResults.SOk, new JsonObject { ["ok"] = true }));
        Assert.Equal(1, code);
        Assert.Equal("bad_reply", (string?)output["error"]);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void UnsupportedBuildDoesNothing()
    {
        var (code, output, api) = Sync(Credentials(Entry()), buildSupported: false);
        Assert.Equal(1, code);
        Assert.Equal("unsupported_build", (string?)output["error"]);
        Assert.Empty(api.Calls);
    }

    [Fact]
    public void WindowsFailuresAreReported()
    {
        var (code, output, _) = Sync(Credentials(Entry()), setup: api => api.AddCredentialsHr = HResults.EFail);
        Assert.Equal(1, code);
        Assert.Equal("sync_failed", (string?)output["error"]);
        Assert.Equal("0x80004005", (string?)output["hresult"]);
        (code, _, var api2) = Sync(Credentials(Entry()), setup: api => api.RemoveAllHr = HResults.EFail);
        Assert.Equal(1, code);
        Assert.Equal(["remove_all"], api2.Calls.ToArray());
        (code, _, _) = Sync(Credentials(Entry()), setup: api => api.RemoveAllHr = HResults.NteNotFound);
        Assert.Equal(0, code);
    }

    [Fact]
    public void InvalidEntriesAreSkipped()
    {
        var (_, output, api) = Sync(Credentials(
            Entry(credentialId: "not base64!"), Entry(credentialId: "AQI="), Entry(credentialId: ""),
            Entry(userId: ""), Entry(userId: Convert.ToBase64String(new byte[65]).TrimEnd('=')),
            Entry(rpId: ""), Entry(rpId: new string('a', 254)), Entry(userName: "a\u0000b"),
            Entry(userName: new string('n', 1025)), Entry()));
        Assert.Equal(1, (int)output["count"]!);
        Assert.Single(api.AddedCredentials!);
    }

    [Fact]
    public void DuplicateCredentialIdsAreAddedOnce()
    {
        var (_, output, api) = Sync(Credentials(Entry(), Entry(userName: "copy"), Entry("BAUG", "dg")));
        Assert.Equal(2, (int)output["count"]!);
        Assert.Equal("ann", api.AddedCredentials![0].UserName);  // the first one wins
    }

    [Fact]
    public void ClearCacheRemovesOnlyTheNames()
    {
        var api = new FakeWebAuthnApi();
        using var output = new StringWriter();
        var context = new CliContext(output, api, ProviderHarness.TestClsid, () => true, () => 0,
                                     _ => throw new InvalidOperationException("no query"));
        Assert.Equal(0, Cli.Run(["--clear-cache"], context));
        Assert.Equal(["remove_all"], api.Calls.ToArray());  // the authenticator stays registered
        Assert.Equal("{\"ok\":true}", output.ToString().Trim());
        api.RemoveAllHr = HResults.EFail;
        Assert.Equal(1, Cli.Run(["--clear-cache"], context));
        var unsupported = new CliContext(new StringWriter(), new FakeWebAuthnApi(), ProviderHarness.TestClsid,
                                         () => false, () => 0);
        Assert.Equal(1, Cli.Run(["--clear-cache"], unsupported));
    }

    [Fact]
    public void KeyMaterialInTheReplyIsNeverPassedOn()
    {
        var entry = Entry();
        entry["private_key"] = "SECRET";
        var (_, output, api) = Sync(Credentials(entry));
        Assert.Equal(1, (int)output["count"]!);
        Assert.DoesNotContain("SECRET", output.ToJsonString());
        Assert.Equal(6, typeof(CredentialDetail).GetProperties().Length);  // the six fields only
    }

    [Fact]
    public async Task TheQueryAsksForCredentialsAndNeverStartsTheApp()
    {
        var pipe = new FakeConnector((_, _) => throw new AgentUnavailableException());
        var launcher = new FakeLauncher();
        var result = await MetadataSync.Query(pipe, launcher)(CancellationToken.None);
        Assert.Equal(HResults.AppNotRunning, result.HResult);
        Assert.Equal(0, launcher.Calls);

        var answering = FakeConnector.Replying(new JsonObject { ["ok"] = true, ["credentials"] = new JsonArray() });
        result = await MetadataSync.Query(answering, launcher)(CancellationToken.None);
        Assert.Equal(HResults.SOk, result.HResult);
        var sent = Assert.Single(answering.Sent);
        Assert.Equal("passkey_credentials_system", (string?)sent["action"]);
        Assert.Equal(1, (int)sent["system_protocol"]!);
        Assert.NotNull((string?)sent["transaction_id"]);
    }
}
