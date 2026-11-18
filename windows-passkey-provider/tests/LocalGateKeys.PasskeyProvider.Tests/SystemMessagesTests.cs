using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>The golden messages in tests/fixtures/system-messages.json, which the Python suite checks too.</summary>
public class SystemMessagesTests
{
    private static readonly JsonObject Fixture =
        JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "system-messages.json")))!
            .AsObject();

    private static readonly Guid Txn = Guid.Parse((string)Fixture["transaction_id"]!);
    private static readonly CallerHint Caller = new("msedge.exe", "Sign in - Example");

    private static void Matches(string action, JsonObject request)
    {
        Assert.Equal(action, (string?)request["action"]);
        var outbound = OperationRunner.PrepareOutbound(request, Txn);
        var expected = Fixture["requests"]![action]!;
        Assert.True(JsonNode.DeepEquals(expected, outbound), $"{action}:\n{outbound.ToJsonString()}\n!=\n{expected.ToJsonString()}");
    }

    [Fact]
    public void CreateRequest() => Matches("passkey_create_system", SystemMessages.ToJson(new CreateSystemRequest(
        RpId: "example.test", RpName: "Example", UserId: "dXNlci0x", UserName: "ada", UserDisplayName: "Ada",
        ClientDataHash: "KWP_BNIOH-3bk5rDnK8Y4uGkOSaVOX1HNXwbLx-D9EY", Algorithms: [-7, -257], ExcludeCredentials: [],
        ResidentKey: true, UserVerification: "required", Caller: Caller)));

    [Fact]
    public void GetRequest() => Matches("passkey_get_system", SystemMessages.ToJson(new GetSystemRequest(
        RpId: "example.test", ClientDataHash: "KWP_BNIOH-3bk5rDnK8Y4uGkOSaVOX1HNXwbLx-D9EY", AllowCredentials: [],
        UserVerification: "required", Caller: Caller)));

    [Fact]
    public void SmallRequests()
    {
        Matches("passkey_cancel_system", SystemMessages.Cancel());
        Matches("passkey_lock_status_system", SystemMessages.LockStatus());
        Matches("passkey_credentials_system", SystemMessages.Credentials());
    }

    [Fact]
    public void CallerWithoutTitleOmitsIt()
    {
        var json = SystemMessages.ToJson(new GetSystemRequest("example.test", "x", [], "discouraged",
                                                              new CallerHint("app.exe", null)));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["image"] = "app.exe" }, json["caller"]));
        json = SystemMessages.ToJson(new GetSystemRequest("example.test", "x", [], "discouraged", null));
        Assert.False(json.ContainsKey("caller"));
    }

    private static JsonObject Reply(string action) => Fixture["replies"]![action]!.AsObject();

    [Fact]
    public void Replies()
    {
        var created = SystemMessages.ReadCreateReply(Reply("passkey_create_system"));
        Assert.Equal(("AAECAwQFBgcICQoLDA0ODw", "AQID", "none"),
                     (created.CredentialId, created.AuthenticatorData, created.AttestationFormat));
        Assert.Equal(("o2NmbXRkbm9uZQ", -7), (created.AttestationObject, created.PublicKeyAlgorithm));

        var got = SystemMessages.ReadGetReply(Reply("passkey_get_system"));
        Assert.Equal(("AAECAwQFBgcICQoLDA0ODw", "AQID", "BAUG", "dXNlci0x", "ada", "Ada"),
                     (got.CredentialId, got.AuthenticatorData, got.Signature, got.UserHandle, got.UserName,
                      got.UserDisplayName));

        Assert.False(SystemMessages.ReadLockStatusReply(Reply("passkey_lock_status_system")).Locked);

        var credential = Assert.Single(SystemMessages.ReadCredentialsReply(Reply("passkey_credentials_system")).Credentials);
        Assert.Equal(new CredentialMetadata("AAECAwQFBgcICQoLDA0ODw", "example.test", "Example", "dXNlci0x", "ada", "Ada"),
                     credential);
    }

    [Fact]
    public void MalformedRepliesThrow()
    {
        Assert.Throws<PipeProtocolException>(() => SystemMessages.ReadGetReply(new JsonObject { ["ok"] = true }));
        Assert.Throws<PipeProtocolException>(
            () => SystemMessages.ReadLockStatusReply(new JsonObject { ["ok"] = true, ["locked"] = "no" }));
        Assert.Throws<PipeProtocolException>(
            () => SystemMessages.ReadCreateReply(new JsonObject { ["ok"] = true, ["credential_id"] = 5 }));
    }

    [Fact]
    public void ErrorReplyMapsThroughTheTable()
    {
        Assert.Equal(HResults.NteUserCancelled, ErrorMap.ToHResult((string?)Reply("error")["error"]));
    }
}
