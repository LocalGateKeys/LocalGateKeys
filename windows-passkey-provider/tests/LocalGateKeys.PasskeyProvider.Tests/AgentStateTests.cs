using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Tests;

public sealed class AgentStateTests : IDisposable
{
    private const string Token = "tok-0123456789abcdef0123456789abcdef-XYZ";
    private const string Pipe = @"\\.\pipe\LocalGateKeys-0123456789abcdef0123456789abcdef";
    private static readonly string Sid = WindowsIdentity.GetCurrent().User!.Value;
    private readonly string _dir = Directory.CreateTempSubdirectory("lgk-agent-state-").FullName;
    private string Path => System.IO.Path.Join(_dir, "agent-state.json");

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Protect(string token, string entropy = "LocalGateKeys.agent-token.v1") =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(token), Encoding.ASCII.GetBytes(entropy),
                                                     DataProtectionScope.CurrentUser));

    // The shape NamedPipeAgentServer.start writes.
    private static JsonObject Valid() => new()
    {
        ["version"] = 3, ["transport"] = "named_pipe", ["pipe"] = Pipe, ["token"] = Protect(Token),
        ["protection"] = "dpapi-user", ["pid"] = 4242, ["user_sid"] = Sid, ["bridge_revision"] = "test",
    };

    private AgentState Load(JsonObject state)
    {
        File.WriteAllText(Path, state.ToJsonString());
        return AgentState.Load(Path, Sid);
    }

    private void Rejected(JsonObject state, string code) =>
        Assert.Equal(code, Assert.Throws<AgentRejectedException>(() => Load(state)).Code);

    [Fact]
    public void LoadsTheAgentsStateFile()
    {
        var state = Load(Valid());
        Assert.Equal(Pipe, state.PipeName);
        Assert.Equal(Token, state.Token);
        Assert.Equal(4242, state.Pid);
        Assert.Equal(Sid, state.UserSid);
        Assert.DoesNotContain(Token, state.ToString());
    }

    [Fact]
    public void DefaultPathIsTheAppDataFolder()
    {
        var expected = System.IO.Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                              "LocalGateKeys", "agent-state.json");
        Assert.Equal(expected, AgentState.DefaultPath());
    }

    [Fact]
    public void MissingFileMeansTheAppIsNotRunning()
    {
        Assert.Throws<AgentUnavailableException>(() => AgentState.Load(Path, Sid));
    }

    [Fact]
    public void WrongSidIsRejected()
    {
        var state = Valid();
        state["user_sid"] = "S-1-5-21-1-2-3-1001";
        Rejected(state, "agent_access_denied");
    }

    [Fact]
    public void MissingPidIsRejected()
    {
        var state = Valid();
        state.Remove("pid");
        Rejected(state, "agent_state_invalid");
    }

    public static TheoryData<string, JsonNode?> BadFields => new()
    {
        { "pid", JsonValue.Create("4242") }, { "pid", JsonValue.Create(true) }, { "pid", JsonValue.Create(0) },
        { "pid", JsonValue.Create(-5) }, { "pid", JsonValue.Create(4242.5) }, { "pid", JsonValue.Create(1L << 40) },
        { "pid", null },
        { "transport", JsonValue.Create("tcp") },
        { "pipe", JsonValue.Create(@"\\.\pipe\LocalGateKeys-0123456789ABCDEF0123456789ABCDEF") },
        { "pipe", JsonValue.Create(@"\\.\pipe\Other-0123456789abcdef0123456789abcdef") },
        { "pipe", JsonValue.Create(@"\\server\pipe\LocalGateKeys-0123456789abcdef0123456789abcdef") },
        { "pipe", JsonValue.Create(@"\\.\pipe\LocalGateKeys-0123456789abcdef0123456789abcde") },
        { "pipe", JsonValue.Create(@"\\.\pipe\LocalGateKeys-0123456789abcdef0123456789abcdef0") },
        { "user_sid", JsonValue.Create("") }, { "user_sid", JsonValue.Create(5) },
        { "protection", JsonValue.Create("dpapi-machine") },
        { "token", JsonValue.Create("not base64!") }, { "token", JsonValue.Create(Protect(Token, "other entropy")) },
        { "token", JsonValue.Create(Protect("short")) }, { "token", JsonValue.Create(Protect(new string('t', 257))) },
        { "token", JsonValue.Create(7) },
    };

    [Theory]
    [MemberData(nameof(BadFields))]
    public void MalformedFieldsAreRejected(string field, JsonNode? value)
    {
        var state = Valid();
        state[field] = value;
        Rejected(state, "agent_state_invalid");
    }

    [Fact]
    public void PlaintextTokenIsRejectedInARelease()
    {
        var state = Valid();
        state["token"] = Token;
        state["protection"] = "none";
#if DEBUG
        Assert.Equal(Token, Load(state).Token);
#else
        Rejected(state, "agent_state_invalid");
        state.Remove("protection");  // the agent's default is "none"
        Rejected(state, "agent_state_invalid");
#endif
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("not json")]
    [InlineData("")]
    public void NonObjectFilesAreRejected(string text)
    {
        File.WriteAllText(Path, text);
        var error = Assert.Throws<AgentRejectedException>(() => AgentState.Load(Path, Sid));
        Assert.Equal("agent_state_invalid", error.Code);
        Assert.StartsWith("state_", error.Detail);
    }

    [Fact]
    public void OversizedFileIsRejected()
    {
        File.WriteAllText(Path, "{\"pad\":\"" + new string('x', 70_000) + "\"}");
        Assert.Equal("agent_state_invalid", Assert.Throws<AgentRejectedException>(() => AgentState.Load(Path, Sid)).Code);
    }
}
