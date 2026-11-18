using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class PipeClientTests
{
    private const string Token = "tok-0123456789abcdef0123456789abcdef-XYZ";
    private static readonly string Sid = WindowsIdentity.GetCurrent().User!.Value;

    private static JsonObject Request() => new()
    {
        ["action"] = "passkey_lock_status_system", ["system_protocol"] = 1,
        ["transaction_id"] = "3f2b8c1e-5d4a-4b6f-9e21-7c0d8a9b1e42",
    };

    private static PipeClient Client(FakePipeServer server, int pid, IServerImageCheck check) =>
        new(() => new AgentState(server.PipeName, Token, pid, Sid), check);

    [Fact]
    public async Task SendsTheTokenAndReturnsTheReply()
    {
        await using var server = new FakePipeServer(_ => new JsonObject { ["ok"] = true, ["locked"] = true });
        var check = new FakeImageCheck(trusted: true);
        var request = Request();
        var reply = await Client(server, Environment.ProcessId, check).SendAsync(request, CancellationToken.None);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["ok"] = true, ["locked"] = true }, reply));
        Assert.Equal(Token, (string?)server.Request!["token"]);
        Assert.Equal("passkey_lock_status_system", (string?)server.Request["action"]);
        Assert.False(request.ContainsKey("token"));  // the caller's object never holds the token
        Assert.Equal([Environment.ProcessId], check.Asked);
    }

    [Fact]
    public async Task ServerPidMismatchWritesNothing()
    {
        await using var server = new FakePipeServer();
        var check = new FakeImageCheck(trusted: true);
        var error = await Assert.ThrowsAsync<AgentRejectedException>(
            () => Client(server, Environment.ProcessId + 1, check).SendAsync(Request(), CancellationToken.None));
        Assert.Equal("agent_connection_changed", error.Code);
        Assert.Equal("server_pid_mismatch", error.Detail);
        // The server marks the connection after the client already has it: wait for the server side to finish.
        Assert.Empty(await server.ReceivedAsync());
        Assert.True(server.Connected);
        Assert.Null(server.Request);
    }

    [Fact]
    public async Task UntrustedServerImageWritesNothing()
    {
        await using var server = new FakePipeServer();
        var check = new FakeImageCheck(trusted: false);
        var error = await Assert.ThrowsAsync<AgentRejectedException>(
            () => Client(server, Environment.ProcessId, check).SendAsync(Request(), CancellationToken.None));
        Assert.Equal("agent_server_untrusted", error.Code);
        Assert.Equal("server_untrusted", error.Detail);
        Assert.Equal([Environment.ProcessId], check.Asked);
        Assert.Empty(await server.ReceivedAsync());
        Assert.Null(server.Request);
    }

    [Fact]
    public async Task MissingPipeIsUnavailable()
    {
        var name = @"\\.\pipe\LocalGateKeys-" + Guid.NewGuid().ToString("N");
        var client = new PipeClient(() => new AgentState(name, Token, Environment.ProcessId, Sid),
                                    new FakeImageCheck(trusted: true));
        var error = await Assert.ThrowsAsync<AgentUnavailableException>(() => client.SendAsync(Request(), CancellationToken.None));
        Assert.Equal("pipe_missing", error.Reason);
    }

    [Fact]
    public async Task StateErrorsPassThrough()
    {
        var unavailable = new PipeClient(() => throw new AgentUnavailableException(), new FakeImageCheck(true));
        await Assert.ThrowsAsync<AgentUnavailableException>(() => unavailable.SendAsync(Request(), CancellationToken.None));
        var rejected = new PipeClient(() => throw new AgentRejectedException("agent_access_denied"), new FakeImageCheck(true));
        await Assert.ThrowsAsync<AgentRejectedException>(() => rejected.SendAsync(Request(), CancellationToken.None));
    }

    [Fact]
    public async Task SilentServerHonoursCancellation()
    {
        await using var server = new FakePipeServer(_ => null);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var watch = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Client(server, Environment.ProcessId, new FakeImageCheck(true)).SendAsync(Request(), cts.Token));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), watch.Elapsed.ToString());
        Assert.NotNull(server.Request);  // it was sent; only the wait was cut short
    }
}
