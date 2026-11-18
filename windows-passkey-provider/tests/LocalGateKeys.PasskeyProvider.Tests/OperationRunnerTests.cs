using System.Diagnostics;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class OperationRunnerTests
{
    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan ShortWindow = TimeSpan.FromMilliseconds(300);
    private static readonly Guid Txn = Guid.Parse("3F2B8C1E-5D4A-4B6F-9E21-7C0D8A9B1E42");
    private const string TxnText = "3f2b8c1e-5d4a-4b6f-9e21-7c0d8a9b1e42";

    private static JsonObject Get() => new()
    {
        ["action"] = "passkey_get_system", ["rp_id"] = "example.test",
        ["client_data_hash"] = "KWP_BNIOH-3bk5rDnK8Y4uGkOSaVOX1HNXwbLx-D9EY",
        ["allow_credentials"] = new JsonArray(), ["user_verification"] = "required",
    };

    private static OperationRunner Runner(IPipeConnector pipe, IProcessLauncher? launcher = null,
                                          TimeSpan? timeout = null, TimeSpan? window = null) =>
        new(pipe, launcher ?? new FakeLauncher(), timeout ?? ShortTimeout, window ?? ShortWindow)
        {
            RetryInterval = TimeSpan.FromMilliseconds(20),
            CancelTimeout = TimeSpan.FromMilliseconds(300),
        };

    [Fact]
    public void ProductionValues()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), OperationRunner.DefaultTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), OperationRunner.DefaultConnectWindow);
        Assert.Equal(TimeSpan.FromMilliseconds(250), OperationRunner.DefaultRetryInterval);
        var runner = new OperationRunner(FakeConnector.Silent(), new FakeLauncher(), OperationRunner.DefaultTimeout,
                                         OperationRunner.DefaultConnectWindow);
        Assert.Equal(OperationRunner.DefaultRetryInterval, runner.RetryInterval);
        Assert.True(runner.StartsApp);
    }

    [Fact]
    public async Task SuccessReturnsTheReplyAndStampsProtocolAndTransaction()
    {
        var reply = new JsonObject { ["ok"] = true, ["credential_id"] = "AAEC" };
        var pipe = FakeConnector.Replying(reply);
        var request = Get();
        request["system_protocol"] = 9;
        request["transaction_id"] = "spoofed";
        request["token"] = "never forwarded from the caller";
        var result = await Runner(pipe).RunAsync(request, Txn, CancellationToken.None);
        Assert.Equal(0, result.HResult);
        Assert.True(JsonNode.DeepEquals(reply, result.Reply));
        var sent = Assert.Single(pipe.Sent);
        Assert.Equal(1, sent["system_protocol"]!.GetValue<int>());
        Assert.Equal(TxnText, (string?)sent["transaction_id"]);
        Assert.False(sent.ContainsKey("token"));
        Assert.Equal("required", (string?)sent["user_verification"]);
        Assert.Equal("spoofed", (string?)request["transaction_id"]);  // the caller's object is not changed
    }

    [Fact]
    public async Task BusyIsUserCancelled()
    {
        var pipe = FakeConnector.Replying(new JsonObject { ["ok"] = false, ["error"] = "busy" });
        var result = await Runner(pipe).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.NteUserCancelled, result.HResult);
        Assert.Null(result.Reply);
        Assert.Empty(pipe.Of("passkey_cancel_system"));  // the app answered: nothing to cancel
    }

    [Theory]
    [InlineData("{\"ok\":\"true\"}")]
    [InlineData("{\"ok\":1}")]
    [InlineData("{}")]
    [InlineData("{\"ok\":false}")]
    [InlineData("{\"ok\":false,\"error\":7}")]
    public async Task OddRepliesFail(string json)
    {
        var pipe = FakeConnector.Replying(JsonNode.Parse(json)!.AsObject());
        var result = await Runner(pipe).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.EFail, result.HResult);
        Assert.Null(result.Reply);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NoAnswerTimesOutAndSendsCancel(bool ignoreToken)
    {
        var pipe = FakeConnector.Silent(ignoreToken);
        var watch = Stopwatch.StartNew();
        var result = await Runner(pipe).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.Timeout, result.HResult);
        Assert.True(watch.Elapsed >= ShortTimeout - TimeSpan.FromMilliseconds(30), watch.Elapsed.ToString());
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), watch.Elapsed.ToString());
        var cancel = Assert.Single(pipe.Of("passkey_cancel_system"));
        Assert.Equal(TxnText, (string?)cancel["transaction_id"]);
        Assert.Equal(1, cancel["system_protocol"]!.GetValue<int>());
        Assert.Equal(3, cancel.Count);  // action, system_protocol, transaction_id: nothing else
    }

    [Fact]
    public async Task ConnectorBlockingSynchronouslyStillTimesOut()
    {
        // A connector stuck before its first await (state file, DPAPI, CreateFile, signature check) must not
        // outlast the timer: neither the request nor the follow-up cancel.
        using var release = new ManualResetEventSlim();
        var blocking = new FakeConnector((_, _) =>
        {
            release.Wait(TimeSpan.FromSeconds(10));
            return Task.FromResult(new JsonObject { ["ok"] = true });
        });
        var watch = Stopwatch.StartNew();
        var result = await Runner(blocking).RunAsync(Get(), Txn, CancellationToken.None);
        watch.Stop();
        release.Set();
        Assert.Equal(HResults.Timeout, result.HResult);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), watch.Elapsed.ToString());
        Assert.Single(blocking.Of("passkey_cancel_system"));
    }

    [Fact]
    public async Task ConnectorBlockingSynchronouslyHonoursWindowsCancel()
    {
        using var release = new ManualResetEventSlim();
        var blocking = new FakeConnector((_, _) =>
        {
            release.Wait(TimeSpan.FromSeconds(10));
            return Task.FromResult(new JsonObject { ["ok"] = true });
        });
        using var windows = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var watch = Stopwatch.StartNew();
        var result = await Runner(blocking, timeout: TimeSpan.FromSeconds(20)).RunAsync(Get(), Txn, windows.Token);
        watch.Stop();
        release.Set();
        Assert.Equal(HResults.Cancelled, result.HResult);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), watch.Elapsed.ToString());
    }

    [Fact]
    public async Task WindowsCancelIsCancelledAndSendsCancel()
    {
        var pipe = FakeConnector.Silent();
        using var windows = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var result = await Runner(pipe, timeout: TimeSpan.FromSeconds(20)).RunAsync(Get(), Txn, windows.Token);
        Assert.Equal(HResults.Cancelled, result.HResult);
        var cancel = Assert.Single(pipe.Of("passkey_cancel_system"));
        Assert.Equal(TxnText, (string?)cancel["transaction_id"]);
    }

    [Fact]
    public async Task AlreadyCancelledByWindowsSendsNothing()
    {
        var pipe = FakeConnector.Silent();
        using var windows = new CancellationTokenSource();
        windows.Cancel();
        var result = await Runner(pipe).RunAsync(Get(), Txn, windows.Token);
        Assert.Equal(HResults.Cancelled, result.HResult);
        Assert.Empty(pipe.Sent);
    }

    [Fact]
    public async Task CancelThatNeverAnswersStillEndsInTime()
    {
        var silentEverything = new FakeConnector(async (_, _) =>
        {
            await new TaskCompletionSource().Task;
            return new JsonObject();
        });
        var watch = Stopwatch.StartNew();
        var result = await Runner(silentEverything).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.Timeout, result.HResult);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), watch.Elapsed.ToString());
        Assert.Single(silentEverything.Of("passkey_cancel_system"));
    }

    [Fact]
    public async Task NoPipeStartsTheAppOnceThenGivesUpAtTheConnectWindow()
    {
        var pipe = new FakeConnector((_, _) => throw new AgentUnavailableException());
        var launcher = new FakeLauncher();
        var watch = Stopwatch.StartNew();
        var result = await Runner(pipe, launcher, timeout: TimeSpan.FromSeconds(20))
            .RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.AppNotRunning, result.HResult);
        Assert.Equal(1, launcher.Calls);
        Assert.True(watch.Elapsed >= ShortWindow - TimeSpan.FromMilliseconds(30), watch.Elapsed.ToString());
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3), watch.Elapsed.ToString());
        Assert.True(pipe.Sent.Count > 2);  // retried
        Assert.Empty(pipe.Of("passkey_cancel_system"));  // nothing ever reached an app
    }

    [Fact]
    public async Task AppStartedByTheLauncherAnswers()
    {
        var up = false;
        var launcher = new FakeLauncher { OnStart = () => up = true };
        var pipe = new FakeConnector((_, _) => up
            ? Task.FromResult(new JsonObject { ["ok"] = true, ["locked"] = false })
            : throw new AgentUnavailableException());
        var result = await Runner(pipe, launcher).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(0, result.HResult);
        Assert.Equal(1, launcher.Calls);
    }

    [Fact]
    public async Task LockStatusNeverStartsTheApp()
    {
        var pipe = new FakeConnector((_, _) => throw new AgentUnavailableException());
        var launcher = new FakeLauncher();
        var runner = Runner(pipe, launcher);
        runner.StartsApp = false;
        var result = await runner.RunAsync(new JsonObject { ["action"] = "passkey_lock_status_system" }, Txn,
                                           CancellationToken.None);
        Assert.Equal(HResults.AppNotRunning, result.HResult);
        Assert.Equal(0, launcher.Calls);
        Assert.Single(pipe.Sent);
    }

    [Fact]
    public async Task RejectedPeerFailsWithoutRetryOrLaunch()
    {
        var pipe = new FakeConnector((_, _) => throw new AgentRejectedException("agent_connection_changed"));
        var launcher = new FakeLauncher();
        var result = await Runner(pipe, launcher).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.EFail, result.HResult);
        Assert.Equal(0, launcher.Calls);
        Assert.Single(pipe.Sent);
    }

    [Fact]
    public async Task BrokenConnectionAfterSendFailsAndCancels()
    {
        var pipe = new FakeConnector((request, _) => (string?)request["action"] == "passkey_cancel_system"
            ? Task.FromResult(new JsonObject { ["ok"] = true })
            : throw new IOException("pipe broken"));
        var result = await Runner(pipe).RunAsync(Get(), Txn, CancellationToken.None);
        Assert.Equal(HResults.EFail, result.HResult);
        Assert.Single(pipe.Of("passkey_cancel_system"));
    }

    [Fact]
    public async Task NonCeremonyTimeoutSendsNoCancel()
    {
        var pipe = FakeConnector.Silent();
        var result = await Runner(pipe).RunAsync(new JsonObject { ["action"] = "passkey_credentials_system" }, Txn,
                                                 CancellationToken.None);
        Assert.Equal(HResults.Timeout, result.HResult);
        Assert.Empty(pipe.Of("passkey_cancel_system"));
    }

    [Theory]
    [InlineData("get_browser")]
    [InlineData("passkey_get_browser")]
    [InlineData("")]
    public async Task OnlyTheFiveSystemActionsAreSent(string action)
    {
        var pipe = FakeConnector.Replying(new JsonObject { ["ok"] = true });
        var result = await Runner(pipe).RunAsync(new JsonObject { ["action"] = action }, Txn, CancellationToken.None);
        Assert.Equal(HResults.EInvalidArg, result.HResult);
        Assert.Empty(pipe.Sent);
        result = await Runner(pipe).RunAsync(new JsonObject(), Txn, CancellationToken.None);
        Assert.Equal(HResults.EInvalidArg, result.HResult);
        Assert.Empty(pipe.Sent);
    }

    [Fact]
    public async Task OneRunPerTransaction()
    {
        var runner = Runner(FakeConnector.Replying(new JsonObject { ["ok"] = true }));
        await runner.RunAsync(Get(), Txn, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunAsync(Get(), Txn, CancellationToken.None));
    }
}
