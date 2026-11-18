using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using LocalGateKeys.PasskeyProvider.Diagnostics;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public partial class ProviderLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lgk-provider-log-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private string LogPath => Path.Combine(_dir, "logs", "passkey-provider.log");

    // Every line: time, op, txn (8 hex), outcome, hr, then optional check/stage/detail/api_hr, then ms.
    [GeneratedRegex(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z op=[a-z0-9_]+ txn=[0-9a-f]{8} outcome=[a-z0-9_]+ hr=0x[0-9A-F]{8}( check=[a-z0-9_]+)?( stage=[a-z0-9_]+)?( detail=[a-z0-9_]+)?( api_hr=0x[0-9A-F]{8})? ms=\d+$")]
    private static partial Regex LineShape();

    [Fact]
    public void LineFormat()
    {
        var record = new OperationRecord("make_credential", ProviderHarness.Txn, "cancelled", HResults.Cancelled,
                                         "pipe", "awaiting_reply", null, null, 5321);
        var line = ProviderLog.Line(record, new DateTimeOffset(2026, 11, 9, 2, 31, 2, TimeSpan.Zero));
        Assert.Equal("2026-11-09T02:31:02.000Z op=make_credential txn=3f2b8c1e outcome=cancelled hr=0x800704C7 " +
                     "check=pipe stage=awaiting_reply ms=5321", line);
        Assert.Matches(LineShape(), line);
    }

    [Theory]
    [InlineData("example.test")]
    [InlineData("ada@example.test")]
    [InlineData("AAECAwQFBgcICQoLDA0ODw")]
    [InlineData("C:\\Users\\x")]
    [InlineData("has space")]
    [InlineData("0123456789012345678901234567890123456789012345678")]  // 49 characters
    public void AnythingButAFixedWordIsReplaced(string value)
    {
        Assert.Equal("invalid", ProviderLog.Word(value));
        var line = ProviderLog.Line(new OperationRecord(value, Guid.Empty, value, 0, value, value, value), DateTimeOffset.UnixEpoch);
        Assert.DoesNotContain(value, line);
        Assert.Matches(LineShape(), line);
    }

    [Fact]
    public void RotatesPastTheLimit()
    {
        var log = new ProviderLog(LogPath);
        Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
        File.WriteAllBytes(LogPath, new byte[ProviderLog.MaxBytes]);
        log.Write(new OperationRecord("cancel", Guid.Empty, "ok", 0));
        Assert.True(File.Exists(LogPath + ".1"));
        Assert.Single(File.ReadAllLines(LogPath));
    }

    [Fact]
    public void NeverThrows()
    {
        var log = new ProviderLog(Path.Combine(_dir, "a\0b", "x.log"));
        log.Write(new OperationRecord("cancel", Guid.Empty, "ok", 0));
    }

    [Fact]
    public void DefaultPathIsUnderTheDataFolder() =>
        Assert.EndsWith(Path.Combine("LocalGateKeys", "logs", "passkey-provider.log"), ProviderLog.DefaultPath());

    // -- what a ceremony logs -------------------------------------------------------------------------------

    [Fact]
    public void SuccessfulCreate()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        Assert.Equal(HResults.SOk, harness.Call(create: true, null).Hr);
        var record = harness.Log.Last;
        Assert.Equal(("make_credential", "ok", "encode", "reply"), (record.Operation, record.Outcome, record.Check, record.Stage));
    }

    [Fact]
    public void BadSignatureNamesTheKeyKind()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        var signature = harness.GoodSignature();
        signature[0] ^= 1;
        harness.Call(create: true, signature);
        var record = harness.Log.Last;
        Assert.Equal(("bad_signature", "signature_verify", "key_ecs1_72"), (record.Outcome, record.Check, record.Detail));
    }

    [Fact]
    public void KeyFetchFailureCarriesItsHResult()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Api.KeyHr = unchecked((int)0x800706FF);
        harness.Call(create: false, null);
        var record = harness.Log.Last;
        Assert.Equal(("get_assertion", "key_fetch_failed", "key_fetch"), (record.Operation, record.Outcome, record.Check));
        Assert.Equal(unchecked((int)0x800706FF), record.ApiHResult);
    }

    [Fact]
    public void DecodeFailureCarriesItsHResult()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Api.MakeCredential = null;
        harness.Call(create: true, null);
        Assert.Equal(("decode_failed", "decode"), (harness.Log.Last.Outcome, harness.Log.Last.Check));
    }

    [Fact]
    public void AppErrorIsNamed()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = false, ["error"] = "busy" }));
        harness.Call(create: true, null);
        var record = harness.Log.Last;
        Assert.Equal(("app_error", "app_reply", "busy"), (record.Outcome, record.Stage, record.Detail));
    }

    [Fact]
    public void UnknownAppErrorIsOther()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = false, ["error"] = "Weird Thing" }));
        harness.Call(create: true, null);
        Assert.Equal("other", harness.Log.Last.Detail);
    }

    [Fact]
    public void AppUnavailableNamesTheReason()
    {
        using var harness = new ProviderHarness(new FakeConnector((_, _) => throw new AgentUnavailableException("pipe_missing")));
        harness.Call(create: true, null);
        var record = harness.Log.Last;
        Assert.Equal(("app_unavailable", "unavailable_pipe_missing"), (record.Outcome, record.Detail));
    }

    [Fact]
    public void ServerPinRefusalNamesTheSubCheck()
    {
        using var harness = new ProviderHarness(new FakeConnector(
            (_, _) => throw new AgentRejectedException("agent_server_untrusted", "server_package_family")));
        harness.Call(create: true, null);
        var record = harness.Log.Last;
        Assert.Equal(("pipe_refused", "server_package_family"), (record.Outcome, record.Detail));
    }

    [Fact]
    public async Task CancelledWhileAwaitingTheAppNamesTheStage()
    {
        // The device run: Windows cancelled after ~5 s. The line tells whether the app had the request.
        using var harness = new ProviderHarness(new FakeConnector(async (request, ct) =>
        {
            if ((string?)request["action"] == "passkey_cancel_system")
                return new JsonObject { ["ok"] = true };
            PipeProgress.Mark("awaiting_reply");
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException();
        }), ProviderHarness.LongTimings);
        var call = Task.Run(() => harness.Call(create: true, null));
        RequestSignatureTests.WaitFor(() => harness.Pipe.Of("passkey_create_system").Length == 1);
        Assert.Equal(HResults.SOk, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));
        Assert.Equal(HResults.Cancelled, (await call).Hr);
        var ceremony = harness.Log.Records.First(r => r.Operation == "make_credential");
        Assert.Equal(("cancelled", "pipe", "awaiting_reply"), (ceremony.Outcome, ceremony.Check, ceremony.Stage));
        Assert.Contains(harness.Log.Records, r => r is { Operation: "cancel", Outcome: "cancelled_transaction" });
    }

    [Fact]
    public void LockStatusLogsTheAnswer()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = true, ["locked"] = false }));
        harness.LockStatus();
        Assert.Equal(("lock_status", "unlocked"), (harness.Log.Last.Operation, harness.Log.Last.Outcome));
    }

    [Fact]
    public void NoForbiddenFieldIsEverWritten()
    {
        var log = new ProviderLog(LogPath);
        var token = "tok-0123456789abcdef0123456789abcdef-XYZ";
        var stopwatch = Stopwatch.StartNew();
        // Exercise every outcome with the real file log.
        foreach (var connector in new[]
                 {
                     FakeConnector.Replying(ProviderHarness.CreateReply()),
                     FakeConnector.Replying(ProviderHarness.GetReply()),
                     FakeConnector.Replying(new JsonObject { ["ok"] = false, ["error"] = "example.test" }),
                     new FakeConnector((_, _) => throw new AgentRejectedException("agent_server_untrusted", "server_path")),
                     new FakeConnector((_, _) => throw new AgentUnavailableException()),
                 })
        {
            using var harness = new ProviderHarness(connector, log: log);
            harness.Call(create: true, null);
            harness.Call(create: false, null);
            var bad = harness.GoodSignature();
            bad[1] ^= 1;
            harness.Call(create: true, bad);
            harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded));
            harness.LockStatus();
        }
        var text = File.ReadAllText(LogPath, Encoding.UTF8);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length >= 20, lines.Length.ToString());
        Assert.All(lines, line => Assert.Matches(LineShape(), line));
        string[] forbidden =
        [
            ProviderHarness.RpId, "Example", "ada", "Ada", "msedge", "Sign in", token,
            CtapMapping.B64(ProviderHarness.CredentialId), CtapMapping.B64(ProviderHarness.UserId),
            CtapMapping.B64(ProviderHarness.ClientDataHash), Convert.ToHexString(ProviderHarness.Encoded),
            Convert.ToHexString(ProviderHarness.ClientDataHash), "dXNlci0x", "BAUG", "\\pipe\\", "LocalGateKeys-",
            ProviderHarness.TxnText,
        ];
        foreach (var value in forbidden)
            Assert.DoesNotContain(value, text, StringComparison.OrdinalIgnoreCase);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(60));
    }
}
