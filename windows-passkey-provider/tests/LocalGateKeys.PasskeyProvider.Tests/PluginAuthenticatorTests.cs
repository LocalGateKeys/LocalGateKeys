using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class PluginAuthenticatorTests
{
    [Fact]
    public void MakeCredentialForwardsAndEncodes()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));

        var (hr, response) = harness.Call(create: true, null);

        Assert.Equal(HResults.SOk, hr);
        Assert.Equal(FakeWebAuthnApi.EncodedMarker, response);
        Assert.Equal(["key", "decode_make", "encode_make"], harness.Api.Calls.ToArray());
        Assert.Equal(ProviderHarness.AuthData(attested: true), harness.Api.EncodedAttestation!.AuthenticatorData);
        Assert.Equal(1, harness.Foreground.Calls);
        var sent = Assert.Single(harness.Pipe.Sent);
        var expected = JsonNode.Parse("""
            {"action":"passkey_create_system","rp_id":"example.test","rp_name":"Example","user_id":"dXNlci0x",
             "user_name":"ada","user_display_name":"Ada","client_data_hash":"","algorithms":[-7,-257],
             "exclude_credentials":[],"resident_key":true,"user_verification":"required",
             "caller":{"image":"msedge.exe","title":"Sign in - Example"},
             "system_protocol":1,"transaction_id":"3f2b8c1e-5d4a-4b6f-9e21-7c0d8a9b1e42"}
            """)!.AsObject();
        expected["client_data_hash"] = CtapMapping.B64(ProviderHarness.ClientDataHash);
        Assert.True(JsonNode.DeepEquals(expected, sent), sent.ToJsonString());
    }

    [Fact]
    public void GetAssertionForwardsAndEncodes()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.GetReply()));
        harness.Api.GetAssertion = ProviderHarness.GetInput(uv: -1, allow: [ProviderHarness.CredentialId]);

        var (hr, response) = harness.Call(create: false, null);

        Assert.Equal(HResults.SOk, hr);
        Assert.Equal(FakeWebAuthnApi.EncodedMarker, response);
        var output = harness.Api.EncodedAssertion!;
        Assert.Equal(ProviderHarness.CredentialId, output.CredentialId);
        Assert.Equal(new byte[] { 4, 5, 6 }, output.Signature);
        Assert.Equal(ProviderHarness.UserId, output.UserHandle);
        var sent = Assert.Single(harness.Pipe.Sent);
        Assert.Equal("passkey_get_system", (string?)sent["action"]);
        Assert.Equal("discouraged", (string?)sent["user_verification"]);
        Assert.Equal(CtapMapping.B64(ProviderHarness.CredentialId), (string?)sent["allow_credentials"]![0]);
        Assert.Null(sent["token"]);
    }

    [Theory]
    [InlineData("user_cancelled", HResults.NteUserCancelled)]
    [InlineData("busy", HResults.NteUserCancelled)]
    [InlineData("item_limit", HResults.NteUserCancelled)]
    [InlineData("invalid_state", HResults.NteExists)]
    [InlineData("disabled", HResults.NteDeviceNotFound)]
    public void AppErrorsMapAndNothingIsEncoded(string error, int expected)
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = false, ["error"] = error }));
        var (hr, response) = harness.Call(create: true, null);
        Assert.Equal(expected, hr);
        Assert.Null(response);
        Assert.DoesNotContain("encode_make", harness.Api.Calls);
    }

    [Fact]
    public void ReplyForAnotherRpIsRefused()
    {
        var authData = ProviderHarness.AuthData(attested: true, rpId: "evil.test");
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply(authData)));
        Assert.Equal(HResults.EFail, harness.Call(create: true, null).Hr);
        Assert.DoesNotContain("encode_make", harness.Api.Calls);
    }

    [Fact]
    public void ReplyOutsideTheAllowListIsRefused()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.GetReply(credentialId: [9, 9, 9])));
        harness.Api.GetAssertion = ProviderHarness.GetInput(allow: [ProviderHarness.CredentialId]);
        Assert.Equal(HResults.EFail, harness.Call(create: false, null).Hr);
    }

    [Fact]
    public void UndecodableRequestNeverReachesThePipe()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Api.MakeCredential = null;
        Assert.Equal(HResults.EInvalidArg, harness.Call(create: true, null).Hr);
        Assert.Empty(harness.Pipe.Sent);
    }

    [Fact]
    public void WrongRequestTypeIsRefused()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        Assert.Equal(HResults.EInvalidArg, harness.Call(create: true, null, requestType: 2).Hr);
        Assert.Empty(harness.Pipe.Sent);
        Assert.Empty(harness.Api.Calls);
    }

    [Fact]
    public unsafe void NullPointersAreRefused()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        IPluginAuthenticator com = harness.Provider;
        var response = new WebAuthnPluginOperationResponse();
        Assert.Equal(HResults.EInvalidArg, com.MakeCredential(null, &response));
        Assert.Equal(HResults.EInvalidArg, com.GetAssertion(null, null));
        Assert.Equal(HResults.EInvalidArg, com.CancelOperation(null));
        Assert.Equal(HResults.EInvalidArg, com.GetLockStatus(null));
    }

    [Fact]
    public void SilentAppEndsWithTimeoutAndCancel()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(ignoreToken: true));
        var watch = Stopwatch.StartNew();
        var (hr, _) = harness.Call(create: true, null);
        Assert.Equal(HResults.Timeout, hr);
        Assert.True(watch.Elapsed <= ProviderHarness.ShortTimings.Total + TimeSpan.FromMilliseconds(200),
                    watch.Elapsed.ToString());
        Assert.Single(harness.Pipe.Of("passkey_cancel_system"));
    }

    [Fact]
    public void AppNotRunningIsStartedOnceThenDeviceNotFound()
    {
        using var harness = new ProviderHarness(new FakeConnector((_, _) => throw new AgentUnavailableException()));
        Assert.Equal(HResults.NteDeviceNotFound, harness.Call(create: false, null).Hr);
        Assert.Equal(1, harness.Launcher.Calls);
    }

    [Fact]
    public async Task DuplicateRunningTransactionIsRefused()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(), ProviderHarness.LongTimings);
        var first = Task.Run(() => harness.Call(create: true, null));
        RequestSignatureTests.WaitFor(() => harness.Pipe.Sent.Count == 1);
        Assert.Equal(HResults.EInvalidArg, harness.Call(create: false, null).Hr);
        Assert.Equal(HResults.SOk, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));
        Assert.Equal(HResults.Cancelled, (await first).Hr);
    }

    // -- GetLockStatus ----------------------------------------------------------------------------------------

    [Fact]
    public void LockStatusUnlocked()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = true, ["locked"] = false }));
        Assert.Equal((HResults.SOk, PluginLockStatus.PluginUnlocked), harness.LockStatus());
        var sent = Assert.Single(harness.Pipe.Sent);
        Assert.Equal("passkey_lock_status_system", (string?)sent["action"]);
        Assert.Empty(harness.Api.Calls);  // no signature on this call in the IDL
    }

    [Fact]
    public void LockStatusLocked()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = true, ["locked"] = true }));
        Assert.Equal((HResults.SOk, PluginLockStatus.PluginLocked), harness.LockStatus());
    }

    [Fact]
    public void LockStatusNeverStartsTheApp()
    {
        using var harness = new ProviderHarness(new FakeConnector((_, _) => throw new AgentUnavailableException()));
        Assert.Equal((HResults.SOk, PluginLockStatus.PluginLocked), harness.LockStatus());
        Assert.Equal(0, harness.Launcher.Calls);
    }

    [Fact]
    public void LockStatusWithoutAnswerIsLockedWithinBudget()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(ignoreToken: true));
        var watch = Stopwatch.StartNew();
        Assert.Equal((HResults.SOk, PluginLockStatus.PluginLocked), harness.LockStatus());
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), watch.Elapsed.ToString());
    }

    [Fact]
    public void LockStatusOddReplyIsLocked()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(new JsonObject { ["ok"] = true, ["locked"] = "no" }));
        Assert.Equal((HResults.SOk, PluginLockStatus.PluginLocked), harness.LockStatus());
    }

    [Fact]
    public void ProductionTimings()
    {
        var timings = ProviderTimings.Default;
        Assert.Equal(TimeSpan.FromSeconds(30), timings.Total);
        Assert.Equal(TimeSpan.FromSeconds(27), timings.Operation);  // above the app's 25 s deadline
        Assert.Equal(TimeSpan.FromSeconds(10), timings.ConnectWindow);
        Assert.Equal(TimeSpan.FromSeconds(2), timings.LockStatus);
        // Runner timer + follow-up cancel + encode margin fit inside 30 s from entry.
        Assert.True(timings.Operation + timings.Cancel + ProviderTimings.DeliverMargin <= TimeSpan.FromSeconds(30));
        Assert.Equal(TimeSpan.FromSeconds(27), timings.RunnerTimeout(TimeSpan.Zero));
        Assert.Equal(TimeSpan.FromSeconds(22.5), timings.RunnerTimeout(TimeSpan.FromSeconds(5)));
        Assert.True(timings.RunnerTimeout(TimeSpan.FromSeconds(28)) <= TimeSpan.Zero);
    }

    [Fact]
    public void SlowKeyFetchStillAnswersWithinTotalFromEntry()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(ignoreToken: true));
        harness.Api.OnKey = () => Thread.Sleep(700);
        var watch = Stopwatch.StartNew();
        var (hr, _) = harness.Call(create: true, null);
        Assert.Equal(HResults.Timeout, hr);
        Assert.True(watch.Elapsed <= ProviderHarness.ShortTimings.Total + TimeSpan.FromMilliseconds(200),
                    watch.Elapsed.ToString());
        Assert.Single(harness.Pipe.Of("passkey_cancel_system"));
    }

    [Fact]
    public void KeyFetchPastTheBudgetEndsWithoutThePipe()
    {
        // webauthn.dll calls run on the COM thread and are the platform's own: a slow one is not cut short, but
        // nothing of ours starts once the budget is gone.
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Api.OnKey = () => Thread.Sleep(ProviderHarness.ShortTimings.Total + TimeSpan.FromMilliseconds(100));
        var (hr, response) = harness.Call(create: true, null);
        Assert.Equal(HResults.Timeout, hr);
        Assert.Null(response);
        Thread.Sleep(300);
        Assert.Empty(harness.Pipe.Sent);
        Assert.Equal(0, harness.Foreground.Calls);
    }

    public static TheoryData<bool> BothCeremonies => new() { true, false };

    [Theory]
    [MemberData(nameof(BothCeremonies))]
    public void WebAuthnDllIsCalledOnlyOnTheIncomingComThread(bool create)
    {
        // Real-device bug 2026-11-09: the key fetch made from a pool thread while the COM thread waited failed in
        // the platform (0x800706FF). The sample and KeePassPasskey call webauthn.dll on the incoming call thread.
        var reply = create ? ProviderHarness.CreateReply() : ProviderHarness.GetReply();
        using var harness = new ProviderHarness(FakeConnector.Replying(reply));
        var comThread = Environment.CurrentManagedThreadId;

        Assert.Equal(HResults.SOk, harness.Call(create, null).Hr);

        var calls = harness.Api.Threads.ToArray();
        Assert.Equal(create ? ["key", "decode_make", "encode_make"] : ["key", "decode_get", "encode_get"],
                     calls.Select(c => c.Call).ToArray());
        Assert.All(calls, c => Assert.Equal(comThread, c.Thread));
    }

    [Fact]
    public async Task CancelVerifiesOnItsOwnComThread()
    {
        using var harness = new ProviderHarness(FakeConnector.Silent(), ProviderHarness.LongTimings);
        var call = Task.Run(() => harness.Call(create: true, null));
        RequestSignatureTests.WaitFor(() => harness.Pipe.Of("passkey_create_system").Length == 1);
        var ceremonyThreads = harness.Api.Threads.Select(c => c.Thread).ToHashSet();
        Assert.Single(ceremonyThreads);
        Assert.Equal(HResults.SOk, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));
        Assert.Equal(Environment.CurrentManagedThreadId, harness.Api.Threads.Last().Thread);
        Assert.Equal(HResults.Cancelled, (await call).Hr);
    }

    [Fact]
    public void ReplayedSignatureIsRefused()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        var signature = harness.GoodSignature();
        Assert.Equal(HResults.SOk, harness.Call(create: true, signature).Hr);
        Assert.Equal(HResults.NteBadSignature, harness.Call(create: true, signature, Guid.NewGuid()).Hr);
        Assert.Equal(HResults.NteBadSignature, harness.Call(create: false, signature, Guid.NewGuid()).Hr);
        Assert.Single(harness.Pipe.Sent);
    }

    [Fact]
    public void MalleatedSignatureIsAReplay()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        var signature = harness.GoodSignature();
        var twin = Malleate(signature);
        Assert.NotEqual(signature, twin);
        Assert.True(RequestSignature.Verify(harness.Api.PublicKeyBlob(), ProviderHarness.Encoded, twin));  // valid
        Assert.Equal(HResults.SOk, harness.Call(create: true, signature).Hr);
        Assert.Equal(HResults.NteBadSignature, harness.Call(create: true, twin, Guid.NewGuid()).Hr);
        Assert.Single(harness.Pipe.Sent);
        Assert.Equal(ReplayCache.Canonical(signature), ReplayCache.Canonical(twin));
    }

    [Fact]
    public void SameRequestWithAFreshSignatureIsNotAReplay()
    {
        // A page retrying with the same options after the user closed the Windows dialog.
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        Assert.Equal(HResults.SOk, harness.Call(create: true, harness.GoodSignature()).Hr);
        Assert.Equal(HResults.SOk, harness.Call(create: true, harness.GoodSignature(), Guid.NewGuid()).Hr);
    }

    /// <summary>(r, s) to (r, n - s) with n of the curve the length names (64: P-256, 96: P-384, 132: P-521).</summary>
    internal static byte[] Malleate(byte[] signature)
    {
        var curve = signature.Length switch
        {
            64 => ECCurve.NamedCurves.nistP256,
            96 => ECCurve.NamedCurves.nistP384,
            132 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException("length"),
        };
        using var key = ECDsa.Create(curve);
        var n = new System.Numerics.BigInteger(key.ExportExplicitParameters(false).Curve.Order, isUnsigned: true,
                                               isBigEndian: true);
        var half = signature.Length / 2;
        var s = new System.Numerics.BigInteger(signature.AsSpan(half, half), isUnsigned: true, isBigEndian: true);
        var twin = (byte[])signature.Clone();
        Array.Clear(twin, half, half);
        var bytes = (n - s).ToByteArray(isUnsigned: true, isBigEndian: true);
        bytes.CopyTo(twin, signature.Length - bytes.Length);
        return twin;
    }

    [Fact]
    public async Task CancelBeforeRegistrationIsNotLost()
    {
        using var keyFetched = new ManualResetEventSlim();
        using var harness = new ProviderHarness(FakeConnector.Silent(), ProviderHarness.LongTimings);
        var first = true;
        harness.Api.OnKey = () =>
        {
            if (first)
            {
                first = false;
                keyFetched.Wait(TimeSpan.FromSeconds(10));
            }
        };
        var watch = Stopwatch.StartNew();
        var call = Task.Run(() => harness.Call(create: true, null));
        RequestSignatureTests.WaitFor(() => harness.Api.Calls.Contains("key"));
        // Arrives while the ceremony is still fetching its key: not registered yet.
        Assert.Equal(HResults.NteNotFound, harness.Cancel(harness.Api.Sign(ProviderHarness.Encoded)));
        keyFetched.Set();
        var (hr, _) = await call;
        Assert.Equal(HResults.Cancelled, hr);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10));
        Assert.Empty(harness.Pipe.Of("passkey_create_system"));
    }

    [Fact]
    public async Task EarlyCancelWithBadSignatureIsIgnored()
    {
        using var keyFetched = new ManualResetEventSlim();
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        var first = true;
        harness.Api.OnKey = () =>
        {
            if (first)
            {
                first = false;
                keyFetched.Wait(TimeSpan.FromSeconds(10));
            }
        };
        var call = Task.Run(() => harness.Call(create: true, null));
        RequestSignatureTests.WaitFor(() => harness.Api.Calls.Contains("key"));
        Assert.Equal(HResults.NteNotFound, harness.Cancel([1, 2, 3]));
        keyFetched.Set();
        Assert.Equal(HResults.SOk, (await call).Hr);
    }

    [Fact]
    public void CallsMarkActivity()
    {
        using var harness = new ProviderHarness(FakeConnector.Replying(ProviderHarness.CreateReply()));
        harness.Call(create: true, null);
        Assert.False(harness.Idle.IsIdle(TimeSpan.FromSeconds(5)));
    }
}
