using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text.Json;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Com;
using LocalGateKeys.PasskeyProvider.Diagnostics;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>
/// Timers of one provider process. <see cref="Total"/> is the hard bound on a ceremony's COM result, measured from
/// the call's entry (Global Constraints: 30 s). The app gets <see cref="Operation"/> (27 s, above its own 25 s
/// deadline), less whatever key fetch and decode used, so that the follow-up cancel (<see cref="Cancel"/>) and
/// <see cref="DeliverMargin"/> still fit inside <see cref="Total"/>.
/// </summary>
public sealed record ProviderTimings(
    TimeSpan Total, TimeSpan Operation, TimeSpan ConnectWindow, TimeSpan LockStatus, TimeSpan RetryInterval,
    TimeSpan Cancel)
{
    public static readonly TimeSpan DeliverMargin = TimeSpan.FromMilliseconds(500);

    public static ProviderTimings Default { get; } = new(
        TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(27), OperationRunner.DefaultConnectWindow,
        TimeSpan.FromSeconds(2), OperationRunner.DefaultRetryInterval, OperationRunner.DefaultCancelTimeout);

    public TimeSpan LockStatusGuard => LockStatus + TimeSpan.FromSeconds(1);

    /// <summary>The runner's timer for a call that has already used <paramref name="elapsed"/>.</summary>
    public TimeSpan RunnerTimeout(TimeSpan elapsed)
    {
        var left = Total - elapsed - Cancel - DeliverMargin;
        return left < Operation ? left : Operation;
    }
}

/// <summary>
/// <c>IPluginAuthenticator</c>. Order for the two ceremonies: copy the request, verify <c>pbRequestSignature</c>
/// with the operation-signing key read from webauthn.dll now (and refuse a replayed signature), and only then
/// register the transaction, decode, map and use the pipe; any verification failure is <c>NTE_BAD_SIGNATURE</c>
/// with nothing sent. webauthn.dll is called only on the incoming COM thread (see <c>Ceremony</c>); the process's
/// own work runs on the thread pool, which the COM thread waits for at most <see cref="ProviderTimings.Total"/> from
/// entry (pipe, app start and follow-up cancel included). None throws. One instance serves every COM object of
/// the process, so a <c>CancelOperation</c> on a new object still finds the transaction. Nothing is logged.
/// </summary>
[GeneratedComClass]
internal sealed unsafe partial class PluginAuthenticator : IPluginAuthenticator
{
    public const int MaxEncodedRequest = 1024 * 1024;

    private readonly Guid _clsid;
    private readonly IWebAuthnApi _api;
    private readonly IPipeConnector _pipe;
    private readonly IProcessLauncher _launcher;
    private readonly ICallerHints _callers;
    private readonly IForegroundGrant _foreground;
    private readonly IdleTracker _idle;
    private readonly ProviderTimings _timings;
    private readonly ConcurrentDictionary<Guid, Transaction> _transactions = new();
    private readonly ReplayCache _replays = new();
    private readonly PendingCancels _pendingCancels = new();
    private readonly IProviderLog _log;

    /// <summary>
    /// What one operation did, for the diagnostics log only (reason words, HRESULTs, the pipe stage). Written by the
    /// COM thread and the work thread; the line is taken when the COM call returns.
    /// </summary>
    private sealed class Trace
    {
        public volatile string Check = "start";
        public volatile string? Outcome;
        public volatile string? Stage;
        public volatile string? Detail;
        public int? ApiHResult;
        public volatile PipeProgress? Progress;
    }

    private sealed class Transaction(byte[] encodedRequest, CancellationToken abort) : IDisposable
    {
        public byte[] EncodedRequest { get; } = encodedRequest;
        public CancellationTokenSource Cancel { get; } = CancellationTokenSource.CreateLinkedTokenSource(abort);

        public void TryCancel()
        {
            try
            {
                Cancel.Cancel();  // the runner then sends passkey_cancel_system to the app
            }
            catch (ObjectDisposedException)
            {
                // Finished meanwhile.
            }
        }

        public void Dispose() => Cancel.Dispose();
    }

    public PluginAuthenticator(Guid clsid, IWebAuthnApi api, IPipeConnector pipe, IProcessLauncher launcher,
                               ICallerHints callers, IForegroundGrant foreground, IdleTracker idle,
                               ProviderTimings timings, IProviderLog? log = null)
    {
        _log = log ?? NullProviderLog.Instance;
        _clsid = clsid;
        _api = api;
        _pipe = pipe;
        _launcher = launcher;
        _callers = callers;
        _foreground = foreground;
        _idle = idle;
        _timings = timings;
    }

    // -- COM entry points -----------------------------------------------------------------------------------

    int IPluginAuthenticator.MakeCredential(WebAuthnPluginOperationRequest* request,
                                            WebAuthnPluginOperationResponse* response) =>
        MakeCredential(request, response);

    int IPluginAuthenticator.GetAssertion(WebAuthnPluginOperationRequest* request,
                                          WebAuthnPluginOperationResponse* response) =>
        GetAssertion(request, response);

    int IPluginAuthenticator.CancelOperation(WebAuthnPluginCancelOperationRequest* request) => CancelOperation(request);

    int IPluginAuthenticator.GetLockStatus(int* lockStatus) => GetLockStatus(lockStatus);

    public int MakeCredential(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response) =>
        Ceremony(request, response, create: true);

    public int GetAssertion(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response) =>
        Ceremony(request, response, create: false);

    public int CancelOperation(WebAuthnPluginCancelOperationRequest* request)
    {
        using var _ = _idle.Begin();
        var watch = Stopwatch.StartNew();
        var trace = new Trace();
        var id = request is null ? Guid.Empty : request->transactionId;
        var hr = CancelCore(request, trace);
        Record("cancel", id, hr, trace, watch);
        return hr;
    }

    private int CancelCore(WebAuthnPluginCancelOperationRequest* request, Trace trace)
    {
        try
        {
            trace.Check = "copy";
            if (request is null)
                return HResults.EInvalidArg;
            var signature = Copy(request->pbRequestSignature, request->cbRequestSignature, RequestSignature.MaxSignatureLength);
            if (signature is null)
                return Ends(trace, "bad_signature", HResults.NteBadSignature);
            var id = request->transactionId;
            trace.Check = "transaction";
            if (!_transactions.TryGetValue(id, out var transaction))
            {
                // Perhaps its ceremony is still fetching the signing key: remember it, checked at registration.
                _pendingCancels.Remember(id, signature);
                return Ends(trace, "remembered", HResults.NteNotFound);  // as the sample [S4]
            }
            if (!Verified(CancelSignedData(transaction), signature, trace))
                return HResults.NteBadSignature;
            transaction.TryCancel();
            return Ends(trace, "cancelled_transaction", HResults.SOk);
        }
        catch (Exception)
        {
            return Ends(trace, "failed", HResults.EFail);
        }
    }

    /// <summary>
    /// What Windows signs for a cancel. UNVERIFIED (U15): no Microsoft source says; the sample does not check it.
    /// KeePassPasskey ([S10], secondary) found by trial that it is the encoded request of the operation being
    /// cancelled. Fails closed: if that is wrong, every cancel is refused and the operation ends at its timer.
    /// </summary>
    internal static ReadOnlySpan<byte> CancelSignedData(byte[] encodedRequestOfTransaction) => encodedRequestOfTransaction;

    private static ReadOnlySpan<byte> CancelSignedData(Transaction transaction) =>
        CancelSignedData(transaction.EncodedRequest);

    /// <summary>
    /// Asks the app with a 2 s budget and never starts it; no pipe, no answer or anything odd is
    /// <c>PluginLocked</c>. Unsigned in the IDL (design note section 9 residual).
    /// </summary>
    public int GetLockStatus(int* lockStatus)
    {
        using var _ = _idle.Begin();
        if (lockStatus is null)
            return HResults.EInvalidArg;
        *lockStatus = PluginLockStatus.PluginLocked;
        var watch = Stopwatch.StartNew();
        var trace = new Trace { Check = "pipe", Outcome = "locked" };
        var id = Guid.NewGuid();
        try
        {
            var runner = new OperationRunner(_pipe, _launcher, _timings.LockStatus, TimeSpan.Zero)
            {
                StartsApp = false,
                RetryInterval = _timings.RetryInterval,
                CancelTimeout = _timings.Cancel,
            };
            var task = runner.RunAsync(SystemMessages.LockStatus(), id, CancellationToken.None);
            if (!task.Wait(_timings.LockStatusGuard))
            {
                trace.Detail = "guard_timeout";
            }
            else
            {
                var result = task.Result;
                trace.Stage = result.Stage;
                trace.Detail = result.Detail;
                trace.ApiHResult = result.HResult == HResults.SOk ? null : result.HResult;
                if (result is { HResult: HResults.SOk, Reply: { } reply } && !SystemMessages.ReadLockStatusReply(reply).Locked)
                {
                    *lockStatus = PluginLockStatus.PluginUnlocked;
                    trace.Outcome = "unlocked";
                }
            }
        }
        catch (Exception)
        {
            trace.Detail = "error";  // stays locked
        }
        Record("lock_status", id, HResults.SOk, trace, watch);
        return HResults.SOk;
    }

    // -- ceremonies -----------------------------------------------------------------------------------------

    /// <summary>
    /// Every webauthn.dll call (signing key, decode, encode) runs here, on the incoming COM call thread, as the
    /// Microsoft sample ([S4] PluginAuthenticatorImpl.cpp) and KeePassPasskey ([S10]) do: the platform serves them
    /// as calls nested in the operation it is running. Made from another thread while the COM thread waited, the
    /// key fetch failed on the first real device test (WebAuthN log: 0x800706FF RPC_S_CALL_IN_PROGRESS at
    /// MakeCredentialActiveCheck) and every request ended before the pipe. Only this process's own work (caller
    /// hint, foreground grant, pipe, app start, reply check) runs on the thread pool, bounded by
    /// <see cref="ProviderTimings.Total"/> from entry; the platform's own calls are not timed by us.
    /// </summary>
    private int Ceremony(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response, bool create)
    {
        using var activity = _idle.Begin();
        var entry = Stopwatch.StartNew();
        var trace = new Trace();
        var id = request is null ? Guid.Empty : request->transactionId;
        var hr = CeremonyCore(request, response, create, entry, trace);
        Record(create ? "make_credential" : "get_assertion", id, hr, trace, entry);
        return hr;
    }

    private int CeremonyCore(WebAuthnPluginOperationRequest* request, WebAuthnPluginOperationResponse* response,
                             bool create, Stopwatch entry, Trace trace)
    {
        try
        {
            trace.Check = "request";
            if (request is null || response is null)
                return Ends(trace, "invalid_request", HResults.EInvalidArg);
            *response = default;
            if (request->requestType != WebAuthnPluginRequestType.Ctap2Cbor)
                return Ends(trace, "invalid_request", HResults.EInvalidArg);
            var encoded = Copy(request->pbEncodedRequest, request->cbEncodedRequest, MaxEncodedRequest);
            var signature = Copy(request->pbRequestSignature, request->cbRequestSignature,
                                 RequestSignature.MaxSignatureLength);
            if (signature is null || encoded is null)
                return Ends(trace, signature is null ? "bad_signature" : "invalid_request", HResults.NteBadSignature);
            var transactionId = request->transactionId;
            var hWnd = request->hWnd;

            if (!Verified(encoded, signature, trace))
                return HResults.NteBadSignature;
            trace.Check = "replay";
            if (!_replays.TryAccept(signature))
                return Ends(trace, "replay", HResults.NteBadSignature);

            // Not disposed while the work may still hold its token.
            var abort = new CancellationTokenSource();
            var transaction = new Transaction(encoded, abort.Token);
            trace.Check = "transaction";
            if (!_transactions.TryAdd(transactionId, transaction))
            {
                transaction.Dispose();
                return Ends(trace, "duplicate_transaction", HResults.EInvalidArg);  // a second call with a running id
            }
            Task<Outcome>? work = null;
            try
            {
                trace.Check = "early_cancel";
                if (_pendingCancels.Take(transactionId) is { } early
                    && Verified(CancelSignedData(transaction), early, new Trace()))
                {
                    transaction.TryCancel();
                    trace.Detail = "early_cancel_applied";
                }
                trace.Check = "decode";
                if (create)
                {
                    var hr = _api.DecodeMakeCredential(encoded, out var input);
                    if (hr != HResults.SOk || input is null)
                        return Api(trace, "decode_failed", hr, hr == HResults.SOk ? HResults.EInvalidArg : hr);
                    trace.Check = "map";
                    if (Message(() => CtapMapping.ToRequest(input, _callers.From(hWnd))) is not { } message)
                        return Ends(trace, "invalid_request", HResults.EInvalidArg);
                    trace.Check = "pipe";
                    work = Task.Run(() => CreateWork(input, message, transaction, transactionId, entry, trace));
                }
                else
                {
                    var hr = _api.DecodeGetAssertion(encoded, out var input);
                    if (hr != HResults.SOk || input is null)
                        return Api(trace, "decode_failed", hr, hr == HResults.SOk ? HResults.EInvalidArg : hr);
                    trace.Check = "map";
                    if (Message(() => CtapMapping.ToRequest(input, _callers.From(hWnd))) is not { } message)
                        return Ends(trace, "invalid_request", HResults.EInvalidArg);
                    trace.Check = "pipe";
                    work = Task.Run(() => GetWork(input, message, transaction, transactionId, entry, trace));
                }
                var left = _timings.Total - ProviderTimings.DeliverMargin - entry.Elapsed;
                if (left <= TimeSpan.Zero || !work.Wait(left))
                {
                    abort.Cancel();  // the runner sends passkey_cancel_system if the app may hold a prompt
                    trace.Stage = trace.Progress?.Stage ?? trace.Stage;
                    return Ends(trace, "timeout", HResults.Timeout);
                }
                return Deliver(work.Result, response, trace);
            }
            finally
            {
                _transactions.TryRemove(new KeyValuePair<Guid, Transaction>(transactionId, transaction));
                if (work is null || work.IsCompleted)
                    transaction.Dispose();
                else
                    _ = work.ContinueWith(_ => transaction.Dispose(), CancellationToken.None,
                                          TaskContinuationOptions.None, TaskScheduler.Default);
            }
        }
        catch (Exception)
        {
            return Ends(trace, "failed", HResults.EFail);
        }
    }

    private static int Ends(Trace trace, string outcome, int hr)
    {
        trace.Outcome = outcome;
        return hr;
    }

    private static int Api(Trace trace, string outcome, int apiHr, int hr)
    {
        trace.ApiHResult = apiHr;
        return Ends(trace, outcome, hr);
    }

    /// <summary>One line in the diagnostics log; reason words and HRESULTs only.</summary>
    private void Record(string operation, Guid transactionId, int hr, Trace trace, Stopwatch watch)
    {
        var outcome = trace.Outcome ?? (hr == HResults.SOk ? "ok" : "failed");
        _log.Write(new OperationRecord(operation, transactionId, outcome, hr, trace.Check, trace.Stage, trace.Detail,
                                       trace.ApiHResult, watch.ElapsedMilliseconds));
    }

    /// <summary>The outcome word for a finished pipe call.</summary>
    private static string PipeOutcome(OperationResult result) => result switch
    {
        { HResult: HResults.Timeout } => "timeout",
        { HResult: HResults.Cancelled } => "cancelled",
        { Stage: "app_reply" } => "app_error",
        { Detail: { } detail } when detail.StartsWith("unavailable_", StringComparison.Ordinal) => "app_unavailable",
        { Detail: { } detail } when detail.StartsWith("server_", StringComparison.Ordinal)
                                    || detail.StartsWith("state_", StringComparison.Ordinal)
                                    || detail.StartsWith("pipe_open_", StringComparison.Ordinal) => "pipe_refused",
        _ => "pipe_failed",
    };

    private static JsonObject? Message(Func<CreateSystemRequest> map)
    {
        try
        {
            return SystemMessages.ToJson(map());
        }
        catch (CtapMappingException)
        {
            return null;
        }
    }

    private static JsonObject? Message(Func<GetSystemRequest> map)
    {
        try
        {
            return SystemMessages.ToJson(map());
        }
        catch (CtapMappingException)
        {
            return null;
        }
    }

    /// <summary>What the thread-pool part hands back: an HRESULT, or the checked reply to encode.</summary>
    private readonly record struct Outcome(int HResult, AttestationOutput? Attestation, AssertionOutput? Assertion);

    private static Outcome Fail(int hr) => new(hr, null, null);

    private Outcome CreateWork(MakeCredentialInput input, JsonObject message, Transaction transaction, Guid transactionId,
                               Stopwatch entry, Trace trace)
    {
        try
        {
            var result = Forward(message, transaction, transactionId, entry, trace);
            trace.Stage = result.Stage;
            trace.Detail = result.Detail ?? trace.Detail;
            if (result.HResult != HResults.SOk || result.Reply is null)
            {
                trace.Outcome = PipeOutcome(result);
                return Fail(result.HResult == HResults.SOk ? HResults.EFail : result.HResult);
            }
            trace.Check = "reply_check";
            try
            {
                return new Outcome(HResults.SOk, CtapMapping.ReadCreateReply(result.Reply, input), null);
            }
            catch (CtapMappingException)
            {
                trace.Outcome = "reply_rejected";
                return Fail(HResults.EFail);
            }
        }
        catch (Exception)
        {
            return Fail(HResults.EFail);
        }
    }

    private Outcome GetWork(GetAssertionInput input, JsonObject message, Transaction transaction, Guid transactionId,
                            Stopwatch entry, Trace trace)
    {
        try
        {
            var result = Forward(message, transaction, transactionId, entry, trace);
            trace.Stage = result.Stage;
            trace.Detail = result.Detail ?? trace.Detail;
            if (result.HResult != HResults.SOk || result.Reply is null)
            {
                trace.Outcome = PipeOutcome(result);
                return Fail(result.HResult == HResults.SOk ? HResults.EFail : result.HResult);
            }
            trace.Check = "reply_check";
            try
            {
                return new Outcome(HResults.SOk, null, CtapMapping.ReadGetReply(result.Reply, input));
            }
            catch (CtapMappingException)
            {
                trace.Outcome = "reply_rejected";
                return Fail(HResults.EFail);
            }
        }
        catch (Exception)
        {
            return Fail(HResults.EFail);
        }
    }

    /// <summary>On the COM thread: encode with webauthn.dll and hand the CoTaskMem buffer over ([S4]).</summary>
    private int Deliver(Outcome outcome, WebAuthnPluginOperationResponse* response, Trace trace)
    {
        if (outcome.HResult != HResults.SOk)
            return outcome.HResult;
        trace.Check = "encode";
        var encoded = default(EncodedResponse);
        var hr = outcome.Attestation is { } attestation
            ? _api.EncodeMakeCredentialResponse(attestation, out encoded)
            : outcome.Assertion is { } assertion
                ? _api.EncodeGetAssertionResponse(assertion, out encoded)
                : HResults.EFail;
        if (hr != HResults.SOk || encoded.Buffer == 0 || encoded.Length == 0)
        {
            if (encoded.Buffer != 0)
                Marshal.FreeCoTaskMem(encoded.Buffer);
            return Api(trace, "encode_failed", hr, hr == HResults.SOk ? HResults.EFail : hr);
        }
        trace.Outcome = "ok";
        response->cbEncodedResponse = encoded.Length;
        response->pbEncodedResponse = (byte*)encoded.Buffer;
        return HResults.SOk;
    }

    private OperationResult Forward(JsonObject message, Transaction transaction, Guid transactionId, Stopwatch entry,
                                    Trace trace)
    {
        // Out of time or aborted (the COM thread already answered): stop before granting foreground rights.
        var timeout = _timings.RunnerTimeout(entry.Elapsed);
        if (timeout <= TimeSpan.Zero)
            return new OperationResult(HResults.Timeout, null) { Stage = "before_pipe" };
        if (transaction.Cancel.IsCancellationRequested)
            return new OperationResult(HResults.Cancelled, null) { Stage = "before_pipe" };
        // Shared with the runner (it reuses an ambient progress), so a COM-thread timeout can name the stage.
        var progress = new PipeProgress();
        PipeProgress.Current = progress;
        trace.Progress = progress;
        _foreground.AllowAgent();
        var runner = new OperationRunner(_pipe, _launcher, timeout, _timings.ConnectWindow)
        {
            RetryInterval = _timings.RetryInterval,
            CancelTimeout = _timings.Cancel,
        };
        try
        {
            // The runner bounds itself (timer + bounded cancel); the COM thread's wait bounds everything again.
            return runner.RunAsync(message, transactionId, transaction.Cancel.Token).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return new OperationResult(HResults.EFail, null) { Stage = progress.Stage, Detail = "error" };
        }
    }

    // -- helpers --------------------------------------------------------------------------------------------

    /// <summary>Key fetch then verification; on failure the trace names which, with the key fetch's HRESULT.</summary>
    private bool Verified(ReadOnlySpan<byte> data, byte[] signature, Trace trace)
    {
        trace.Check = "key_fetch";
        var hr = _api.GetOperationSigningPublicKey(_clsid, out var key);
        if (hr != HResults.SOk || key.Length == 0)
        {
            trace.ApiHResult = hr;
            trace.Outcome = "key_fetch_failed";
            return false;
        }
        trace.Check = "signature_verify";
        if (!RequestSignature.Verify(key, data, signature))
        {
            trace.Outcome = "bad_signature";
            trace.Detail = RequestSignature.KeyKind(key);
            return false;
        }
        return true;
    }

    private static byte[]? Copy(byte* data, uint length, int max)
    {
        if (data is null || length == 0 || length > max)
            return null;
        return new ReadOnlySpan<byte>(data, (int)length).ToArray();
    }
}
