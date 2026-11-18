using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Runtime;

public readonly record struct OperationResult(int HResult, JsonObject? Reply)
{
    /// <summary>Where the call ended (a <see cref="PipeProgress"/> stage, or <c>reply</c>); diagnostics only.</summary>
    public string Stage { get; init; } = "";

    /// <summary>A fixed reason word (failed sub-check, app error code, ...); diagnostics only.</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// One Windows transaction against the app: stamps <c>system_protocol</c> and <c>transaction_id</c>, starts the
/// app once and retries the pipe within the connect window when it is not running, and holds a hard timer. Every
/// path ends in an HRESULT (design note section 7); a ceremony that times out, is cancelled by Windows, or breaks
/// after it may have reached the app is followed by <c>passkey_cancel_system</c> for the same transaction.
/// Nothing is logged: requests and replies hold user data, and the client adds the token.
/// </summary>
public sealed class OperationRunner
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DefaultConnectWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan DefaultRetryInterval = TimeSpan.FromMilliseconds(250);
    public static readonly TimeSpan DefaultCancelTimeout = TimeSpan.FromSeconds(2);
    public const int SystemProtocol = 1;

    public const string CreateAction = "passkey_create_system";
    public const string GetAction = "passkey_get_system";
    public const string CancelAction = "passkey_cancel_system";
    public const string LockStatusAction = "passkey_lock_status_system";
    public const string CredentialsAction = "passkey_credentials_system";

    private static readonly HashSet<string> Actions =
        [CreateAction, GetAction, CancelAction, LockStatusAction, CredentialsAction];

    private readonly IPipeConnector _pipe;
    private readonly IProcessLauncher _launcher;
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _connectWindow;
    private int _used;

    public OperationRunner(IPipeConnector pipe, IProcessLauncher launcher, TimeSpan timeout, TimeSpan connectWindow)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(connectWindow, TimeSpan.Zero);
        _pipe = pipe;
        _launcher = launcher;
        _timeout = timeout;
        _connectWindow = connectWindow;
    }

    /// <summary>False for <c>GetLockStatus</c>: a stopped app is reported, never started.</summary>
    public bool StartsApp { get; set; } = true;

    public TimeSpan RetryInterval { get; init; } = DefaultRetryInterval;

    /// <summary>How long the follow-up cancel may take (outside the main timer, so the worst case is bounded).</summary>
    public TimeSpan CancelTimeout { get; init; } = DefaultCancelTimeout;

    /// <summary>The request as sent, without the token: a copy with the protocol and transaction id stamped.</summary>
    public static JsonObject PrepareOutbound(JsonObject request, Guid transactionId)
    {
        var outbound = request.DeepClone().AsObject();
        outbound.Remove("token");  // only the pipe client adds it, from the agent state
        outbound["system_protocol"] = SystemProtocol;
        outbound["transaction_id"] = TransactionText(transactionId);
        return outbound;
    }

    /// <summary>Lower-case, hyphenated: the form the app's transaction pattern requires.</summary>
    public static string TransactionText(Guid transactionId) => transactionId.ToString("D");

    public async Task<OperationResult> RunAsync(JsonObject request, Guid transactionId, CancellationToken windowsCancel)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Interlocked.Exchange(ref _used, 1) != 0)
            throw new InvalidOperationException("One OperationRunner per transaction.");
        var action = request["action"] is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;
        if (action is null || !Actions.Contains(action))
            return Fail(HResults.EInvalidArg);
        if (windowsCancel.IsCancellationRequested)
            return Fail(HResults.Cancelled);

        var ceremony = action is CreateAction or GetAction;
        var outbound = PrepareOutbound(request, transactionId);
        var progress = PipeProgress.Current ?? new PipeProgress();
        PipeProgress.Current = progress;
        string? unavailable = null;
        using var timer = new CancellationTokenSource(_timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timer.Token, windowsCancel);
        var ct = linked.Token;
        var mayHaveReachedApp = false;
        Stopwatch? connecting = null;
        try
        {
            while (true)
            {
                try
                {
                    mayHaveReachedApp = true;
                    var reply = await SendBoundedAsync(_pipe, outbound, ct).ConfigureAwait(false);
                    return Map(reply);
                }
                catch (AgentUnavailableException ex)
                {
                    mayHaveReachedApp = false;
                    unavailable = "unavailable_" + ex.Reason;
                    if (!StartsApp)
                        return Fail(HResults.AppNotRunning) with { Stage = progress.Stage, Detail = unavailable };
                    if (connecting is null)
                    {
                        connecting = Stopwatch.StartNew();
                        _launcher.StartAgentOnce();
                    }
                    var left = _connectWindow - connecting.Elapsed;
                    if (left <= TimeSpan.Zero)
                        return Fail(HResults.AppNotRunning) with { Stage = progress.Stage, Detail = unavailable };
                    await Task.Delay(left < RetryInterval ? left : RetryInterval, ct).ConfigureAwait(false);
                }
            }
        }
        catch (AgentRejectedException ex)
        {
            // A pin check failed before anything was written.
            return Fail(HResults.EFail) with { Stage = progress.Stage, Detail = ex.Detail };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            var hr = windowsCancel.IsCancellationRequested ? HResults.Cancelled : HResults.Timeout;
            var stage = progress.Stage;  // before the follow-up cancel moves it
            if (ceremony && mayHaveReachedApp)
                await SendCancelAsync(transactionId).ConfigureAwait(false);
            return Fail(hr) with { Stage = stage, Detail = mayHaveReachedApp ? null : unavailable };
        }
        catch (Exception ex)
        {
            // Broken pipe, bad frame, anything else after the write: the app may hold an open prompt.
            var stage = progress.Stage;
            if (ceremony && mayHaveReachedApp)
                await SendCancelAsync(transactionId).ConfigureAwait(false);
            return Fail(HResults.EFail) with
            {
                Stage = stage,
                Detail = ex is PipeProtocolException ? "protocol" : ex is IOException ? "io" : "error",
            };
        }
    }

    private static OperationResult Fail(int hr) => new(hr, null);

    private static OperationResult Map(JsonObject? reply)
    {
        if (reply?["ok"] is not JsonValue ok)
            return Fail(HResults.EFail);
        if (ok.GetValueKind() == JsonValueKind.True)
            return new OperationResult(HResults.SOk, reply) { Stage = "reply" };
        if (ok.GetValueKind() != JsonValueKind.False)
            return Fail(HResults.EFail) with { Stage = "reply", Detail = "reply_shape" };
        var error = reply["error"] is JsonValue code && code.GetValueKind() == JsonValueKind.String
            ? code.GetValue<string>()
            : null;
        return Fail(ErrorMap.ToHResult(error)) with { Stage = "app_reply", Detail = ErrorMap.KnownCode(error) };
    }

    /// <summary>
    /// The connector runs on the thread pool and is awaited with <paramref name="ct"/>, so neither its synchronous
    /// part (state file, DPAPI, CreateFile, signature check) nor a connector that ignores the token can outlast the
    /// timer or a Windows cancel. An abandoned call's later failure is observed, never left unobserved.
    /// </summary>
    private static async Task<JsonObject> SendBoundedAsync(IPipeConnector pipe, JsonObject request,
                                                          CancellationToken ct)
    {
        var call = Task.Run(() => pipe.SendAsync(request, ct), ct);
        try
        {
            return await call.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!call.IsCompleted)
        {
            _ = call.ContinueWith(static t => _ = t.Exception, CancellationToken.None,
                                  TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                                  TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>Best effort and bounded; never starts the app and never throws.</summary>
    private async Task SendCancelAsync(Guid transactionId)
    {
        var cancel = PrepareOutbound(new JsonObject { ["action"] = CancelAction }, transactionId);
        using var cts = new CancellationTokenSource(CancelTimeout);
        try
        {
            await SendBoundedAsync(_pipe, cancel, cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The app drops the approval at its own 25 s deadline anyway.
        }
    }
}
