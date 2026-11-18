using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>Sends one request to the app and returns its reply (one connection per request).</summary>
public interface IPipeConnector
{
    /// <exception cref="AgentUnavailableException">Not reachable; nothing was written.</exception>
    /// <exception cref="AgentRejectedException">A pin check failed; nothing was written.</exception>
    Task<JsonObject> SendAsync(JsonObject request, CancellationToken ct);
}

/// <summary>
/// The client end of the agent pipe, a port of <c>forward_named_pipe</c>: validated state file (user SID), the pipe
/// opened with identification-only SQOS, <c>GetNamedPipeServerProcessId</c> equal to the recorded pid, and the
/// server image checked, all before the token or the request is written. No retry after the write: the app may
/// already be acting on it.
/// </summary>
public sealed class PipeClient : IPipeConnector
{
    private const uint BusyWaitMs = 1000;
    private readonly Func<AgentState> _loadState;
    private readonly IServerImageCheck _imageCheck;

    public PipeClient(Func<AgentState> loadState, IServerImageCheck imageCheck)
    {
        _loadState = loadState;
        _imageCheck = imageCheck;
    }

    public static PipeClient ForInstalledProvider() =>
        new(AgentState.LoadDefault, ServerImageCheck.ForInstalledProvider());

    public async Task<JsonObject> SendAsync(JsonObject request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();
        PipeProgress.Mark("state");
        var state = _loadState();  // fresh each time: the app may have restarted with a new pipe and pid
        if (!AgentState.ValidPipeName(state.PipeName))
            throw new AgentRejectedException("agent_state_invalid", "state_pipe_name");
        PipeProgress.Mark("connect");
        var handle = Open(state.PipeName);
        PipeProgress.Mark("server_pin");
        try
        {
            CheckServer(handle, state.Pid);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
        await using var stream = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, handle);

        var outbound = request.DeepClone().AsObject();
        outbound["token"] = state.Token;
        var frame = PipeFraming.Encode(outbound);
        PipeProgress.Mark("send");
        outbound.Clear();
        try
        {
            await stream.WriteAsync(frame, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(frame);
        }
        PipeProgress.Mark("awaiting_reply");
        return await PipeFraming.ReadFrameAsync(stream, ct).ConfigureAwait(false);
    }

    private void CheckServer(SafePipeHandle handle, int expectedPid)
    {
        if (expectedPid <= 0)
            throw new AgentRejectedException("agent_connection_changed", "server_pid_missing");
        // Hold the recorded process open first: while this handle lives its pid cannot be reused, so the pipe's
        // server pid (read after it) and the image check below are provably about this one process.
        using var process = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false,
                                                      (uint)expectedPid);
        if (process.IsInvalid)
            throw new AgentRejectedException("agent_connection_changed", "server_not_running");
        if (!NativeMethods.GetNamedPipeServerProcessId(handle, out var pid) || pid != (uint)expectedPid)
            throw new AgentRejectedException("agent_connection_changed", "server_pid_mismatch");
        if (_imageCheck.Refusal(expectedPid) is { } refusal)
            throw new AgentRejectedException("agent_server_untrusted", "server_" + refusal);
    }

    private static SafePipeHandle Open(string pipeName)
    {
        for (var attempt = 0; ; attempt++)
        {
            var handle = NativeMethods.CreateFile(
                pipeName, NativeMethods.GenericRead | NativeMethods.GenericWrite, 0, IntPtr.Zero,
                NativeMethods.OpenExisting,
                NativeMethods.SecuritySqosPresent | NativeMethods.SecurityIdentification | NativeMethods.FileFlagOverlapped,
                IntPtr.Zero);
            if (!handle.IsInvalid)
                return handle;
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            switch (error)
            {
                // Every instance busy: the listener creates the next one right away, so wait for it once.
                case NativeMethods.ErrorPipeBusy when attempt == 0 && NativeMethods.WaitNamedPipe(pipeName, BusyWaitMs):
                    continue;
                case NativeMethods.ErrorFileNotFound or NativeMethods.ErrorPathNotFound:
                    throw new AgentUnavailableException("pipe_missing");
                case NativeMethods.ErrorPipeBusy or NativeMethods.ErrorSemTimeout:
                    throw new AgentUnavailableException("pipe_busy");
                default:
                    // The Win32 error number only (e.g. 5 = access denied): no path, no name.
                    throw new AgentRejectedException("agent_access_denied",
                                                     "pipe_open_error_" + error.ToString(CultureInfo.InvariantCulture));
            }
        }
    }
}
