namespace LocalGateKeys.PasskeyProvider.Protocol;

// Messages carry a fixed description only: never a path, a token or request contents. Details are fixed reason
// words for the diagnostics log (Diagnostics/ProviderLog.cs).

/// <summary>A frame that is not one well-formed JSON object of at most 1 MiB, or a reply of the wrong shape.</summary>
public sealed class PipeProtocolException(string message) : Exception(message);

/// <summary>
/// The app is not reachable yet (no state file, or no pipe of that name). Raised before anything is written,
/// so the caller may start the app and retry. <see cref="Reason"/>: <c>state_missing</c>, <c>pipe_missing</c> or
/// <c>pipe_busy</c>.
/// </summary>
public sealed class AgentUnavailableException(string reason = "state_missing") : Exception("LocalGateKeys is not running")
{
    public string Reason { get; } = reason;
}

/// <summary>
/// The state file or the pipe's server failed a check (shape, user SID, server pid, server image). Raised before
/// anything is written; never retried. <see cref="Code"/> uses the agent's bridge codes; <see cref="Detail"/>
/// names the failed sub-check for the diagnostics log.
/// </summary>
public sealed class AgentRejectedException(string code, string? detail = null)
    : Exception("LocalGateKeys pipe check failed: " + code)
{
    public string Code { get; } = code;
    public string Detail { get; } = detail ?? code;
}
