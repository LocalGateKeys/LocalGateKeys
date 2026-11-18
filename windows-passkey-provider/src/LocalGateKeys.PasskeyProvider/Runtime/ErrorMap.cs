namespace LocalGateKeys.PasskeyProvider.Runtime;

public static class HResults
{
    public const int SOk = 0;
    public const int EFail = unchecked((int)0x80004005);
    public const int EInvalidArg = unchecked((int)0x80070057);
    public const int ENotImpl = unchecked((int)0x80004001);
    public const int ENoInterface = unchecked((int)0x80004002);
    public const int ClassENoAggregation = unchecked((int)0x80040110);
    public const int NteBadSignature = unchecked((int)0x80090006);
    public const int NteExists = unchecked((int)0x8009000F);
    public const int NteNotFound = unchecked((int)0x80090011);
    public const int NteInvalidParameter = unchecked((int)0x80090027);
    public const int NteDeviceNotFound = unchecked((int)0x80090035);
    public const int NteUserCancelled = unchecked((int)0x80090036);

    /// <summary>HRESULT_FROM_WIN32(ERROR_TIMEOUT): no reply within the 30 s timer.</summary>
    public const int Timeout = unchecked((int)0x800705B4);

    /// <summary>HRESULT_FROM_WIN32(ERROR_CANCELLED): Windows cancelled the operation.</summary>
    public const int Cancelled = unchecked((int)0x800704C7);

    /// <summary>The app was started once and the pipe retried for 10 s without success.</summary>
    public const int AppNotRunning = NteDeviceNotFound;
}

/// <summary>App reply <c>error</c> codes to the HRESULT returned to Windows (design note section 7).</summary>
public static class ErrorMap
{
    private static readonly HashSet<string> Known =
    [
        "user_cancelled", "locked_declined", "busy", "item_limit", "not_found", "invalid_state", "not_supported",
        "disabled", "invalid_request", "session_changed", "client_not_allowed", "client_signer_mismatch",
        "client_pin_mismatch", "client_pin_unregistered", "unauthorized", "bridge_protocol_error", "locked",
        "timeout", "cancelled",
    ];

    /// <summary>The app's error code when it is one of the known fixed codes, else <c>other</c> (diagnostics).</summary>
    public static string KnownCode(string? appError) =>
        appError is not null && Known.Contains(appError) ? appError : "other";

    public static int ToHResult(string? appError) => appError switch
    {
        // All end as NotAllowedError, so a site learns nothing about which one it was.
        "user_cancelled" or "locked_declined" or "busy" or "item_limit" => HResults.NteUserCancelled,
        "not_found" => HResults.NteNotFound,
        "invalid_state" => HResults.NteExists,
        "not_supported" => HResults.NteInvalidParameter,
        "disabled" => HResults.NteDeviceNotFound,
        _ => HResults.EFail,
    };
}
