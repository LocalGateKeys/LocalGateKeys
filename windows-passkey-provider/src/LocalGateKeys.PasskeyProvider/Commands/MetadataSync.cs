using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Commands;

/// <summary>One entry of Windows' credential metadata cache: IDs and names, never key material.</summary>
public sealed record CredentialDetail(
    byte[] CredentialId, string RpId, string RpName, byte[] UserId, string UserName, string UserDisplayName);

/// <summary>
/// <c>--sync</c> (design note section 5.4): asks the running app for the names over the pipe
/// (<c>passkey_credentials_system</c>; the app pins this exe), then replaces Windows' metadata cache with
/// <c>WebAuthNPluginAuthenticatorRemoveAllCredentials</c> + <c>...AddCredentials</c>. It never starts the app, and when
/// the app cannot answer (locked, not running, off) the cache is left as it is.
/// </summary>
public static class MetadataSync
{
    public const int MaxCredentials = 10_000;
    public const int MaxCredentialIdBytes = 1023;
    public const int MaxUserIdBytes = 64;
    public const int MaxRpIdLength = 253;
    public const int MaxNameLength = 1024;
    public static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The real query: one <c>passkey_credentials_system</c> request, app not started.</summary>
    public static Func<CancellationToken, Task<OperationResult>> Query(IPipeConnector pipe, IProcessLauncher launcher) =>
        ct => new OperationRunner(pipe, launcher, QueryTimeout, TimeSpan.Zero) { StartsApp = false }
            .RunAsync(SystemMessages.Credentials(), Guid.NewGuid(), ct);

    public static JsonObject Run(CliContext context, out bool ok)
    {
        ok = false;
        if (!context.BuildSupported())
            return new JsonObject { ["ok"] = false, ["error"] = "unsupported_build" };
        if (context.QueryCredentials is null)
            return new JsonObject { ["ok"] = false, ["error"] = "unavailable" };
        OperationResult result;
        using (var cts = new CancellationTokenSource(QueryTimeout + TimeSpan.FromSeconds(1)))
        {
            var query = context.QueryCredentials(cts.Token);
            result = query.Wait(QueryTimeout + TimeSpan.FromSeconds(2)) ? query.Result : new(HResults.Timeout, null);
        }
        if (result.HResult != HResults.SOk || result.Reply is null)
            return Failure("query_failed", result.HResult == HResults.SOk ? HResults.EFail : result.HResult);
        CredentialsReply reply;
        try
        {
            reply = SystemMessages.ReadCredentialsReply(result.Reply);
        }
        catch (PipeProtocolException)
        {
            return new JsonObject { ["ok"] = false, ["error"] = "bad_reply" };
        }
        var details = ToDetails(reply.Credentials);
        var removed = context.Api.RemoveAllCredentials(context.Clsid);
        if (removed is not (HResults.SOk or HResults.NteNotFound))
            return Failure("sync_failed", removed);
        if (details.Count > 0)
        {
            var added = context.Api.AddCredentials(context.Clsid, details);
            if (added != HResults.SOk)
                return Failure("sync_failed", added);
        }
        ok = true;
        return new JsonObject { ["ok"] = true, ["count"] = details.Count };
    }

    /// <summary>
    /// Valid entries only (strict base64url IDs, bounded strings), each credential ID once (the first wins; imports can
    /// duplicate one, and a batch Windows rejects would leave the cache empty), at most <see cref="MaxCredentials"/>.
    /// </summary>
    public static IReadOnlyList<CredentialDetail> ToDetails(IEnumerable<CredentialMetadata> credentials)
    {
        var details = new List<CredentialDetail>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in credentials)
        {
            if (details.Count >= MaxCredentials)
                break;
            if (entry is null)
                continue;
            byte[] credentialId, userId;
            try
            {
                credentialId = CtapMapping.Unb64(entry.CredentialId);
                userId = CtapMapping.Unb64(entry.UserId);
            }
            catch (CtapMappingException)
            {
                continue;
            }
            if (credentialId.Length is 0 or > MaxCredentialIdBytes || userId.Length is 0 or > MaxUserIdBytes)
                continue;
            if (entry.RpId.Length is 0 or > MaxRpIdLength || !Clean(entry.RpId) || !Clean(entry.RpName)
                || !Clean(entry.UserName) || !Clean(entry.UserDisplayName))
                continue;
            if (!seen.Add(Convert.ToHexString(credentialId)))
                continue;
            details.Add(new CredentialDetail(credentialId, entry.RpId, entry.RpName, userId, entry.UserName,
                                             entry.UserDisplayName));
        }
        return details;

        static bool Clean(string value) => value.Length <= MaxNameLength && !value.Any(char.IsControl);
    }

    private static JsonObject Failure(string error, int hr) => new()
    {
        ["ok"] = false,
        ["error"] = error,
        ["hresult"] = "0x" + hr.ToString("X8", System.Globalization.CultureInfo.InvariantCulture),
    };
}
