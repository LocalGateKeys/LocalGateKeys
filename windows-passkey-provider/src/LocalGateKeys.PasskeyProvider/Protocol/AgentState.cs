using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>
/// The running app's <c>agent-state.json</c> (written by <c>NamedPipeAgentServer.start</c>), validated as
/// <c>forward_named_pipe</c> does: named-pipe transport, the <c>LocalGateKeys-</c> + 32 lower-case hex pipe name,
/// a DPAPI user-scope token (entropy <c>LocalGateKeys.agent-token.v1</c>) of 32 to 256 characters, a positive
/// integer pid, and the current user's SID.
/// </summary>
public sealed class AgentState
{
    public const string PipePrefix = @"\\.\pipe\LocalGateKeys-";
    private const int MaxFileBytes = 64 * 1024;
    private static readonly byte[] TokenEntropy = "LocalGateKeys.agent-token.v1"u8.ToArray();

    /// <summary>Plaintext tokens (<c>"protection": "none"</c>, written only without pywin32) are for development.</summary>
#if DEBUG
    internal const bool PlaintextTokenAllowed = true;
#else
    internal const bool PlaintextTokenAllowed = false;
#endif

    public string PipeName { get; }
    public string Token { get; }
    public int Pid { get; }
    public string UserSid { get; }

    internal AgentState(string pipeName, string token, int pid, string userSid)
    {
        PipeName = pipeName;
        Token = token;
        Pid = pid;
        UserSid = userSid;
    }

    /// <summary>Never the token.</summary>
    public override string ToString() => $"AgentState(pid={Pid})";

    /// <summary><c>%LOCALAPPDATA%\LocalGateKeys\agent-state.json</c> (<c>config.agent_state_path</c>).</summary>
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalGateKeys",
                     "agent-state.json");

    public static string CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new AgentRejectedException("agent_access_denied");
    }

    public static AgentState LoadDefault() => Load(DefaultPath(), CurrentUserSid());

    /// <exception cref="AgentUnavailableException">No state file: the app is not running.</exception>
    /// <exception cref="AgentRejectedException"><c>agent_state_invalid</c> or <c>agent_access_denied</c>.</exception>
    public static AgentState Load(string path, string currentUserSid)
    {
        var state = ReadObject(path);
        var pipe = String(state, "pipe");
        var sid = String(state, "user_sid");
        var token = String(state, "token");
        var protection = state.ContainsKey("protection") ? String(state, "protection") : "none";
        if (String(state, "transport") != "named_pipe" || !ValidPipeName(pipe) || string.IsNullOrEmpty(sid) ||
            string.IsNullOrEmpty(token) || !TryPid(state, out var pid))
            throw Invalid("state_shape");
        if (!string.Equals(sid, currentUserSid, StringComparison.Ordinal))
            throw new AgentRejectedException("agent_access_denied", "state_sid");
        var plain = protection switch
        {
            "dpapi-user" => Unprotect(token),
            "none" when PlaintextTokenAllowed => token,
            _ => throw Invalid("state_protection"),
        };
        if (plain.Length is < 32 or > 256)
            throw Invalid("state_token");
        return new AgentState(pipe!, plain, pid, sid!);
    }

    internal static bool ValidPipeName(string? pipe) =>
        pipe is not null && pipe.Length == PipePrefix.Length + 32 &&
        pipe.StartsWith(PipePrefix, StringComparison.Ordinal) &&
        pipe.AsSpan(PipePrefix.Length).IndexOfAnyExcept("0123456789abcdef") < 0;

    private static JsonObject ReadObject(string path)
    {
        byte[] bytes;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > MaxFileBytes)
                throw Invalid("state_size");
            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
        }
        catch (FileNotFoundException)
        {
            throw new AgentUnavailableException();
        }
        catch (DirectoryNotFoundException)
        {
            throw new AgentUnavailableException();
        }
        catch (IOException)
        {
            throw Invalid("state_io");
        }
        catch (UnauthorizedAccessException)
        {
            throw Invalid("state_access");
        }
        try
        {
            return JsonNode.Parse(bytes, documentOptions: new JsonDocumentOptions { MaxDepth = 16 }) as JsonObject
                   ?? throw Invalid("state_json");
        }
        catch (JsonException)
        {
            throw Invalid("state_json");
        }
        catch (ArgumentException)
        {
            throw Invalid("state_json");
        }
    }

    private static string? String(JsonObject state, string key) =>
        state[key] is JsonValue value && value.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : null;

    private static bool TryPid(JsonObject state, out int pid)
    {
        pid = 0;
        return state["pid"] is JsonValue value && value.GetValueKind() == JsonValueKind.Number &&
               value.TryGetValue(out pid) && pid > 0;
    }

    private static string Unprotect(string token)
    {
        byte[]? plain = null;
        try
        {
            plain = ProtectedData.Unprotect(Convert.FromBase64String(token), TokenEntropy,
                                            DataProtectionScope.CurrentUser);
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(plain);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or DecoderFallbackException)
        {
            throw Invalid("state_dpapi");
        }
        finally
        {
            if (plain is not null)
                CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static AgentRejectedException Invalid(string detail) => new("agent_state_invalid", detail);
}
