using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace LocalGateKeys.PasskeyProvider.Protocol;

// The five system actions of design note section 5.2. Binary values are base64url without padding (as
// passkeys.py). OperationRunner adds system_protocol and transaction_id; PipeClient adds the token.

/// <summary>Display hint about the calling app (image file name, window title); never used for policy.</summary>
public sealed record CallerHint(string? Image, string? Title);

public sealed record GetSystemRequest(
    string RpId, string ClientDataHash, IReadOnlyList<string> AllowCredentials, string UserVerification,
    CallerHint? Caller)
{
    public string Action => "passkey_get_system";
}

public sealed record CreateSystemRequest(
    string RpId, string RpName, string UserId, string UserName, string UserDisplayName, string ClientDataHash,
    IReadOnlyList<int> Algorithms, IReadOnlyList<string> ExcludeCredentials, bool ResidentKey,
    string UserVerification, CallerHint? Caller)
{
    public string Action => "passkey_create_system";
}

/// <summary>
/// <c>AttestationObject</c> (fmt none, CBOR, base64url) and <c>PublicKeyAlgorithm</c> (-7) are sent too; the
/// provider builds its response from the authenticator data and the format.
/// </summary>
public sealed record CreateSystemReply(
    string CredentialId, string AuthenticatorData, string AttestationFormat, string? AttestationObject = null,
    int? PublicKeyAlgorithm = null);

public sealed record GetSystemReply(
    string CredentialId, string AuthenticatorData, string Signature, string UserHandle, string UserName,
    string UserDisplayName);

public sealed record LockStatusReply(bool Locked);

public sealed record CredentialMetadata(
    string CredentialId, string RpId, string RpName, string UserId, string UserName, string UserDisplayName);

public sealed record CredentialsReply(IReadOnlyList<CredentialMetadata> Credentials);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    NumberHandling = JsonNumberHandling.Strict)]
[JsonSerializable(typeof(GetSystemRequest))]
[JsonSerializable(typeof(CreateSystemRequest))]
[JsonSerializable(typeof(CreateSystemReply))]
[JsonSerializable(typeof(GetSystemReply))]
[JsonSerializable(typeof(LockStatusReply))]
[JsonSerializable(typeof(CredentialsReply))]
internal sealed partial class SystemMessagesContext : JsonSerializerContext;

public static class SystemMessages
{
    public static JsonObject ToJson(GetSystemRequest request) => Node(request, SystemMessagesContext.Default.GetSystemRequest);

    public static JsonObject ToJson(CreateSystemRequest request) =>
        Node(request, SystemMessagesContext.Default.CreateSystemRequest);

    /// <summary>Cancels the transaction whose id the runner stamps on it.</summary>
    public static JsonObject Cancel() => new() { ["action"] = "passkey_cancel_system" };

    public static JsonObject LockStatus() => new() { ["action"] = "passkey_lock_status_system" };

    public static JsonObject Credentials() => new() { ["action"] = "passkey_credentials_system" };

    // Readers for an ok reply; a missing, null or mistyped field is a PipeProtocolException.
    public static CreateSystemReply ReadCreateReply(JsonObject reply) =>
        Read(reply, SystemMessagesContext.Default.CreateSystemReply);

    public static GetSystemReply ReadGetReply(JsonObject reply) => Read(reply, SystemMessagesContext.Default.GetSystemReply);

    public static LockStatusReply ReadLockStatusReply(JsonObject reply) =>
        Read(reply, SystemMessagesContext.Default.LockStatusReply);

    public static CredentialsReply ReadCredentialsReply(JsonObject reply) =>
        Read(reply, SystemMessagesContext.Default.CredentialsReply);

    private static JsonObject Node<T>(T value, JsonTypeInfo<T> info) =>
        JsonSerializer.SerializeToNode(value, info)!.AsObject();

    private static T Read<T>(JsonObject reply, JsonTypeInfo<T> info)
    {
        try
        {
            return reply.Deserialize(info) ?? throw new PipeProtocolException("empty reply");
        }
        catch (JsonException)
        {
            throw new PipeProtocolException("reply has the wrong shape");
        }
        catch (InvalidOperationException)
        {
            throw new PipeProtocolException("reply has the wrong shape");
        }
    }
}
