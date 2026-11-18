using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Com;
using LocalGateKeys.PasskeyProvider.Diagnostics;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Provider;

namespace LocalGateKeys.PasskeyProvider.Tests.Fakes;

/// <summary>A PluginAuthenticator wired to fakes, and helpers that call it the way COM does (native structs).</summary>
internal sealed class ProviderHarness : IDisposable
{
    public static readonly Guid TestClsid = new("0a6c1d2e-3f40-4b5c-8d9e-1f2a3b4c5d6e");
    public static readonly Guid Txn = Guid.Parse("3F2B8C1E-5D4A-4B6F-9E21-7C0D8A9B1E42");
    public const string TxnText = "3f2b8c1e-5d4a-4b6f-9e21-7c0d8a9b1e42";
    public static readonly byte[] Encoded = [0xA4, 0x01, 0x6C, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65];
    public static readonly byte[] ClientDataHash = SHA256.HashData("client data"u8.ToArray());
    public static readonly byte[] CredentialId = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
    public static readonly byte[] UserId = "user-1"u8.ToArray();
    public const string RpId = "example.test";

    public FakeWebAuthnApi Api { get; }
    public FakeConnector Pipe { get; }
    public FakeLauncher Launcher { get; } = new();
    public FakeForeground Foreground { get; } = new();
    public IdleTracker Idle { get; } = new();
    public PluginAuthenticator Provider { get; }

    public static ProviderTimings ShortTimings { get; } = new(
        Total: TimeSpan.FromMilliseconds(2000), Operation: TimeSpan.FromMilliseconds(1500),
        ConnectWindow: TimeSpan.FromMilliseconds(300), LockStatus: TimeSpan.FromMilliseconds(400),
        RetryInterval: TimeSpan.FromMilliseconds(20), Cancel: TimeSpan.FromMilliseconds(300));

    /// <summary>Long enough that only a cancel ends the call.</summary>
    public static ProviderTimings LongTimings { get; } = ShortTimings with
    {
        Total = TimeSpan.FromSeconds(25), Operation = TimeSpan.FromSeconds(20),
    };

    public RecordingLog Log { get; } = new();

    public ProviderHarness(FakeConnector pipe, ProviderTimings? timings = null, IProviderLog? log = null,
                           ECCurve? curve = null)
    {
        Api = new FakeWebAuthnApi(curve);
        Pipe = pipe;
        Provider = new PluginAuthenticator(TestClsid, Api, Pipe, Launcher, new FakeCallerHints(), Foreground, Idle,
                                           timings ?? ShortTimings, log ?? Log);
        Api.MakeCredential = MakeInput();
        Api.GetAssertion = GetInput();
    }

    public static MakeCredentialInput MakeInput(int uv = 1, int rk = 1, IReadOnlyList<byte[]>? exclude = null) =>
        new(Encoding.UTF8.GetBytes(RpId), ClientDataHash, "Example", UserId, "ada", "Ada", [-7, -257],
            exclude ?? [], 1, uv, rk);

    public static GetAssertionInput GetInput(int uv = 1, IReadOnlyList<byte[]>? allow = null) =>
        new(Encoding.UTF8.GetBytes(RpId), ClientDataHash, allow ?? [], 1, uv);

    public const byte FlagsUpUvBeBs = 0x01 | 0x04 | 0x08 | 0x10;

    public static byte[] AuthData(bool attested, string rpId = RpId, byte[]? aaguid = null, byte[]? credentialId = null,
                                  byte flags = FlagsUpUvBeBs)
    {
        var data = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));
        data.Add((byte)(flags | (attested ? 0x40 : 0)));
        data.AddRange(new byte[4]);
        if (attested)
        {
            var id = credentialId ?? CredentialId;
            data.AddRange(aaguid ?? ProviderIds.AaguidBytes());
            data.Add((byte)(id.Length >> 8));
            data.Add((byte)id.Length);
            data.AddRange(id);
            data.AddRange(new byte[] { 0xA5, 0x01, 0x02 });  // stands in for the COSE key
        }
        return [.. data];
    }

    public static JsonObject CreateReply(byte[]? authData = null) => new()
    {
        ["ok"] = true, ["credential_id"] = CtapMapping.B64(CredentialId),
        ["authenticator_data"] = CtapMapping.B64(authData ?? AuthData(attested: true)),
        ["attestation_object"] = "o2NmbXRkbm9uZQ", ["attestation_format"] = "none", ["public_key_algorithm"] = -7,
    };

    public static JsonObject GetReply(byte[]? credentialId = null) => new()
    {
        ["ok"] = true, ["credential_id"] = CtapMapping.B64(credentialId ?? CredentialId),
        ["authenticator_data"] = CtapMapping.B64(AuthData(attested: false)), ["signature"] = "BAUG",
        ["user_handle"] = CtapMapping.B64(UserId), ["user_name"] = "ada", ["user_display_name"] = "Ada",
    };

    public byte[] GoodSignature() => Api.Sign(Encoded);

    public unsafe (int Hr, byte[]? Response) Call(bool create, byte[]? signature, Guid? txn = null,
                                                   int requestType = WebAuthnPluginRequestType.Ctap2Cbor)
    {
        signature ??= GoodSignature();
        fixed (byte* sig = signature)
        fixed (byte* enc = Encoded)
        {
            var request = new WebAuthnPluginOperationRequest
            {
                hWnd = 0x1234, transactionId = txn ?? Txn, cbRequestSignature = (uint)signature.Length,
                pbRequestSignature = signature.Length == 0 ? null : sig, requestType = requestType,
                cbEncodedRequest = (uint)Encoded.Length, pbEncodedRequest = enc,
            };
            var response = new WebAuthnPluginOperationResponse();
            IPluginAuthenticator com = Provider;
            var hr = create ? com.MakeCredential(&request, &response) : com.GetAssertion(&request, &response);
            byte[]? bytes = null;
            if (response.pbEncodedResponse is not null)
            {
                bytes = new ReadOnlySpan<byte>(response.pbEncodedResponse, (int)response.cbEncodedResponse).ToArray();
                Marshal.FreeCoTaskMem((nint)response.pbEncodedResponse);
            }
            return (hr, bytes);
        }
    }

    public unsafe int Cancel(byte[] signature, Guid? txn = null)
    {
        fixed (byte* sig = signature)
        {
            var request = new WebAuthnPluginCancelOperationRequest
            {
                transactionId = txn ?? Txn, cbRequestSignature = (uint)signature.Length,
                pbRequestSignature = signature.Length == 0 ? null : sig,
            };
            IPluginAuthenticator com = Provider;
            return com.CancelOperation(&request);
        }
    }

    public unsafe (int Hr, int Status) LockStatus()
    {
        var status = -1;
        IPluginAuthenticator com = Provider;
        var hr = com.GetLockStatus(&status);
        return (hr, status);
    }

    public void Dispose() => Api.Dispose();
}

internal sealed class RecordingLog : IProviderLog
{
    public System.Collections.Concurrent.ConcurrentQueue<OperationRecord> Records { get; } = new();
    public void Write(OperationRecord record) => Records.Enqueue(record);
    public OperationRecord Last => Records.Last();
}
