using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>
/// The agent pipe's frame: a 4-byte big-endian length, then one UTF-8 JSON object of at most 1 MiB
/// (<c>_encode</c>/<c>_decode</c> in <c>src/localvault/pipe_transport.py</c>).
/// </summary>
public static class PipeFraming
{
    public const int MaxPayload = 1024 * 1024;  // protocol.MAX_LOCAL_MESSAGE

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false,
                                                          throwOnInvalidBytes: true);

    private static readonly JsonDocumentOptions ParseOptions = new()
    {
        MaxDepth = 64,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowDuplicateProperties = false,
    };

    /// <summary>One frame for <paramref name="value"/>; <see cref="PipeProtocolException"/> over 1 MiB.</summary>
    public static byte[] Encode(JsonObject value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var buffer = new MemoryStream();
        buffer.Write(stackalloc byte[4]);
        using (var writer = new Utf8JsonWriter(buffer))
            value.WriteTo(writer);
        var length = buffer.Length - 4;
        if (length > MaxPayload)
        {
            CryptoClear(buffer);
            throw new PipeProtocolException("message too large");
        }
        var frame = buffer.ToArray();
        CryptoClear(buffer);
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)length);
        return frame;
    }

    /// <summary>Reads exactly one frame; anything malformed, truncated or oversized is a <see cref="PipeProtocolException"/>.</summary>
    public static async Task<JsonObject> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await ReadExactAsync(stream, header, ct).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length > MaxPayload)
            throw new PipeProtocolException("message too large");
        var payload = new byte[length];
        await ReadExactAsync(stream, payload, ct).ConfigureAwait(false);
        return Decode(payload);
    }

    internal static JsonObject Decode(byte[] payload)
    {
        try
        {
            var text = StrictUtf8.GetString(payload);
            return JsonNode.Parse(text, documentOptions: ParseOptions) as JsonObject
                   ?? throw new PipeProtocolException("message is not a JSON object");
        }
        catch (DecoderFallbackException)
        {
            throw new PipeProtocolException("message is not UTF-8");
        }
        catch (JsonException)
        {
            throw new PipeProtocolException("message is not JSON");
        }
        catch (ArgumentException)
        {
            throw new PipeProtocolException("message is not JSON");
        }
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            throw new PipeProtocolException("truncated message");
        }
    }

    private static void CryptoClear(MemoryStream buffer)
    {
        // The request frame holds the agent token: do not leave it in a growable buffer.
        if (buffer.TryGetBuffer(out var segment))
            segment.AsSpan().Clear();
    }
}
