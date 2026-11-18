using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class PipeFramingTests
{
    private static async Task<JsonObject> ReadAsync(byte[] frame) =>
        await PipeFraming.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None);

    private static byte[] Frame(byte[] payload)
    {
        var frame = new byte[payload.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)payload.Length);
        payload.CopyTo(frame, 4);
        return frame;
    }

    [Fact]
    public async Task RoundTrip()
    {
        var value = new JsonObject { ["action"] = "passkey_get_system", ["n"] = 7, ["name"] = "Ünïcode ✓" };
        var frame = PipeFraming.Encode(value);
        Assert.Equal((uint)(frame.Length - 4), BinaryPrimitives.ReadUInt32BigEndian(frame));
        var back = await ReadAsync(frame);
        Assert.True(JsonNode.DeepEquals(value, back));
    }

    [Fact]
    public void EncodesLikeThePythonAgent()
    {
        // pipe_transport._encode({"ok": True}) == b"\x00\x00\x00\x0b" + b'{"ok":true}'
        var frame = PipeFraming.Encode(new JsonObject { ["ok"] = true });
        Assert.Equal(Convert.FromHexString("0000000B").Concat(Encoding.ASCII.GetBytes("{\"ok\":true}")).ToArray(), frame);
    }

    [Fact]
    public async Task ExactlyOneMebibyteIsAccepted()
    {
        var filler = new string('x', PipeFraming.MaxPayload - "{\"a\":\"\"}".Length);
        var value = new JsonObject { ["a"] = filler };
        var frame = PipeFraming.Encode(value);
        Assert.Equal(PipeFraming.MaxPayload + 4, frame.Length);
        Assert.Equal(filler, (await ReadAsync(frame))["a"]!.GetValue<string>());
    }

    [Fact]
    public void EncodeRejectsOneMebibytePlusOne()
    {
        var value = new JsonObject { ["a"] = new string('x', PipeFraming.MaxPayload - "{\"a\":\"\"}".Length + 1) };
        Assert.Throws<PipeProtocolException>(() => PipeFraming.Encode(value));
    }

    [Fact]
    public async Task ReadRejectsLengthOverOneMebibyteBeforeReadingThePayload()
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, PipeFraming.MaxPayload + 1);
        // No payload follows: the length alone must be refused.
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync(header));
    }

    [Theory]
    [InlineData("[1,2]")]
    [InlineData("\"text\"")]
    [InlineData("{\"a\":1")]
    [InlineData("{\"a\":1,\"a\":2}")]
    [InlineData("")]
    public async Task ReadRejectsAnythingButOneJsonObject(string payload)
    {
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync(Frame(Encoding.UTF8.GetBytes(payload))));
    }

    [Fact]
    public async Task ReadRejectsInvalidUtf8()
    {
        var payload = Encoding.ASCII.GetBytes("{\"a\":\"\u0001\"}");
        payload[6] = 0xFF;
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync(Frame(payload)));
    }

    [Fact]
    public async Task ReadRejectsTruncatedFrames()
    {
        var frame = PipeFraming.Encode(new JsonObject { ["ok"] = true });
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync(frame[..^1]));
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync(frame[..2]));
        await Assert.ThrowsAsync<PipeProtocolException>(() => ReadAsync([]));
    }
}
