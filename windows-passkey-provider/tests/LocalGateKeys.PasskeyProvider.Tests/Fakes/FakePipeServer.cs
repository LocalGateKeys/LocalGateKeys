using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Tests.Fakes;

/// <summary>
/// A real named pipe in this test process, named like the agent's (<c>LocalGateKeys-</c> + 32 hex), serving one
/// connection: it records every byte the client wrote and answers one framed request with <see cref="Reply"/>
/// (null: never answers, holds the connection until the client goes).
/// </summary>
internal sealed class FakePipeServer : IAsyncDisposable
{
    private readonly NamedPipeServerStream _server;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _serving;
    private readonly MemoryStream _received = new();

    public string PipeName { get; }
    public Func<JsonObject, JsonObject?> Reply { get; init; } = _ => new JsonObject { ["ok"] = true };
    public JsonObject? Request { get; private set; }
    public bool Connected { get; private set; }

    public FakePipeServer(Func<JsonObject, JsonObject?>? reply = null)
    {
        if (reply is not null)
            Reply = reply;
        var name = "LocalGateKeys-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        PipeName = @"\\.\pipe\" + name;
        _server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                                            PipeOptions.Asynchronous);
        _serving = Task.Run(ServeAsync);
    }

    /// <summary>Everything the client wrote (after it disconnected or the server stopped).</summary>
    public async Task<byte[]> ReceivedAsync()
    {
        await Task.WhenAny(_serving, Task.Delay(TimeSpan.FromSeconds(5)));
        lock (_received)
            return _received.ToArray();
    }

    private async Task ServeAsync()
    {
        try
        {
            await _server.WaitForConnectionAsync(_stop.Token);
            Connected = true;
            var recorder = new RecordingStream(_server, _received);
            JsonObject request;
            try
            {
                request = await PipeFraming.ReadFrameAsync(recorder, _stop.Token);
            }
            catch (PipeProtocolException)
            {
                return;  // the client went away without a whole frame
            }
            Request = request;
            var reply = Reply(request);
            if (reply is null)
            {
                await Task.Delay(Timeout.Infinite, _stop.Token);
                return;
            }
            var frame = PipeFraming.Encode(reply);
            await _server.WriteAsync(frame, _stop.Token);
            await _server.FlushAsync(_stop.Token);
            _server.WaitForPipeDrain();
        }
        catch (OperationCanceledException)
        {
            // The test stopped the server; nothing left to serve.
        }
        catch (IOException)
        {
            // The client closed the pipe before the reply; the test checks the outcome.
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await _serving;
        }
        catch (OperationCanceledException)
        {
            // Expected: DisposeAsync cancelled the serving loop.
        }
        await _server.DisposeAsync();
        _stop.Dispose();
    }

    /// <summary>Reads through to the pipe and keeps a copy of every byte read.</summary>
    private sealed class RecordingStream(Stream inner, MemoryStream copy) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            var n = await inner.ReadAsync(buffer, ct);
            lock (copy)
                copy.Write(buffer.Span[..n]);
            return n;
        }
    }
}

internal sealed class FakeImageCheck(bool trusted) : IServerImageCheck
{
    public List<int> Asked { get; } = [];

    public bool IsTrustedServer(int pid)
    {
        Asked.Add(pid);
        return trusted;
    }
}
