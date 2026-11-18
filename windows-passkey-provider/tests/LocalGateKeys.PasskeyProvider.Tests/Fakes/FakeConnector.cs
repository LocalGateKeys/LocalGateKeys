using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests.Fakes;

/// <summary>An IPipeConnector whose answer per request is scripted; records every request (a deep copy).</summary>
internal sealed class FakeConnector : IPipeConnector
{
    private readonly Func<JsonObject, CancellationToken, Task<JsonObject>> _answer;
    public ConcurrentQueue<JsonObject> Sent { get; } = new();

    public FakeConnector(Func<JsonObject, CancellationToken, Task<JsonObject>> answer) => _answer = answer;

    public static FakeConnector Replying(JsonObject reply) =>
        new((_, _) => Task.FromResult(reply.DeepClone().AsObject()));

    /// <summary>Ceremonies never answer (until cancelled, or never with ignoreToken); a cancel answers ok.</summary>
    public static FakeConnector Silent(bool ignoreToken = false) => new(async (request, ct) =>
    {
        if ((string?)request["action"] == "passkey_cancel_system")
            return new JsonObject { ["ok"] = true };
        if (ignoreToken)
            await new TaskCompletionSource().Task;
        await Task.Delay(Timeout.Infinite, ct);
        throw new InvalidOperationException("unreachable");
    });

    public Task<JsonObject> SendAsync(JsonObject request, CancellationToken ct)
    {
        Sent.Enqueue(request.DeepClone().AsObject());
        return _answer(request, ct);
    }

    public JsonObject[] Of(string action) => Sent.Where(r => (string?)r["action"] == action).ToArray();
}

internal sealed class FakeLauncher : IProcessLauncher
{
    public int Calls;
    public Action? OnStart;

    public bool StartAgentOnce()
    {
        Interlocked.Increment(ref Calls);
        OnStart?.Invoke();
        return true;
    }
}
