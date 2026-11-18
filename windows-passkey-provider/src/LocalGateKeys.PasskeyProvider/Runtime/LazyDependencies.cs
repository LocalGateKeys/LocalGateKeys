using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Runtime;

/// <summary>
/// Builds the real pipe client on first use (its server pin reads the provider's Authenticode signer), so the COM
/// server can register its class object first. A build failure surfaces as the call's own failure.
/// </summary>
public sealed class LazyPipeConnector(Func<IPipeConnector> create) : IPipeConnector
{
    private readonly Lazy<IPipeConnector> _inner = new(create, LazyThreadSafetyMode.ExecutionAndPublication);

    public bool Created => _inner.IsValueCreated;

    public Task<JsonObject> SendAsync(JsonObject request, CancellationToken ct) => _inner.Value.SendAsync(request, ct);
}

/// <summary>The app launcher, built on first use for the same reason.</summary>
public sealed class LazyLauncher(Func<IProcessLauncher> create) : IProcessLauncher
{
    private readonly Lazy<IProcessLauncher> _inner = new(create, LazyThreadSafetyMode.ExecutionAndPublication);

    public bool Created => _inner.IsValueCreated;

    public bool StartAgentOnce() => _inner.Value.StartAgentOnce();
}
