namespace LocalGateKeys.PasskeyProvider.Protocol;

/// <summary>
/// How far one pipe call got, for the diagnostics log: <c>state</c> (reading agent-state.json), <c>connect</c>,
/// <c>server_pin</c>, <c>send</c>, <c>awaiting_reply</c>. Flows with the async context of the call that set
/// <see cref="Current"/>; a fixed word only.
/// </summary>
public sealed class PipeProgress
{
    private static readonly AsyncLocal<PipeProgress?> Ambient = new();

    public string Stage { get; private set; } = "start";

    public static PipeProgress? Current
    {
        get => Ambient.Value;
        set => Ambient.Value = value;
    }

    public static void Mark(string stage)
    {
        if (Ambient.Value is { } progress)
            progress.Stage = stage;
    }
}
