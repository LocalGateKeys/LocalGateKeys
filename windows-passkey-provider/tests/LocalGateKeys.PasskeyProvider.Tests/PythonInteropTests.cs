using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>
/// Driven by tests/test_passkey_provider_interop.py: the app's own code writes agent-state.json (DPAPI-protected
/// token) into a temp folder and runs this test with the paths in the environment. Without them it does nothing.
/// </summary>
public class PythonInteropTests
{
    [Fact]
    public void ReadsTheStateFileThePythonAgentWrote()
    {
        var statePath = Environment.GetEnvironmentVariable("LGK_INTEROP_AGENT_STATE");
        var expectedPath = Environment.GetEnvironmentVariable("LGK_INTEROP_EXPECTED");
        if (string.IsNullOrEmpty(statePath) || string.IsNullOrEmpty(expectedPath))
            return;  // only meaningful when the pytest side prepared the files
        var expected = File.ReadAllLines(expectedPath);  // token, pid, pipe
        var state = AgentState.Load(statePath, AgentState.CurrentUserSid());
        Assert.Equal(expected[0], state.Token);
        Assert.Equal(int.Parse(expected[1]), state.Pid);
        Assert.Equal(expected[2], state.PipeName);
    }
}
