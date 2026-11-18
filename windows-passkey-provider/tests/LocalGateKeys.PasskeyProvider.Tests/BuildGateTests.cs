using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class BuildGateTests
{
    [Theory]
    [InlineData(26100, 6724, false)]
    [InlineData(26100, 6725, true)]
    [InlineData(26200, 6724, false)]
    [InlineData(26200, 6725, true)]
    [InlineData(26300, 1, true)]
    [InlineData(27000, 0, true)]
    [InlineData(22631, 9999, false)]
    [InlineData(22000, 100000, false)]
    [InlineData(0, 0, false)]
    [InlineData(-1, 7000, false)]
    public void Rule(int build, int ubr, bool supported)
    {
        Assert.Equal(supported, BuildGate.IsSupported(build, ubr));
    }

    [Fact]
    public void ReadsThisPc()
    {
        // Only that it answers; the value depends on the machine.
        _ = BuildGate.IsCurrentSystemSupported();
    }
}
