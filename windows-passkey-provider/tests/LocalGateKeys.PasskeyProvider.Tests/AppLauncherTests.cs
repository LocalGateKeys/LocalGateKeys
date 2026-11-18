using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests;

public sealed class AppLauncherTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("lgk-launcher-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Agent()
    {
        var path = Path.Join(_dir, "LocalGateKeys.exe");
        File.WriteAllBytes(path, [0x4D, 0x5A]);
        return path;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("\0bad")]
    public void WithoutAUsableOwnPathTheLauncherNeverStartsAndNeverThrows(string? self)
    {
        var launcher = AppLauncher.Create(self);
        Assert.False(launcher.StartAgentOnce());
        Assert.False(launcher.StartAgentOnce());
        _ = AppLauncher.Shared;  // the real one is built without throwing
    }

    [Fact]
    public void AgentIsLocalGateKeysExeInTheParentFolder()
    {
        Assert.Equal(@"C:\Program Files\LocalGateKeys\LocalGateKeys.exe",
                     AppLauncher.AgentPathFor(@"C:\Program Files\LocalGateKeys\PasskeyProvider\LocalGateKeysPasskeyProvider.exe"));
    }

    [Fact]
    public void StartsInTheBackground()
    {
        var info = AppLauncher.StartInfoFor(@"C:\Apps\LocalGateKeys\LocalGateKeys.exe");
        Assert.Equal(@"C:\Apps\LocalGateKeys\LocalGateKeys.exe", info.FileName);
        Assert.Equal(["--background"], info.ArgumentList);
        Assert.Equal(string.Empty, info.Arguments);
        Assert.False(info.UseShellExecute);
        Assert.Equal(@"C:\Apps\LocalGateKeys", info.WorkingDirectory);
    }

    [Fact]
    public void StartsAtMostOnce()
    {
        var starts = new List<string>();
        var launcher = new AppLauncher(Agent(), path => { starts.Add(path); return true; }, _ => true);
        Assert.True(launcher.StartAgentOnce());
        Assert.False(launcher.StartAgentOnce());
        Assert.False(launcher.StartAgentOnce());
        Assert.Single(starts);
    }

    [Fact]
    public void ConcurrentCallersStartOnce()
    {
        var starts = 0;
        var launcher = new AppLauncher(Agent(), _ => { Interlocked.Increment(ref starts); return true; }, _ => true);
        Parallel.For(0, 32, _ => launcher.StartAgentOnce());
        Assert.Equal(1, starts);
    }

    [Fact]
    public void MissingAgentIsNotStarted()
    {
        var starts = 0;
        var launcher = new AppLauncher(Path.Join(_dir, "LocalGateKeys.exe"), _ => { starts++; return true; }, _ => true);
        Assert.False(launcher.StartAgentOnce());
        Assert.Equal(0, starts);
    }

    [Fact]
    public void UntrustedAgentIsNotStarted()
    {
        var starts = 0;
        var launcher = new AppLauncher(Agent(), _ => { starts++; return true; }, _ => false);
        Assert.False(launcher.StartAgentOnce());
        Assert.Equal(0, starts);
    }

    [Fact]
    public void StartFailureIsFalseAndNotRetried()
    {
        var starts = 0;
        var launcher = new AppLauncher(Agent(), _ => { starts++; throw new InvalidOperationException("no"); }, _ => true);
        Assert.False(launcher.StartAgentOnce());
        Assert.False(launcher.StartAgentOnce());
        Assert.Equal(1, starts);
    }
}
