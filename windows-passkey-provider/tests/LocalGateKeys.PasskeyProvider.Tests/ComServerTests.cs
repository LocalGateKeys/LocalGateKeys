using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using LocalGateKeys.PasskeyProvider.Com;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public unsafe class ComServerTests
{
    [Fact]
    public void IdleAfterTheTimeWithNothingRunning()
    {
        var now = TimeSpan.Zero;
        var idle = new IdleTracker(() => now);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        now = TimeSpan.FromSeconds(59);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        now = TimeSpan.FromSeconds(60);
        Assert.True(idle.IsIdle(IdleTracker.DefaultIdle));
    }

    [Fact]
    public void NeverIdleWhileACallRuns()
    {
        var now = TimeSpan.Zero;
        var idle = new IdleTracker(() => now);
        var call = idle.Begin();
        now = TimeSpan.FromMinutes(10);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        call.Dispose();
        call.Dispose();  // twice is harmless
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        now += TimeSpan.FromSeconds(60);
        Assert.True(idle.IsIdle(IdleTracker.DefaultIdle));
    }

    [Fact]
    public void IdleExitIsSixtySeconds() => Assert.Equal(TimeSpan.FromSeconds(60), IdleTracker.DefaultIdle);

    [Fact]
    public void LockServerAndOutsideReferencesKeepTheServer()
    {
        var now = TimeSpan.Zero;
        var idle = new IdleTracker(() => now);
        idle.LockServer(true);
        now = TimeSpan.FromMinutes(5);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        Assert.False(idle.IsQuiet(0));
        idle.LockServer(false);
        idle.LockServer(false);  // never below zero
        now += TimeSpan.FromSeconds(60);
        Assert.True(idle.IsIdle(IdleTracker.DefaultIdle));
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle, outsideReferences: 1));
        Assert.False(idle.IsQuiet(1));
        Assert.True(idle.IsQuiet(0));
        idle.LockServer(true);
        idle.LockServer(false);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));  // a lock change counts as activity
    }

    [Fact]
    public void ALockFromADeadClientExpiresAfterTenMinutes()
    {
        var now = TimeSpan.Zero;
        var idle = new IdleTracker(() => now);
        idle.LockServer(true);  // never released
        now = TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1);
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle));
        Assert.False(idle.IsQuiet(0));
        now = TimeSpan.FromMinutes(10);
        Assert.True(idle.IsIdle(IdleTracker.DefaultIdle));
        Assert.True(idle.IsQuiet(0));
        Assert.False(idle.IsIdle(IdleTracker.DefaultIdle, outsideReferences: 1));
        using (idle.Begin())
            Assert.False(idle.IsQuiet(0));  // a running call still keeps it
        Assert.Equal(TimeSpan.FromMinutes(10), IdleTracker.MaxLockedIdle);
    }

    [Fact]
    public void OutsideReferencesCountWhatCallersHold()
    {
        var (_, harness) = Factory();
        using var disposeHarness = harness;
        var wrappers = new StrategyBasedComWrappers();
        var own = wrappers.GetOrCreateComInterfaceForObject(harness.Provider, CreateComInterfaceFlags.None);
        try
        {
            Assert.Equal(0, ComServerHost.OutsideReferences(own));
            var held = wrappers.GetOrCreateComInterfaceForObject(harness.Provider, CreateComInterfaceFlags.None);
            Assert.Equal(1, ComServerHost.OutsideReferences(own));
            Marshal.Release(held);
            Assert.Equal(0, ComServerHost.OutsideReferences(own));
        }
        finally
        {
            Marshal.Release(own);
        }
    }

    private sealed class RecordingRegistrar(Func<string> atRegister) : ComServerHost.IClassRegistrar
    {
        public List<string> Events { get; } = [];

        public int Register(Guid clsid, nint unknown, out uint cookie)
        {
            Events.Add("register:" + atRegister());
            cookie = 7;
            return HResults.SOk;
        }

        public void Revoke(uint cookie) => Events.Add("revoke:" + cookie);
    }

    [Fact]
    public void ClassObjectIsRegisteredBeforeAnythingSlow()
    {
        // The pipe client and launcher read Authenticode signers when built; they must not be built before the
        // class object is registered (DCOM 10010 on the device), and the server is idle-quiet right away here.
        using var api = new FakeWebAuthnApi();
        var pipeBuilt = false;
        var launcherBuilt = false;
        var pipe = new LazyPipeConnector(() =>
        {
            pipeBuilt = true;
            return FakeConnector.Silent();
        });
        var launcher = new LazyLauncher(() =>
        {
            launcherBuilt = true;
            return new FakeLauncher();
        });
        var idle = new IdleTracker();
        var provider = new PluginAuthenticator(ProviderHarness.TestClsid, api, pipe, launcher, new FakeCallerHints(),
                                               new FakeForeground(), idle, ProviderHarness.ShortTimings);
        var registrar = new RecordingRegistrar(() => $"pipe={pipeBuilt},launcher={launcherBuilt}");

        var code = ComServerHost.Serve(ProviderHarness.TestClsid, provider, idle, TimeSpan.Zero, registrar);

        Assert.Equal(0, code);
        Assert.Equal(["register:pipe=False,launcher=False", "revoke:7"], registrar.Events);
        Assert.False(pipe.Created);
        Assert.False(launcher.Created);
    }

    private static (ClassFactory Factory, ProviderHarness Harness) Factory()
    {
        var harness = new ProviderHarness(FakeConnector.Silent());
        return (new ClassFactory(harness.Provider, harness.Idle, new StrategyBasedComWrappers()), harness);
    }

    [Fact]
    public void FactoryHandsOutThePluginAuthenticator()
    {
        var (factory, harness) = Factory();
        using var _ = harness;
        IClassFactory com = factory;
        var iid = ClassFactory.IidIPluginAuthenticator;
        void* instance = null;
        Assert.Equal(HResults.SOk, com.CreateInstance(null, &iid, &instance));
        Assert.True(instance is not null);
        // The returned pointer answers QueryInterface for the IDL's IID.
        Assert.Equal(HResults.SOk, Marshal.QueryInterface((nint)instance, iid, out var again));
        Marshal.Release(again);
        Marshal.Release((nint)instance);

        var unknown = ClassFactory.IidIUnknown;
        Assert.Equal(HResults.SOk, com.CreateInstance(null, &unknown, &instance));
        Marshal.Release((nint)instance);
    }

    [Fact]
    public void FactoryRefusesAggregationAndOtherInterfaces()
    {
        var (factory, harness) = Factory();
        using var _ = harness;
        IClassFactory com = factory;
        var iid = ClassFactory.IidIPluginAuthenticator;
        void* instance = (void*)1;
        Assert.Equal(HResults.ClassENoAggregation, com.CreateInstance((void*)1, &iid, &instance));
        Assert.True(instance is null);
        var experimental = new Guid("e6466e9a-b2f3-47c5-b88d-89bc14a8d998");  // EXPERIMENTAL_IPluginAuthenticator
        Assert.Equal(HResults.ENoInterface, com.CreateInstance(null, &experimental, &instance));
        Assert.Equal(HResults.EInvalidArg, com.CreateInstance(null, &iid, null));
        Assert.Equal(HResults.SOk, com.LockServer(1));
    }

    [Fact]
    public void CallThroughTheComVtableReachesTheProvider()
    {
        var (factory, harness) = Factory();
        using var _ = harness;
        IClassFactory com = factory;
        var iid = ClassFactory.IidIPluginAuthenticator;
        void* instance = null;
        Assert.Equal(HResults.SOk, com.CreateInstance(null, &iid, &instance));
        try
        {
            // Slot 3 + 3 = GetLockStatus (IUnknown has 3 slots; MakeCredential, GetAssertion, CancelOperation).
            var vtable = *(void***)instance;
            var getLockStatus = (delegate* unmanaged[Stdcall]<void*, int*, int>)vtable[6];
            var status = -1;
            Assert.Equal(HResults.SOk, getLockStatus(instance, &status));
            Assert.Equal(PluginLockStatus.PluginLocked, status);  // the silent fake never answers
            var cancel = (delegate* unmanaged[Stdcall]<void*, WebAuthnPluginCancelOperationRequest*, int>)vtable[5];
            var signature = stackalloc byte[] { 1 };
            var request = new WebAuthnPluginCancelOperationRequest
            {
                transactionId = Guid.NewGuid(), cbRequestSignature = 1, pbRequestSignature = signature,
            };
            Assert.Equal(HResults.NteNotFound, cancel(instance, &request));
        }
        finally
        {
            Marshal.Release((nint)instance);
        }
    }
}

public class LazyDependencyTests
{
    [Fact]
    public async Task LazyDependenciesBuildOnFirstUse()
    {
        var built = 0;
        var pipe = new LazyPipeConnector(() =>
        {
            built++;
            return FakeConnector.Replying(new System.Text.Json.Nodes.JsonObject { ["ok"] = true });
        });
        Assert.Equal(0, built);
        _ = await pipe.SendAsync(new System.Text.Json.Nodes.JsonObject(), CancellationToken.None);
        _ = await pipe.SendAsync(new System.Text.Json.Nodes.JsonObject(), CancellationToken.None);
        Assert.Equal(1, built);
    }
}
