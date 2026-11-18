using LocalGateKeys.PasskeyProvider.Protocol;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class ServerImageCheckTests
{
    private static readonly string Self = Environment.ProcessPath!;

    [Fact]
    public void ExpectedServerIsLocalGateKeysExeInTheParentFolder()
    {
        Assert.Equal(@"C:\Program Files\LocalGateKeys\LocalGateKeys.exe",
                     ServerImageCheck.ExpectedServerPathFor(
                         @"C:\Program Files\LocalGateKeys\PasskeyProvider\LocalGateKeysPasskeyProvider.exe"));
    }

    [Fact]
    public void AcceptsTheExpectedImageWithTheSameSigner()
    {
        // This test host is both "server" and "self": same path, same signer (or both unsigned).
        Assert.True(new ServerImageCheck(Self, Self).IsTrustedServer(Environment.ProcessId));
        Assert.True(new ServerImageCheck(Self.ToUpperInvariant(), Self).IsTrustedServer(Environment.ProcessId));
    }

    [Fact]
    public void RejectsAnotherImage()
    {
        var other = Path.Combine(Path.GetDirectoryName(Self)!, "LocalGateKeys.exe");
        Assert.False(new ServerImageCheck(other, Self).IsTrustedServer(Environment.ProcessId));
    }

    private sealed class FakeFamilies(string? own, Func<string?> peer) : IPackageFamilyReader
    {
        public int PeerReads { get; private set; }

        public string? Current() => own;

        public string? OfProcess(Microsoft.Win32.SafeHandles.SafeProcessHandle process)
        {
            Assert.False(process.IsInvalid);  // read from the same opened handle that pins the pid
            PeerReads++;
            return peer();
        }
    }

    [Fact]
    public void PackagedProviderAcceptsAServerWithTheSamePackageFamily()
    {
        var families = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => "IliasPel.LocalGateKeys_abc");
        Assert.True(new ServerImageCheck(Self, Self, families).IsTrustedServer(Environment.ProcessId));
        Assert.Equal(1, families.PeerReads);
    }

    [Theory]
    [InlineData(null)]                              // started by path: no package identity
    [InlineData("Other.Package_abc")]
    [InlineData("ILIASPEL.LOCALGATEKEYS_ABC")]
    [InlineData("")]
    public void PackagedProviderRejectsAnotherOrMissingPackageFamily(string? peer)
    {
        var families = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => peer);
        Assert.False(new ServerImageCheck(Self, Self, families).IsTrustedServer(Environment.ProcessId));
    }

    [Fact]
    public void RefusalNamesTheFailedSubCheck()
    {
        var other = Path.Combine(Path.GetDirectoryName(Self)!, "LocalGateKeys.exe");
        Assert.Equal("path", new ServerImageCheck(other, Self).Refusal(Environment.ProcessId));
        Assert.Equal("pid", new ServerImageCheck(Self, Self).Refusal(0));
        var wrongFamily = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => "Other.Package_abc");
        Assert.Equal("package_family", new ServerImageCheck(Self, Self, wrongFamily).Refusal(Environment.ProcessId));
        var broken = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => throw new InvalidOperationException());
        Assert.Equal("package_family", new ServerImageCheck(Self, Self, broken).Refusal(Environment.ProcessId));
        Assert.Null(new ServerImageCheck(Self, Self).Refusal(Environment.ProcessId));
    }

    [Fact]
    public void PackageFamilyReadErrorsFailClosed()
    {
        var families = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => throw new InvalidOperationException());
        Assert.False(new ServerImageCheck(Self, Self, families).IsTrustedServer(Environment.ProcessId));
    }

    [Fact]
    public void UnpackagedProviderDoesNotReadThePeerFamily()
    {
        var families = new FakeFamilies(null, () => throw new InvalidOperationException());
        Assert.True(new ServerImageCheck(Self, Self, families).IsTrustedServer(Environment.ProcessId));
        Assert.Equal(0, families.PeerReads);
    }

    [Fact]
    public void RealReaderAnswersForThisUnpackagedTestHost()
    {
        Assert.Null(PackageFamilyReader.Instance.Current());
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        Assert.Null(PackageFamilyReader.Instance.OfProcess(process.SafeHandle));
    }

    [Fact]
    public unsafe void OnlyNoPackageMeansUnpackaged()
    {
        // APPMODEL_ERROR_NO_PACKAGE: truly unpackaged, the only null answer.
        var none = new PackageFamilyReader((ref uint length, char* buffer) => 15700);
        Assert.Null(none.Current());
        Assert.True(new ServerImageCheck(Self, Self, none).IsTrustedServer(Environment.ProcessId));
        // Any other error (first or second call): Current throws and the server is refused (fail closed).
        var calls = 0;
        PackageFamilyReader.CurrentFamilyCall secondFails = (ref uint length, char* buffer) =>
        {
            length = 8;
            return ++calls == 1 ? 122 : 87;
        };
        foreach (var reader in new[]
                 {
                     new PackageFamilyReader((ref uint length, char* buffer) => 87),
                     new PackageFamilyReader((ref uint length, char* buffer) => 122),  // length stays 0
                     new PackageFamilyReader(secondFails),
                 })
        {
            Assert.Throws<InvalidOperationException>(() => reader.Current());
            calls = 0;
            Assert.False(new ServerImageCheck(Self, Self, reader).IsTrustedServer(Environment.ProcessId));
            calls = 0;
        }
        // Packaged: the name is read on the second call.
        var name = "IliasPel.LocalGateKeys_abc";
        var packaged = new PackageFamilyReader((ref uint length, char* buffer) =>
        {
            if (buffer == null)
            {
                length = (uint)name.Length + 1;
                return 122;
            }
            for (var i = 0; i < name.Length; i++)
                buffer[i] = name[i];
            buffer[name.Length] = '\0';
            return 0;
        });
        Assert.Equal(name, packaged.Current());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void RejectsBadPids(int pid)
    {
        Assert.False(new ServerImageCheck(Self, Self).IsTrustedServer(pid));
    }

    [Fact]
    public void SignedSelfRejectsAnUnsignedServer()
    {
        // A signed provider never accepts an unsigned agent: the signer of the expected image must match.
        foreach (var packaged in new[] { false, true })
        {
            Assert.False(Authenticode.SameSigner("AA11", null, packaged));
            Assert.False(Authenticode.SameSigner("AA11", "BB22", packaged));
            Assert.True(Authenticode.SameSigner("AA11", "AA11", packaged));
        }
    }

    [Fact]
    public void UnreadableOwnSignerFailsClosedUnlessPackagedOrDebug()
    {
        // Packaged: the package family pin stands in for the signer (Store exes carry no embedded signature).
        Assert.True(Authenticode.SameSigner(null, null, packaged: true));
        Assert.True(Authenticode.SameSigner(null, "AA11", packaged: true));
#if DEBUG
        Assert.True(Authenticode.SameSigner(null, null, packaged: false));
        Assert.True(Authenticode.SameSigner(null, "AA11", packaged: false));
#else
        Assert.False(Authenticode.UnsignedUnpackagedSelfAllowed);
        Assert.False(Authenticode.SameSigner(null, null, packaged: false));
        Assert.False(Authenticode.SameSigner(null, "AA11", packaged: false));
#endif
    }

    [Fact]
    public void UnsignedUnpackagedProviderRefusesTheServerInARelease()
    {
        // The expected server is this (signed) test host; the provider's own image is an unsigned file.
        var unsignedSelf = Path.Combine(Path.GetTempPath(), "lgk-unsigned-self-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(unsignedSelf, [0x4D, 0x5A, 0, 0]);
        try
        {
            var unpackaged = new ServerImageCheck(Self, unsignedSelf, new FakeFamilies(null, () => null));
#if DEBUG
            Assert.Null(unpackaged.Refusal(Environment.ProcessId));
#else
            Assert.Equal("signer", unpackaged.Refusal(Environment.ProcessId));
#endif
            var samePackage = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => "IliasPel.LocalGateKeys_abc");
            Assert.Null(new ServerImageCheck(Self, unsignedSelf, samePackage).Refusal(Environment.ProcessId));
            var otherPackage = new FakeFamilies("IliasPel.LocalGateKeys_abc", () => "Other.Package_abc");
            Assert.Equal("package_family",
                         new ServerImageCheck(Self, unsignedSelf, otherPackage).Refusal(Environment.ProcessId));
        }
        finally
        {
            File.Delete(unsignedSelf);
        }
    }

    [Fact]
    public void ReadsTheSignerOfASignedFile()
    {
        // The runtime's core library carries an embedded Microsoft Authenticode signature.
        var thumbprint = Authenticode.SignerThumbprint(typeof(object).Assembly.Location);
        Assert.NotNull(thumbprint);
        Assert.Equal(64, thumbprint!.Length);  // SHA-256 of the signer certificate, hex
    }

    [Fact]
    public void UnsignedFileHasNoSigner()
    {
        var path = Path.Combine(Path.GetTempPath(), "lgk-unsigned-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, [0x4D, 0x5A, 0, 0]);
        try
        {
            Assert.Null(Authenticode.SignerThumbprint(path));
        }
        finally
        {
            File.Delete(path);
        }
        Assert.Null(Authenticode.SignerThumbprint(path));  // missing
    }
}
