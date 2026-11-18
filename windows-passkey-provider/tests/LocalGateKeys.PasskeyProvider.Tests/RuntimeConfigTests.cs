using System.Text.Json;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>
/// The provider's runtimeconfig (copied next to the tests from the referenced project, the same file publish
/// emits) keeps the runtime injection knobs off; build_msix_package.ps1 checks the packaged copy again.
/// </summary>
public class RuntimeConfigTests
{
    [Theory]
    [InlineData("System.StartupHookProvider.IsSupported")]
    [InlineData("System.Runtime.InteropServices.BuiltInComInterop.IsSupported")]
    public void ProviderRuntimeConfigTurnsTheSwitchOff(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "LocalGateKeysPasskeyProvider.runtimeconfig.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var properties = document.RootElement.GetProperty("runtimeOptions").GetProperty("configProperties");
        Assert.True(properties.TryGetProperty(name, out var value), name + " missing from " + path);
        Assert.Equal(JsonValueKind.False, value.ValueKind);
    }
}
