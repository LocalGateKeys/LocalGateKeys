using System.Globalization;
using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Commands;

public sealed record CliContext(TextWriter Out, IWebAuthnApi Api, Guid Clsid, Func<bool> BuildSupported, Func<int> ComServer,
                                Func<CancellationToken, Task<OperationResult>>? QueryCredentials = null);

/// <summary>
/// The command line. Exactly one argument:
/// <list type="bullet">
/// <item><c>-PluginActivated</c>: the COM server (how Windows starts the exe, MSIX manifest Arguments).</item>
/// <item><c>--register</c>: <c>WebAuthNPluginAddAuthenticator</c> for the current user (the owner turns it on in
/// LocalGateKeys; never run by agents or tests against the real webauthn.dll).</item>
/// <item><c>--unregister</c>: <c>WebAuthNPluginAuthenticatorRemoveAllCredentials</c>, then
/// <c>WebAuthNPluginRemoveAuthenticator</c>.</item>
/// <item><c>--state</c>: read-only; the build gate and <c>WebAuthNPluginGetAuthenticatorState</c>.</item>
/// <item><c>--sync</c>: replace Windows' metadata cache with the app's names and IDs (<see cref="MetadataSync"/>).</item>
/// <item><c>--clear-cache</c>: <c>WebAuthNPluginAuthenticatorRemoveAllCredentials</c> only (passkeys turned off in the
/// app; the registration stays).</item>
/// </list>
/// Each command prints one JSON object on stdout, never a secret. Exit 0 on success, 1 on failure, 2 on usage.
/// Only the plugin API functions of webauthn.dll are called: they act for the current user; nothing is written to
/// the registry here.
/// </summary>
public static class Cli
{
    public const string PluginActivated = "-PluginActivated";
    public const int Ok = 0;
    public const int Failed = 1;
    public const int Usage = 2;

    /// <summary>
    /// True when Windows started the exe as the COM server. COM appends <c>-Embedding</c> to the manifest's
    /// <c>Arguments</c> when it launches a local server, so the line is <c>-PluginActivated -Embedding</c>, not
    /// <c>-PluginActivated</c> alone: the Microsoft sample looks for the flag anywhere in the command line ([S4]
    /// App.xaml.cpp <c>argsString.find(L"-PluginActivated")</c>) and KeePassPasskey uses <c>args.Any</c>. Either flag
    /// starts the server, case-insensitively; everything else on such a line is ignored. (The first device tests
    /// exited with "usage" here, so DCOM logged 10010: the class was never registered.)
    /// </summary>
    public static bool IsComActivation(string[] args) =>
        args.Any(arg => string.Equals(arg, PluginActivated, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(arg, "-Embedding", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(arg, "/Embedding", StringComparison.OrdinalIgnoreCase));

    public static int Run(string[] args, CliContext context)
    {
        if (IsComActivation(args))
            return context.ComServer();
        if (args.Length != 1)
            return Print(context, Usage, new JsonObject { ["ok"] = false, ["error"] = "usage" });
        try
        {
            return args[0] switch
            {
                "--register" => Register(context),
                "--unregister" => Unregister(context),
                "--state" => State(context),
                "--sync" => Sync(context),
                "--clear-cache" => ClearCache(context),
                _ => Print(context, Usage, new JsonObject { ["ok"] = false, ["error"] = "usage" }),
            };
        }
        catch (Exception)
        {
            return Print(context, Failed, new JsonObject { ["ok"] = false, ["error"] = "internal" });
        }
    }

    private static int Register(CliContext context)
    {
        if (!context.BuildSupported())
            return Print(context, Failed, new JsonObject { ["ok"] = false, ["error"] = "unsupported_build" });
        var registration = new AuthenticatorRegistration(
            context.Clsid, ProviderIds.Name, ProviderIds.PluginRpId, GetInfo.LogoBase64(dark: false),
            GetInfo.LogoBase64(dark: true), GetInfo.ForProvider());
        var hr = context.Api.AddAuthenticator(registration);
        if (hr == HResults.SOk)
            return Print(context, Ok, new JsonObject { ["ok"] = true });
        if (hr == HResults.NteExists)
            return Print(context, Ok, new JsonObject { ["ok"] = true, ["already_registered"] = true });
        return Print(context, Failed, Failure("register_failed", hr));
    }

    private static int Unregister(CliContext context)
    {
        var credentials = context.Api.RemoveAllCredentials(context.Clsid);
        var authenticator = context.Api.RemoveAuthenticator(context.Clsid);
        if (Gone(credentials) && Gone(authenticator))
            return Print(context, Ok, new JsonObject { ["ok"] = true });
        var failure = Failure("unregister_failed", Gone(authenticator) ? credentials : authenticator);
        return Print(context, Failed, failure);

        static bool Gone(int hr) => hr is HResults.SOk or HResults.NteNotFound;
    }

    private static int Sync(CliContext context)
    {
        var result = MetadataSync.Run(context, out var ok);
        return Print(context, ok ? Ok : Failed, result);
    }

    private static int ClearCache(CliContext context)
    {
        if (!context.BuildSupported())
            return Print(context, Failed, new JsonObject { ["ok"] = false, ["error"] = "unsupported_build" });
        var hr = context.Api.RemoveAllCredentials(context.Clsid);
        return hr is HResults.SOk or HResults.NteNotFound
            ? Print(context, Ok, new JsonObject { ["ok"] = true })
            : Print(context, Failed, Failure("clear_failed", hr));
    }

    private static int State(CliContext context)
    {
        if (!context.BuildSupported())
            return Print(context, Ok, new JsonObject
            {
                ["ok"] = true, ["build_supported"] = false, ["state"] = "unsupported_build",
            });
        var hr = context.Api.GetAuthenticatorState(context.Clsid, out var state);
        string? name = hr switch
        {
            HResults.SOk when state == AuthenticatorState.Enabled => "enabled",
            HResults.SOk when state == AuthenticatorState.Disabled => "disabled",
            HResults.NteNotFound => "not_registered",  // [S12]: not registered
            HResults.ENotImpl => "unavailable",
            _ => null,
        };
        if (name is null)
        {
            var failure = Failure("state_failed", hr);
            failure["build_supported"] = true;
            return Print(context, Failed, failure);
        }
        return Print(context, Ok, new JsonObject { ["ok"] = true, ["build_supported"] = true, ["state"] = name });
    }

    private static JsonObject Failure(string error, int hr) => new()
    {
        ["ok"] = false,
        ["error"] = error,
        ["hresult"] = "0x" + hr.ToString("X8", CultureInfo.InvariantCulture),
    };

    private static int Print(CliContext context, int code, JsonObject result)
    {
        context.Out.WriteLine(result.ToJsonString());
        context.Out.Flush();
        return code;
    }
}
