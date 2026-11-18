using System.Text.Json.Nodes;
using LocalGateKeys.PasskeyProvider.Interop;
using LocalGateKeys.PasskeyProvider.Protocol;
using LocalGateKeys.PasskeyProvider.Provider;
using LocalGateKeys.PasskeyProvider.Tests.Fakes;

namespace LocalGateKeys.PasskeyProvider.Tests;

public unsafe class CtapMappingTests
{
    private static readonly byte[] RpIdBytes = "example.test"u8.ToArray();

    /// <summary>Builds a decoded make-credential request in native memory, as webauthn.dll would hand it over.</summary>
    private static MakeCredentialInput ReadMake(int? lUv, int lRk = 1, int clientDataHashLength = 32,
                                                string excludeType = "public-key")
    {
        var hash = new byte[clientDataHashLength];
        fixed (byte* rpId = RpIdBytes)
        fixed (byte* cdh = hash)
        fixed (byte* userId = ProviderHarness.UserId)
        fixed (byte* credId = ProviderHarness.CredentialId)
        fixed (char* rpName = "Example")
        fixed (char* userName = "ada")
        fixed (char* displayName = "Ada")
        fixed (char* publicKey = "public-key")
        fixed (char* exType = excludeType)
        fixed (char* otherType = "other")
        {
            var rp = new WebAuthnRpEntityInformation { dwVersion = 1, pwszName = rpName };
            var user = new WebAuthnUserEntityInformation
            {
                dwVersion = 1, cbId = (uint)ProviderHarness.UserId.Length, pbId = userId, pwszName = userName,
                pwszDisplayName = displayName,
            };
            var parameters = stackalloc WebAuthnCoseCredentialParameter[3];
            parameters[0] = new() { dwVersion = 1, pwszCredentialType = publicKey, lAlg = -7 };
            parameters[1] = new() { dwVersion = 1, pwszCredentialType = otherType, lAlg = -8 };
            parameters[2] = new() { dwVersion = 1, pwszCredentialType = publicKey, lAlg = -257 };
            var exclude = new WebAuthnCredentialEx
            {
                dwVersion = 1, cbId = (uint)ProviderHarness.CredentialId.Length, pbId = credId,
                pwszCredentialType = exType,
            };
            var excludeList = stackalloc WebAuthnCredentialEx*[1];
            excludeList[0] = &exclude;
            var options = new WebAuthnCtapCborAuthenticatorOptions { dwVersion = 1, lUp = 1, lUv = lUv ?? 0, lRequireResidentKey = lRk };
            var request = new WebAuthnCtapCborMakeCredentialRequest
            {
                dwVersion = 1, cbRpId = (uint)RpIdBytes.Length, pbRpId = rpId, cbClientDataHash = (uint)hash.Length,
                pbClientDataHash = cdh, pRpInformation = &rp, pUserInformation = &user,
                WebAuthNCredentialParameters = new() { cCredentialParameters = 3, pCredentialParameters = parameters },
                CredentialList = new() { cCredentials = 1, ppCredentials = excludeList },
                pAuthenticatorOptions = lUv is null ? null : &options,
            };
            return CtapMapping.ReadMakeCredential(&request);
        }
    }

    private static GetAssertionInput ReadGet(int lUv, uint allowCount = 1)
    {
        fixed (byte* rpId = RpIdBytes)
        fixed (byte* cdh = ProviderHarness.ClientDataHash)
        fixed (byte* credId = ProviderHarness.CredentialId)
        fixed (char* publicKey = "public-key")
        {
            var allow = new WebAuthnCredentialEx
            {
                dwVersion = 1, cbId = (uint)ProviderHarness.CredentialId.Length, pbId = credId,
                pwszCredentialType = publicKey,
            };
            var list = stackalloc WebAuthnCredentialEx*[1];
            list[0] = &allow;
            var options = new WebAuthnCtapCborAuthenticatorOptions { dwVersion = 1, lUv = lUv };
            var request = new WebAuthnCtapCborGetAssertionRequest
            {
                dwVersion = 1, cbRpId = (uint)RpIdBytes.Length, pbRpId = rpId, cbClientDataHash = 32,
                pbClientDataHash = cdh, CredentialList = new() { cCredentials = allowCount, ppCredentials = allowCount == 0 ? null : list },
                pAuthenticatorOptions = &options,
            };
            return CtapMapping.ReadGetAssertion(&request);
        }
    }

    [Fact]
    public void MakeCredentialStructToJson()
    {
        var input = ReadMake(lUv: 1);
        var json = SystemMessages.ToJson(CtapMapping.ToRequest(input, new CallerHint("msedge.exe", "Sign in")));
        var expected = new JsonObject
        {
            ["action"] = "passkey_create_system", ["rp_id"] = "example.test", ["rp_name"] = "Example",
            ["user_id"] = "dXNlci0x", ["user_name"] = "ada", ["user_display_name"] = "Ada",
            ["client_data_hash"] = CtapMapping.B64(new byte[32]), ["algorithms"] = new JsonArray(-7, -257),
            ["exclude_credentials"] = new JsonArray(CtapMapping.B64(ProviderHarness.CredentialId)),
            ["resident_key"] = true, ["user_verification"] = "required",
            ["caller"] = new JsonObject { ["image"] = "msedge.exe", ["title"] = "Sign in" },
        };
        Assert.True(JsonNode.DeepEquals(expected, json), json.ToJsonString());
    }

    [Theory]
    [InlineData(1, "required")]
    [InlineData(0, "required")]       // "preferred" or not said: the provider can verify, so it does
    [InlineData(-1, "discouraged")]   // only an explicit "discouraged" skips verification
    [InlineData(2, "required")]       // an unknown value never weakens verification
    public void UserVerificationFromLUv(int lUv, string expected)
    {
        Assert.Equal(expected, CtapMapping.ToRequest(ReadMake(lUv), null).UserVerification);
        Assert.Equal(expected, CtapMapping.ToRequest(ReadGet(lUv), null).UserVerification);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    public void ResidentKeyOnlyWhenPlusOne(int lRk, bool expected) =>
        Assert.Equal(expected, CtapMapping.ToRequest(ReadMake(1, lRk), null).ResidentKey);

    [Fact]
    public void MissingOptionsMeansVerifiedAndNoResidentKey()
    {
        var request = CtapMapping.ToRequest(ReadMake(lUv: null), null);
        Assert.Equal("required", request.UserVerification);
        Assert.False(request.ResidentKey);
    }

    [Fact]
    public void NonPublicKeyEntriesAreSkipped()
    {
        var input = ReadMake(1, excludeType: "other");
        Assert.Empty(input.ExcludeCredentials);
        Assert.Equal([-7, -257], input.Algorithms);
    }

    [Fact]
    public void GetAssertionStructToJson()
    {
        var json = SystemMessages.ToJson(CtapMapping.ToRequest(ReadGet(1), null));
        var expected = new JsonObject
        {
            ["action"] = "passkey_get_system", ["rp_id"] = "example.test",
            ["client_data_hash"] = CtapMapping.B64(ProviderHarness.ClientDataHash),
            ["allow_credentials"] = new JsonArray(CtapMapping.B64(ProviderHarness.CredentialId)),
            ["user_verification"] = "required",
        };
        Assert.True(JsonNode.DeepEquals(expected, json), json.ToJsonString());
        Assert.Empty(ReadGet(1, allowCount: 0).AllowCredentials);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void ClientDataHashMustBe32Bytes(int length) =>
        Assert.Throws<CtapMappingException>(() => ReadMake(1, clientDataHashLength: length));

    [Fact]
    public void NullRequestIsInvalid()
    {
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadMakeCredential(null));
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadGetAssertion(null));
    }

    [Fact]
    public void OverlongCredentialListIsInvalid()
    {
        var request = new WebAuthnCtapCborGetAssertionRequest
        {
            dwVersion = 1, CredentialList = new() { cCredentials = 100_000, ppCredentials = (WebAuthnCredentialEx**)8 },
        };
        Assert.False(Reads(&request));
    }

    private static bool Reads(WebAuthnCtapCborGetAssertionRequest* request)
    {
        try
        {
            CtapMapping.ReadGetAssertion(request);
            return true;
        }
        catch (CtapMappingException)
        {
            return false;
        }
    }

    [Fact]
    public void InvalidUtf8RpIdIsInvalid()
    {
        var input = ProviderHarness.GetInput() with { RpId = [0xC3, 0x28] };
        Assert.Throws<CtapMappingException>(() => CtapMapping.ToRequest(input, null));
    }

    // -- replies --------------------------------------------------------------------------------------------

    [Fact]
    public void CreateReplyToAttestationStruct()
    {
        var output = CtapMapping.ReadCreateReply(ProviderHarness.CreateReply(), ProviderHarness.MakeInput());
        var authData = ProviderHarness.AuthData(attested: true);
        Assert.Equal(authData, output.AuthenticatorData);

        CtapMapping.WithNativeAttestation(output, a =>
        {
            Assert.Equal(WebAuthnVersions.CredentialAttestation, a->dwVersion);
            Assert.Equal("none", new string(a->pwszFormatType));
            Assert.Equal(authData, new ReadOnlySpan<byte>(a->pbAuthenticatorData, (int)a->cbAuthenticatorData).ToArray());
            Assert.Equal(0u, a->cbAttestation);
            Assert.True(a->pbAttestation is null);
            Assert.Equal(0u, a->cbCredentialId);
            return 0;
        });
    }

    [Fact]
    public void GetReplyToAssertionStruct()
    {
        var output = CtapMapping.ReadGetReply(ProviderHarness.GetReply(), ProviderHarness.GetInput());
        CtapMapping.WithNativeAssertion(output, r =>
        {
            var a = r->WebAuthNAssertion;
            Assert.Equal(WebAuthnVersions.Assertion, a.dwVersion);
            Assert.Equal(ProviderHarness.AuthData(attested: false),
                         new ReadOnlySpan<byte>(a.pbAuthenticatorData, (int)a.cbAuthenticatorData).ToArray());
            Assert.Equal(new byte[] { 4, 5, 6 }, new ReadOnlySpan<byte>(a.pbSignature, (int)a.cbSignature).ToArray());
            Assert.Equal(1u, a.Credential.dwVersion);
            Assert.Equal("public-key", new string(a.Credential.pwszCredentialType));
            Assert.Equal(ProviderHarness.CredentialId, new ReadOnlySpan<byte>(a.Credential.pbId, (int)a.Credential.cbId).ToArray());
            Assert.Equal(ProviderHarness.UserId, new ReadOnlySpan<byte>(a.pbUserId, (int)a.cbUserId).ToArray());
            Assert.Equal(1u, r->pUserInformation->dwVersion);
            Assert.Equal(ProviderHarness.UserId,
                         new ReadOnlySpan<byte>(r->pUserInformation->pbId, (int)r->pUserInformation->cbId).ToArray());
            Assert.Equal(1u, r->dwNumberOfCredentials);
            return 0;
        });
    }

    [Fact]
    public void EmptyUserHandleHasNoUserEntity()
    {
        var reply = ProviderHarness.GetReply();
        reply["user_handle"] = "";
        var output = CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput(allow: [ProviderHarness.CredentialId]));
        CtapMapping.WithNativeAssertion(output, r =>
        {
            Assert.True(r->pUserInformation is null);
            Assert.Equal(0u, r->WebAuthNAssertion.cbUserId);
            return 0;
        });
    }

    public static TheoryData<string> BadCreateReplies => new()
    {
        "aaguid", "credential", "format", "flags", "base64", "shape",
    };

    [Theory]
    [MemberData(nameof(BadCreateReplies))]
    public void BadCreateRepliesAreRefused(string defect)
    {
        var reply = defect switch
        {
            "aaguid" => ProviderHarness.CreateReply(ProviderHarness.AuthData(attested: true, aaguid: new byte[16])),
            "credential" => ProviderHarness.CreateReply(ProviderHarness.AuthData(attested: true, credentialId: [7, 7])),
            "flags" => ProviderHarness.CreateReply(ProviderHarness.AuthData(attested: false)),
            _ => ProviderHarness.CreateReply(),
        };
        if (defect == "format")
            reply["attestation_format"] = "packed";
        if (defect == "base64")
            reply["authenticator_data"] = "AQID=";
        if (defect == "shape")
            reply.Remove("credential_id");
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadCreateReply(reply, ProviderHarness.MakeInput()));
    }

    [Fact]
    public void DiscoverableGetNeedsAUserHandle()
    {
        var reply = ProviderHarness.GetReply();
        reply["user_handle"] = "";
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput()));
    }

    [Fact]
    public void GetReplyWithAttestedFlagIsRefused()
    {
        var reply = ProviderHarness.GetReply();
        reply["authenticator_data"] = CtapMapping.B64(ProviderHarness.AuthData(attested: true));
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput()));
    }
    // -- UP and UV flags in replies -------------------------------------------------------------------------

    private const byte Up = 0x01, Uv = 0x04, BeBs = 0x08 | 0x10;

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    public void ReplyWithoutUvIsRefusedWhenVerificationWasAsked(int lUv)
    {
        var authData = ProviderHarness.AuthData(attested: true, flags: Up | BeBs);
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadCreateReply(
            ProviderHarness.CreateReply(authData), ProviderHarness.MakeInput(uv: lUv)));
        var reply = ProviderHarness.GetReply();
        reply["authenticator_data"] = CtapMapping.B64(ProviderHarness.AuthData(attested: false, flags: Up | BeBs));
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput(uv: lUv)));
    }

    [Fact]
    public void ReplyWithoutUvIsAcceptedWhenDiscouraged()
    {
        var authData = ProviderHarness.AuthData(attested: true, flags: Up | BeBs);
        Assert.Equal(authData, CtapMapping.ReadCreateReply(
            ProviderHarness.CreateReply(authData), ProviderHarness.MakeInput(uv: -1)).AuthenticatorData);
        var reply = ProviderHarness.GetReply();
        reply["authenticator_data"] = CtapMapping.B64(ProviderHarness.AuthData(attested: false, flags: Up | BeBs));
        Assert.NotNull(CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput(uv: -1)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(-1)]
    public void ReplyWithoutUpIsAlwaysRefused(int lUv)
    {
        var authData = ProviderHarness.AuthData(attested: true, flags: Uv | BeBs);
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadCreateReply(
            ProviderHarness.CreateReply(authData), ProviderHarness.MakeInput(uv: lUv)));
        var reply = ProviderHarness.GetReply();
        reply["authenticator_data"] = CtapMapping.B64(ProviderHarness.AuthData(attested: false, flags: Uv | BeBs));
        Assert.Throws<CtapMappingException>(() => CtapMapping.ReadGetReply(reply, ProviderHarness.GetInput(uv: lUv)));
    }
}
