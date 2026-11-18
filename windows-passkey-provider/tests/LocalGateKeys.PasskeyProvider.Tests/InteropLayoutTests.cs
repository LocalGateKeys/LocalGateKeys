using System.Runtime.InteropServices;
using LocalGateKeys.PasskeyProvider.Interop;

namespace LocalGateKeys.PasskeyProvider.Tests;

/// <summary>
/// Catches layout drift. The table was printed by a C program compiled with MSVC 14.29 (x64) against the Windows SDK
/// 10.0.26100.0 headers (webauthn.h, webauthnplugin.h, pluginauthenticator.h): sizeof and offsetof of each field.
/// </summary>
public class InteropLayoutTests
{
    public static TheoryData<Type, int> Sizes => new()
    {
        { typeof(WebAuthnPluginOperationRequest), 56 },
        { typeof(WebAuthnPluginOperationResponse), 16 },
        { typeof(WebAuthnPluginCancelOperationRequest), 32 },
        { typeof(WebAuthnRpEntityInformation), 32 },
        { typeof(WebAuthnUserEntityInformation), 40 },
        { typeof(WebAuthnCoseCredentialParameter), 24 },
        { typeof(WebAuthnCoseCredentialParameters), 16 },
        { typeof(WebAuthnCredential), 24 },
        { typeof(WebAuthnCredentialEx), 32 },
        { typeof(WebAuthnCredentialList), 16 },
        { typeof(WebAuthnExtensions), 16 },
        { typeof(WebAuthnCtapCborAuthenticatorOptions), 16 },
        { typeof(WebAuthnCtapCborEccPublicKey), 48 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), 48 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), 200 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), 176 },
        { typeof(WebAuthnCredentialAttestation), 192 },
        { typeof(WebAuthnAssertion), 168 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), 216 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), 72 },
        { typeof(WebAuthnPluginAddAuthenticatorResponse), 16 },
        { typeof(WebAuthnPluginCredentialDetails), 64 },
    };

    public static TheoryData<Type, string, int> Offsets => new()
    {
        { typeof(WebAuthnPluginOperationRequest), "transactionId", 8 },
        { typeof(WebAuthnPluginOperationRequest), "cbRequestSignature", 24 },
        { typeof(WebAuthnPluginOperationRequest), "pbRequestSignature", 32 },
        { typeof(WebAuthnPluginOperationRequest), "requestType", 40 },
        { typeof(WebAuthnPluginOperationRequest), "cbEncodedRequest", 44 },
        { typeof(WebAuthnPluginOperationRequest), "pbEncodedRequest", 48 },
        { typeof(WebAuthnPluginOperationResponse), "pbEncodedResponse", 8 },
        { typeof(WebAuthnPluginCancelOperationRequest), "cbRequestSignature", 16 },
        { typeof(WebAuthnPluginCancelOperationRequest), "pbRequestSignature", 24 },
        { typeof(WebAuthnRpEntityInformation), "pwszId", 8 },
        { typeof(WebAuthnRpEntityInformation), "pwszName", 16 },
        { typeof(WebAuthnRpEntityInformation), "pwszIcon", 24 },
        { typeof(WebAuthnUserEntityInformation), "cbId", 4 },
        { typeof(WebAuthnUserEntityInformation), "pbId", 8 },
        { typeof(WebAuthnUserEntityInformation), "pwszName", 16 },
        { typeof(WebAuthnUserEntityInformation), "pwszIcon", 24 },
        { typeof(WebAuthnUserEntityInformation), "pwszDisplayName", 32 },
        { typeof(WebAuthnCoseCredentialParameter), "pwszCredentialType", 8 },
        { typeof(WebAuthnCoseCredentialParameter), "lAlg", 16 },
        { typeof(WebAuthnCoseCredentialParameters), "pCredentialParameters", 8 },
        { typeof(WebAuthnCredential), "cbId", 4 },
        { typeof(WebAuthnCredential), "pbId", 8 },
        { typeof(WebAuthnCredential), "pwszCredentialType", 16 },
        { typeof(WebAuthnCredentialEx), "cbId", 4 },
        { typeof(WebAuthnCredentialEx), "pbId", 8 },
        { typeof(WebAuthnCredentialEx), "pwszCredentialType", 16 },
        { typeof(WebAuthnCredentialEx), "dwTransports", 24 },
        { typeof(WebAuthnCredentialList), "ppCredentials", 8 },
        { typeof(WebAuthnExtensions), "pExtensions", 8 },
        { typeof(WebAuthnCtapCborAuthenticatorOptions), "lUp", 4 },
        { typeof(WebAuthnCtapCborAuthenticatorOptions), "lUv", 8 },
        { typeof(WebAuthnCtapCborAuthenticatorOptions), "lRequireResidentKey", 12 },
        { typeof(WebAuthnCtapCborEccPublicKey), "lKty", 4 },
        { typeof(WebAuthnCtapCborEccPublicKey), "lAlg", 8 },
        { typeof(WebAuthnCtapCborEccPublicKey), "lCrv", 12 },
        { typeof(WebAuthnCtapCborEccPublicKey), "cbX", 16 },
        { typeof(WebAuthnCtapCborEccPublicKey), "pbX", 24 },
        { typeof(WebAuthnCtapCborEccPublicKey), "cbY", 32 },
        { typeof(WebAuthnCtapCborEccPublicKey), "pbY", 40 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), "pKeyAgreement", 8 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), "cbEncryptedSalt", 16 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), "pbEncryptedSalt", 24 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), "cbSaltAuth", 32 },
        { typeof(WebAuthnCtapCborHmacSaltExtension), "pbSaltAuth", 40 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbRpId", 4 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbRpId", 8 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbClientDataHash", 16 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbClientDataHash", 24 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pRpInformation", 32 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pUserInformation", 40 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "WebAuthNCredentialParameters", 48 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "CredentialList", 64 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbCborExtensionsMap", 80 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbCborExtensionsMap", 88 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pAuthenticatorOptions", 96 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "fEmptyPinAuth", 104 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbPinAuth", 108 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbPinAuth", 112 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "lHmacSecretExt", 120 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pHmacSecretMcExtension", 128 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "lPrfExt", 136 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbHmacSecretSaltValues", 140 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbHmacSecretSaltValues", 144 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "dwCredProtect", 152 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "dwPinProtocol", 156 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "dwEnterpriseAttestation", 160 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbCredBlobExt", 164 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbCredBlobExt", 168 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "lLargeBlobKeyExt", 176 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "dwLargeBlobSupport", 180 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "lMinPinLengthExt", 184 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "cbJsonExt", 188 },
        { typeof(WebAuthnCtapCborMakeCredentialRequest), "pbJsonExt", 192 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pwszRpId", 8 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbRpId", 16 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbRpId", 24 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbClientDataHash", 32 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbClientDataHash", 40 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "CredentialList", 48 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbCborExtensionsMap", 64 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbCborExtensionsMap", 72 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pAuthenticatorOptions", 80 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "fEmptyPinAuth", 88 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbPinAuth", 92 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbPinAuth", 96 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pHmacSaltExtension", 104 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbHmacSecretSaltValues", 112 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbHmacSecretSaltValues", 120 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "dwPinProtocol", 128 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "lCredBlobExt", 132 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "lLargeBlobKeyExt", 136 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "dwCredLargeBlobOperation", 140 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbCredLargeBlobCompressed", 144 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbCredLargeBlobCompressed", 152 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "dwCredLargeBlobOriginalSize", 160 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "cbJsonExt", 164 },
        { typeof(WebAuthnCtapCborGetAssertionRequest), "pbJsonExt", 168 },
        { typeof(WebAuthnCredentialAttestation), "pwszFormatType", 8 },
        { typeof(WebAuthnCredentialAttestation), "cbAuthenticatorData", 16 },
        { typeof(WebAuthnCredentialAttestation), "pbAuthenticatorData", 24 },
        { typeof(WebAuthnCredentialAttestation), "cbAttestation", 32 },
        { typeof(WebAuthnCredentialAttestation), "pbAttestation", 40 },
        { typeof(WebAuthnCredentialAttestation), "dwAttestationDecodeType", 48 },
        { typeof(WebAuthnCredentialAttestation), "pvAttestationDecode", 56 },
        { typeof(WebAuthnCredentialAttestation), "cbAttestationObject", 64 },
        { typeof(WebAuthnCredentialAttestation), "pbAttestationObject", 72 },
        { typeof(WebAuthnCredentialAttestation), "cbCredentialId", 80 },
        { typeof(WebAuthnCredentialAttestation), "pbCredentialId", 88 },
        { typeof(WebAuthnCredentialAttestation), "Extensions", 96 },
        { typeof(WebAuthnCredentialAttestation), "dwUsedTransport", 112 },
        { typeof(WebAuthnCredentialAttestation), "bEpAtt", 116 },
        { typeof(WebAuthnCredentialAttestation), "bLargeBlobSupported", 120 },
        { typeof(WebAuthnCredentialAttestation), "bResidentKey", 124 },
        { typeof(WebAuthnCredentialAttestation), "bPrfEnabled", 128 },
        { typeof(WebAuthnCredentialAttestation), "cbUnsignedExtensionOutputs", 132 },
        { typeof(WebAuthnCredentialAttestation), "pbUnsignedExtensionOutputs", 136 },
        { typeof(WebAuthnCredentialAttestation), "pHmacSecret", 144 },
        { typeof(WebAuthnCredentialAttestation), "bThirdPartyPayment", 152 },
        { typeof(WebAuthnCredentialAttestation), "dwTransports", 156 },
        { typeof(WebAuthnCredentialAttestation), "cbClientDataJSON", 160 },
        { typeof(WebAuthnCredentialAttestation), "pbClientDataJSON", 168 },
        { typeof(WebAuthnCredentialAttestation), "cbRegistrationResponseJSON", 176 },
        { typeof(WebAuthnCredentialAttestation), "pbRegistrationResponseJSON", 184 },
        { typeof(WebAuthnAssertion), "cbAuthenticatorData", 4 },
        { typeof(WebAuthnAssertion), "pbAuthenticatorData", 8 },
        { typeof(WebAuthnAssertion), "cbSignature", 16 },
        { typeof(WebAuthnAssertion), "pbSignature", 24 },
        { typeof(WebAuthnAssertion), "Credential", 32 },
        { typeof(WebAuthnAssertion), "cbUserId", 56 },
        { typeof(WebAuthnAssertion), "pbUserId", 64 },
        { typeof(WebAuthnAssertion), "Extensions", 72 },
        { typeof(WebAuthnAssertion), "cbCredLargeBlob", 88 },
        { typeof(WebAuthnAssertion), "pbCredLargeBlob", 96 },
        { typeof(WebAuthnAssertion), "dwCredLargeBlobStatus", 104 },
        { typeof(WebAuthnAssertion), "pHmacSecret", 112 },
        { typeof(WebAuthnAssertion), "dwUsedTransport", 120 },
        { typeof(WebAuthnAssertion), "cbUnsignedExtensionOutputs", 124 },
        { typeof(WebAuthnAssertion), "pbUnsignedExtensionOutputs", 128 },
        { typeof(WebAuthnAssertion), "cbClientDataJSON", 136 },
        { typeof(WebAuthnAssertion), "pbClientDataJSON", 144 },
        { typeof(WebAuthnAssertion), "cbAuthenticationResponseJSON", 152 },
        { typeof(WebAuthnAssertion), "pbAuthenticationResponseJSON", 160 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "pUserInformation", 168 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "dwNumberOfCredentials", 176 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "lUserSelected", 180 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "cbLargeBlobKey", 184 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "pbLargeBlobKey", 192 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "cbUnsignedExtensionOutputs", 200 },
        { typeof(WebAuthnCtapCborGetAssertionResponse), "pbUnsignedExtensionOutputs", 208 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "rclsid", 8 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "pwszPluginRpId", 16 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "pwszLightThemeLogoSvg", 24 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "pwszDarkThemeLogoSvg", 32 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "cbAuthenticatorInfo", 40 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "pbAuthenticatorInfo", 48 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "cSupportedRpIds", 56 },
        { typeof(WebAuthnPluginAddAuthenticatorOptions), "ppwszSupportedRpIds", 64 },
        { typeof(WebAuthnPluginAddAuthenticatorResponse), "pbOpSignPubKey", 8 },
        { typeof(WebAuthnPluginCredentialDetails), "pbCredentialId", 8 },
        { typeof(WebAuthnPluginCredentialDetails), "pwszRpId", 16 },
        { typeof(WebAuthnPluginCredentialDetails), "pwszRpName", 24 },
        { typeof(WebAuthnPluginCredentialDetails), "cbUserId", 32 },
        { typeof(WebAuthnPluginCredentialDetails), "pbUserId", 40 },
        { typeof(WebAuthnPluginCredentialDetails), "pwszUserName", 48 },
        { typeof(WebAuthnPluginCredentialDetails), "pwszUserDisplayName", 56 },
    };

    [Theory]
    [MemberData(nameof(Sizes))]
    public void SizeMatchesTheHeaders(Type type, int size) => Assert.Equal(size, Marshal.SizeOf(type));

    [Theory]
    [MemberData(nameof(Offsets))]
    public void OffsetMatchesTheHeaders(Type type, string field, int offset) =>
        Assert.Equal(offset, (int)Marshal.OffsetOf(type, field));

    [Fact]
    public void EveryFieldIsInTheTable()
    {
        var listed = Offsets.Select(row => ((Type)row[0], (string)row[1])).ToHashSet();
        foreach (var type in Sizes.Select(row => (Type)row[0]))
        {
            foreach (var field in type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public).Skip(1))
                Assert.Contains((type, field.Name), listed);
        }
    }

    [Fact]
    public void InterfaceIdIsFromTheIdl()
    {
        Assert.Equal(new Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7"), typeof(IPluginAuthenticator).GUID);
        Assert.Equal(new Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7"), Com.ClassFactory.IidIPluginAuthenticator);
    }

    [Fact]
    public void VtableOrderIsFromTheIdl()
    {
        var methods = typeof(IPluginAuthenticator).GetMethods().Select(m => m.Name).ToArray();
        Assert.Equal(["MakeCredential", "GetAssertion", "CancelOperation", "GetLockStatus"], methods);
    }
}
