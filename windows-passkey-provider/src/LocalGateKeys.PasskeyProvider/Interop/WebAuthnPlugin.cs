using System.Runtime.InteropServices;

namespace LocalGateKeys.PasskeyProvider.Interop;

// Managed copies of the webauthn.dll plugin structures and functions. Every layout is copied field by field from the
// Windows SDK 10.0.26100.0 headers:
//   C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\webauthn.h
//   C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\webauthnplugin.h
//   C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\pluginauthenticator.idl
// (also https://github.com/microsoft/webauthn). x64 only (the project is win-x64): DWORD/LONG/BOOL = 4 bytes,
// pointers and HWND = 8, GUID = 16 inline, natural alignment. InteropLayoutTests compares every size and offset
// with a table printed by MSVC (sizeof/offsetof) from those same headers.

/// <summary>WEBAUTHN_PLUGIN_REQUEST_TYPE (pluginauthenticator.idl).</summary>
internal static class WebAuthnPluginRequestType
{
    public const int Ctap2Cbor = 0x01;  // WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR
}

/// <summary>PLUGIN_LOCK_STATUS (pluginauthenticator.idl).</summary>
internal static class PluginLockStatus
{
    public const int PluginLocked = 0;
    public const int PluginUnlocked = 1;
}

/// <summary>AUTHENTICATOR_STATE (webauthnplugin.h).</summary>
internal static class AuthenticatorState
{
    public const int Disabled = 0;  // AuthenticatorState_Disabled
    public const int Enabled = 1;   // AuthenticatorState_Enabled
}

/// <summary>Version constants of the structures this provider fills or reads (webauthn.h, webauthnplugin.h).</summary>
internal static class WebAuthnVersions
{
    public const uint RpEntityInformation = 1;           // WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION
    public const uint UserEntityInformation = 1;         // WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION
    public const uint CoseCredentialParameter = 1;       // WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION
    public const uint Credential = 1;                    // WEBAUTHN_CREDENTIAL_CURRENT_VERSION
    public const uint CredentialEx = 1;                  // WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION
    public const uint CredentialAttestation = 8;         // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION (VERSION_8)
    public const uint Assertion = 6;                     // WEBAUTHN_ASSERTION_CURRENT_VERSION (VERSION_6)
    public const uint CtapCborAuthenticatorOptions = 1;  // WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_CURRENT_VERSION
    public const uint CtapCborMakeCredentialRequest = 1; // WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_CURRENT_VERSION
    public const uint CtapCborGetAssertionRequest = 1;   // WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_CURRENT_VERSION
}

internal static class WebAuthnStrings
{
    public const string CredentialTypePublicKey = "public-key";  // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
    public const string AttestationTypeNone = "none";            // WEBAUTHN_ATTESTATION_TYPE_NONE
}

// -- pluginauthenticator.idl ----------------------------------------------------------------------------------

/// <summary>WEBAUTHN_PLUGIN_OPERATION_REQUEST (not the EXPERIMENTAL_ variant, which has no requestType).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationRequest
{
    public nint hWnd;
    public Guid transactionId;
    public uint cbRequestSignature;
    public byte* pbRequestSignature;
    public int requestType;  // WEBAUTHN_PLUGIN_REQUEST_TYPE
    public uint cbEncodedRequest;
    public byte* pbEncodedRequest;
}

/// <summary>WEBAUTHN_PLUGIN_OPERATION_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationResponse
{
    public uint cbEncodedResponse;
    public byte* pbEncodedResponse;
}

/// <summary>WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCancelOperationRequest
{
    public Guid transactionId;
    public uint cbRequestSignature;
    public byte* pbRequestSignature;
}

// -- webauthn.h -------------------------------------------------------------------------------------------------

/// <summary>WEBAUTHN_RP_ENTITY_INFORMATION (VERSION_1).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnRpEntityInformation
{
    public uint dwVersion;
    public char* pwszId;
    public char* pwszName;
    public char* pwszIcon;
}

/// <summary>WEBAUTHN_USER_ENTITY_INFORMATION (VERSION_1).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnUserEntityInformation
{
    public uint dwVersion;
    public uint cbId;
    public byte* pbId;
    public char* pwszName;
    public char* pwszIcon;
    public char* pwszDisplayName;
}

/// <summary>WEBAUTHN_COSE_CREDENTIAL_PARAMETER.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameter
{
    public uint dwVersion;
    public char* pwszCredentialType;
    public int lAlg;
}

/// <summary>WEBAUTHN_COSE_CREDENTIAL_PARAMETERS.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameters
{
    public uint cCredentialParameters;
    public WebAuthnCoseCredentialParameter* pCredentialParameters;
}

/// <summary>WEBAUTHN_CREDENTIAL.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredential
{
    public uint dwVersion;
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType;
}

/// <summary>WEBAUTHN_CREDENTIAL_EX.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialEx
{
    public uint dwVersion;
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType;
    public uint dwTransports;
}

/// <summary>WEBAUTHN_CREDENTIAL_LIST.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialList
{
    public uint cCredentials;
    public WebAuthnCredentialEx** ppCredentials;
}

/// <summary>WEBAUTHN_EXTENSIONS.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnExtensions
{
    public uint cExtensions;
    public void* pExtensions;  // PWEBAUTHN_EXTENSION, never filled by this provider
}

/// <summary>WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_8 layout.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialAttestation
{
    public uint dwVersion;
    public char* pwszFormatType;
    public uint cbAuthenticatorData;
    public byte* pbAuthenticatorData;
    public uint cbAttestation;
    public byte* pbAttestation;
    public uint dwAttestationDecodeType;
    public void* pvAttestationDecode;
    public uint cbAttestationObject;
    public byte* pbAttestationObject;
    public uint cbCredentialId;
    public byte* pbCredentialId;
    // VERSION_2
    public WebAuthnExtensions Extensions;
    // VERSION_3
    public uint dwUsedTransport;
    // VERSION_4
    public int bEpAtt;
    public int bLargeBlobSupported;
    public int bResidentKey;
    // VERSION_5
    public int bPrfEnabled;
    // VERSION_6
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs;
    // VERSION_7
    public void* pHmacSecret;  // PWEBAUTHN_HMAC_SECRET_SALT
    public int bThirdPartyPayment;
    // VERSION_8
    public uint dwTransports;
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;
    public uint cbRegistrationResponseJSON;
    public byte* pbRegistrationResponseJSON;
}

/// <summary>WEBAUTHN_ASSERTION, WEBAUTHN_ASSERTION_VERSION_6 layout.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAssertion
{
    public uint dwVersion;
    public uint cbAuthenticatorData;
    public byte* pbAuthenticatorData;
    public uint cbSignature;
    public byte* pbSignature;
    public WebAuthnCredential Credential;
    public uint cbUserId;
    public byte* pbUserId;
    // VERSION_2
    public WebAuthnExtensions Extensions;
    public uint cbCredLargeBlob;
    public byte* pbCredLargeBlob;
    public uint dwCredLargeBlobStatus;
    // VERSION_3
    public void* pHmacSecret;  // PWEBAUTHN_HMAC_SECRET_SALT
    // VERSION_4
    public uint dwUsedTransport;
    // VERSION_5
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs;
    // VERSION_6
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;
    public uint cbAuthenticationResponseJSON;
    public byte* pbAuthenticationResponseJSON;
}

// -- webauthnplugin.h -------------------------------------------------------------------------------------------

/// <summary>WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS (VERSION_1). Values: +1 TRUE, 0 not defined, -1 FALSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WebAuthnCtapCborAuthenticatorOptions
{
    public uint dwVersion;
    public int lUp;
    public int lUv;
    public int lRequireResidentKey;
}

/// <summary>WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY (VERSION_1); only referenced through the hmac-salt extension.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborEccPublicKey
{
    public uint dwVersion;
    public int lKty;
    public int lAlg;
    public int lCrv;
    public uint cbX;
    public byte* pbX;
    public uint cbY;
    public byte* pbY;
}

/// <summary>WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION (VERSION_1); never read by this provider.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborHmacSaltExtension
{
    public uint dwVersion;
    public WebAuthnCtapCborEccPublicKey* pKeyAgreement;
    public uint cbEncryptedSalt;
    public byte* pbEncryptedSalt;
    public uint cbSaltAuth;
    public byte* pbSaltAuth;
}

/// <summary>WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST (VERSION_1).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborMakeCredentialRequest
{
    public uint dwVersion;
    public uint cbRpId;
    public byte* pbRpId;
    public uint cbClientDataHash;
    public byte* pbClientDataHash;
    public WebAuthnRpEntityInformation* pRpInformation;
    public WebAuthnUserEntityInformation* pUserInformation;
    public WebAuthnCoseCredentialParameters WebAuthNCredentialParameters;
    public WebAuthnCredentialList CredentialList;
    public uint cbCborExtensionsMap;
    public byte* pbCborExtensionsMap;
    public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
    public int fEmptyPinAuth;
    public uint cbPinAuth;
    public byte* pbPinAuth;
    public int lHmacSecretExt;
    public WebAuthnCtapCborHmacSaltExtension* pHmacSecretMcExtension;
    public int lPrfExt;
    public uint cbHmacSecretSaltValues;
    public byte* pbHmacSecretSaltValues;
    public uint dwCredProtect;
    public uint dwPinProtocol;
    public uint dwEnterpriseAttestation;
    public uint cbCredBlobExt;
    public byte* pbCredBlobExt;
    public int lLargeBlobKeyExt;
    public uint dwLargeBlobSupport;
    public int lMinPinLengthExt;
    public uint cbJsonExt;
    public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST (VERSION_1).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionRequest
{
    public uint dwVersion;
    public char* pwszRpId;
    public uint cbRpId;
    public byte* pbRpId;
    public uint cbClientDataHash;
    public byte* pbClientDataHash;
    public WebAuthnCredentialList CredentialList;
    public uint cbCborExtensionsMap;
    public byte* pbCborExtensionsMap;
    public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
    public int fEmptyPinAuth;
    public uint cbPinAuth;
    public byte* pbPinAuth;
    public WebAuthnCtapCborHmacSaltExtension* pHmacSaltExtension;
    public uint cbHmacSecretSaltValues;
    public byte* pbHmacSecretSaltValues;
    public uint dwPinProtocol;
    public int lCredBlobExt;
    public int lLargeBlobKeyExt;
    public uint dwCredLargeBlobOperation;
    public uint cbCredLargeBlobCompressed;
    public byte* pbCredLargeBlobCompressed;
    public uint dwCredLargeBlobOriginalSize;
    public uint cbJsonExt;
    public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionResponse
{
    public WebAuthnAssertion WebAuthNAssertion;
    public WebAuthnUserEntityInformation* pUserInformation;
    public uint dwNumberOfCredentials;
    public int lUserSelected;
    public uint cbLargeBlobKey;
    public byte* pbLargeBlobKey;
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs;
}

/// <summary>
/// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS (version 1; not the _2 structure, which only builds 26100.8524+ know).
/// <c>rclsid</c> is a <c>REFCLSID</c> member, i.e. a pointer to the CLSID.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions
{
    public char* pwszAuthenticatorName;
    public Guid* rclsid;
    public char* pwszPluginRpId;
    public char* pwszLightThemeLogoSvg;
    public char* pwszDarkThemeLogoSvg;
    public uint cbAuthenticatorInfo;
    public byte* pbAuthenticatorInfo;
    public uint cSupportedRpIds;
    public char** ppwszSupportedRpIds;
}

/// <summary>WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorResponse
{
    public uint cbOpSignPubKey;
    public byte* pbOpSignPubKey;
}

/// <summary>WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS (metadata cache entry; IDs and names only, never key material).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCredentialDetails
{
    public uint cbCredentialId;
    public byte* pbCredentialId;
    public char* pwszRpId;
    public char* pwszRpName;
    public uint cbUserId;
    public byte* pbUserId;
    public char* pwszUserName;
    public char* pwszUserDisplayName;
}

/// <summary>
/// The webauthn.dll exports this provider uses (webauthnplugin.h). Only System32 is searched, so a planted
/// webauthn.dll next to the exe is never loaded. <c>REFCLSID</c> parameters are passed as <c>in Guid</c> (a pointer).
/// </summary>
internal static unsafe partial class WebAuthnPluginNative
{
    private const string Dll = "webauthn.dll";

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginGetAuthenticatorState(in Guid rclsid, int* pluginAuthenticatorState);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginAddAuthenticator(WebAuthnPluginAddAuthenticatorOptions* options,
                                                             WebAuthnPluginAddAuthenticatorResponse** response);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial void WebAuthNPluginFreeAddAuthenticatorResponse(WebAuthnPluginAddAuthenticatorResponse* response);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginRemoveAuthenticator(in Guid rclsid);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginGetOperationSigningPublicKey(in Guid rclsid, uint* pcbOpSignPubKey,
                                                                         byte** ppbOpSignPubKey);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial void WebAuthNPluginFreePublicKeyResponse(byte* pbOpSignPubKey);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginAuthenticatorAddCredentials(in Guid rclsid, uint cCredentialDetails,
                                                                        WebAuthnPluginCredentialDetails* pCredentialDetails);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNPluginAuthenticatorRemoveAllCredentials(in Guid rclsid);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNDecodeMakeCredentialRequest(uint cbEncoded, byte* pbEncoded,
                                                                  WebAuthnCtapCborMakeCredentialRequest** request);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial void WebAuthNFreeDecodedMakeCredentialRequest(WebAuthnCtapCborMakeCredentialRequest* request);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNDecodeGetAssertionRequest(uint cbEncoded, byte* pbEncoded,
                                                                WebAuthnCtapCborGetAssertionRequest** request);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial void WebAuthNFreeDecodedGetAssertionRequest(WebAuthnCtapCborGetAssertionRequest* request);

    // The encoded buffer has no Free partner in webauthnplugin.h. The Microsoft sample ([S4]
    // PluginAuthenticatorImpl.cpp) receives it into a wil::unique_cotaskmem_ptr and hands it to
    // WEBAUTHN_PLUGIN_OPERATION_RESPONSE.pbEncodedResponse unchanged: it is CoTaskMem memory owned by the caller.
    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNEncodeMakeCredentialResponse(WebAuthnCredentialAttestation* attestation,
                                                                   uint* pcbResp, byte** ppbResp);

    [LibraryImport(Dll)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    public static partial int WebAuthNEncodeGetAssertionResponse(WebAuthnCtapCborGetAssertionResponse* response,
                                                                 uint* pcbResp, byte** ppbResp);
}
