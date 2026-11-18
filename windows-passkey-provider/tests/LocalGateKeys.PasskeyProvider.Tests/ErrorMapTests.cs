using LocalGateKeys.PasskeyProvider.Runtime;

namespace LocalGateKeys.PasskeyProvider.Tests;

public class ErrorMapTests
{
    // Design note section 7, one row each.
    [Theory]
    [InlineData("user_cancelled", unchecked((int)0x80090036))]   // NTE_USER_CANCELLED
    [InlineData("locked_declined", unchecked((int)0x80090036))]
    [InlineData("busy", unchecked((int)0x80090036))]
    [InlineData("item_limit", unchecked((int)0x80090036))]
    [InlineData("not_found", unchecked((int)0x80090011))]        // NTE_NOT_FOUND
    [InlineData("invalid_state", unchecked((int)0x8009000F))]    // NTE_EXISTS
    [InlineData("not_supported", unchecked((int)0x80090027))]    // NTE_INVALID_PARAMETER
    [InlineData("disabled", unchecked((int)0x80090035))]         // NTE_DEVICE_NOT_FOUND
    [InlineData("invalid_request", unchecked((int)0x80004005))]  // E_FAIL
    [InlineData("session_changed", unchecked((int)0x80004005))]
    [InlineData("unauthorized", unchecked((int)0x80004005))]
    [InlineData("client_not_allowed", unchecked((int)0x80004005))]
    [InlineData("locked", unchecked((int)0x80004005))]
    [InlineData("", unchecked((int)0x80004005))]
    [InlineData("BUSY", unchecked((int)0x80004005))]
    [InlineData(null, unchecked((int)0x80004005))]
    public void AppErrorsMapToTheNoteTable(string? error, int expected)
    {
        Assert.Equal(expected, ErrorMap.ToHResult(error));
    }

    [Fact]
    public void ConditionsWithoutAnAppReply()
    {
        Assert.Equal(unchecked((int)0x800705B4), HResults.Timeout);           // HRESULT_FROM_WIN32(ERROR_TIMEOUT)
        Assert.Equal(unchecked((int)0x800704C7), HResults.Cancelled);         // HRESULT_FROM_WIN32(ERROR_CANCELLED)
        Assert.Equal(unchecked((int)0x80090035), HResults.AppNotRunning);     // NTE_DEVICE_NOT_FOUND
        Assert.Equal(unchecked((int)0x80090006), HResults.NteBadSignature);
        Assert.Equal(unchecked((int)0x80070057), HResults.EInvalidArg);
        Assert.Equal(0, HResults.SOk);
    }
}
