using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using FirmwareKit.AVB.Verification;

namespace FirmwareKit.AVB.Tests;

public class AvbResultStringsTests
{
    [Fact]
    public void SlotVerifyResultStrings_MatchLibAvbValues()
    {
        Assert.Equal("OK", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.Ok));
        Assert.Equal("ERROR_OOM", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorOom));
        Assert.Equal("ERROR_IO", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorIo));
        Assert.Equal("ERROR_VERIFICATION", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorVerification));
        Assert.Equal("ERROR_ROLLBACK_INDEX", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorRollbackIndex));
        Assert.Equal("ERROR_PUBLIC_KEY_REJECTED", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorPublicKeyRejected));
        Assert.Equal("ERROR_INVALID_METADATA", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorInvalidMetadata));
        Assert.Equal("ERROR_UNSUPPORTED_VERSION", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorUnsupportedVersion));
        Assert.Equal("ERROR_INVALID_ARGUMENT", AvbResultStrings.ToLibAvbString(AvbSlotVerifyResult.ErrorInvalidArgument));
    }

    [Fact]
    public void AbFlowResultStrings_MatchLibAvbValues()
    {
        Assert.Equal("OK", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.Ok));
        Assert.Equal("OK_WITH_VERIFICATION_ERROR", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.OkWithVerificationError));
        Assert.Equal("ERROR_OOM", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.ErrorOom));
        Assert.Equal("ERROR_IO", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.ErrorIo));
        Assert.Equal("ERROR_NO_BOOTABLE_SLOTS", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.ErrorNoBootableSlot));
        Assert.Equal("ERROR_INVALID_ARGUMENT", AvbResultStrings.ToLibAvbString(AvbAbFlowResult.ErrorInvalidArgument));

        Assert.Equal("OK", AvbAbFlow.ResultToString(AvbAbFlowResult.Ok));
        Assert.Equal("ERROR_IO", AvbAbFlow.ResultToString(AvbAbFlowResult.ErrorIo));
        Assert.Equal("ERROR_VERIFICATION", AvbSlotVerifier.ResultToString(AvbSlotVerifyResult.ErrorVerification));
    }
}
