namespace FirmwareKit.AVB;

/// <summary>
/// Converts AVB result enums to stable libavb-style string values.
/// </summary>
public static class AvbResultStrings
{
    /// <summary>
    /// Converts <see cref="AvbSlotVerifyResult"/> to a libavb-style string.
    /// </summary>
    public static string ToLibAvbString(AvbSlotVerifyResult result) => result switch
    {
        AvbSlotVerifyResult.Ok => "OK",
        AvbSlotVerifyResult.ErrorOom => "ERROR_OOM",
        AvbSlotVerifyResult.ErrorIo => "ERROR_IO",
        AvbSlotVerifyResult.ErrorVerification => "ERROR_VERIFICATION",
        AvbSlotVerifyResult.ErrorRollbackIndex => "ERROR_ROLLBACK_INDEX",
        AvbSlotVerifyResult.ErrorPublicKeyRejected => "ERROR_PUBLIC_KEY_REJECTED",
        AvbSlotVerifyResult.ErrorInvalidMetadata => "ERROR_INVALID_METADATA",
        AvbSlotVerifyResult.ErrorUnsupportedVersion => "ERROR_UNSUPPORTED_VERSION",
        AvbSlotVerifyResult.ErrorInvalidArgument => "ERROR_INVALID_ARGUMENT",
        _ => "(unknown)"
    };

    /// <summary>
    /// Converts <see cref="AvbAbFlowResult"/> to a libavb-style string.
    /// </summary>
    public static string ToLibAvbString(AvbAbFlowResult result) => result switch
    {
        AvbAbFlowResult.Ok => "OK",
        AvbAbFlowResult.OkWithVerificationError => "OK_WITH_VERIFICATION_ERROR",
        AvbAbFlowResult.ErrorOom => "ERROR_OOM",
        AvbAbFlowResult.ErrorIo => "ERROR_IO",
        AvbAbFlowResult.ErrorNoBootableSlot => "ERROR_NO_BOOTABLE_SLOTS",
        AvbAbFlowResult.ErrorInvalidArgument => "ERROR_INVALID_ARGUMENT",
        _ => "(unknown)"
    };
}
