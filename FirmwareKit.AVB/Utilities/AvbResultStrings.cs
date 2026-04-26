using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Utilities;

/// <summary>
/// Converts AVB result enums to stable libavb-style string values.
/// <para>将AVB结果枚举转换为稳定的libavb风格字符串值。</para>
/// </summary>
public static class AvbResultStrings
{
    /// <summary>
    /// Converts <see cref="AvbSlotVerifyResult"/> to a libavb-style string.
    /// <para>将<see cref="AvbSlotVerifyResult"/>转换为libavb风格的字符串。</para>
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
    /// <para>将<see cref="AvbAbFlowResult"/>转换为libavb风格的字符串。</para>
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

    /// <summary>
    /// Converts <see cref="AvbVBMetaVerifyResult"/> to a libavb-style string.
    /// <para>将<see cref="AvbVBMetaVerifyResult"/>转换为libavb风格的字符串。</para>
    /// </summary>
    public static string ToLibAvbString(AvbVBMetaVerifyResult result) => result switch
    {
        AvbVBMetaVerifyResult.Ok => "OK",
        AvbVBMetaVerifyResult.OkNotSigned => "OK_NOT_SIGNED",
        AvbVBMetaVerifyResult.InvalidVBMetaHeader => "INVALID_VBMETA_HEADER",
        AvbVBMetaVerifyResult.UnsupportedVersion => "UNSUPPORTED_VERSION",
        AvbVBMetaVerifyResult.HashMismatch => "HASH_MISMATCH",
        AvbVBMetaVerifyResult.SignatureMismatch => "SIGNATURE_MISMATCH",
        _ => "(unknown)"
    };
}