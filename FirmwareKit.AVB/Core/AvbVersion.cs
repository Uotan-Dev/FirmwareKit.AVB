namespace FirmwareKit.AVB;

/// <summary>
/// libavb version constants and helpers.
/// Equivalent to values provided by avb_version.h/avb_version.c.
/// </summary>
public static class AvbVersion
{
    /// <summary>Major version of this managed libavb implementation.</summary>
    public const uint Major = 1;

    /// <summary>Minor version of this managed libavb implementation.</summary>
    public const uint Minor = 3;

    /// <summary>Sub-version of this managed libavb implementation.</summary>
    public const uint Sub = 0;

    /// <summary>
    /// String representation of the libavb version.
    /// </summary>
    public const string VersionString = "1.3.0";

    /// <summary>
    /// Returns whether a VBMeta required version is compatible with this runtime.
    /// </summary>
    public static bool IsCompatible(uint requiredMajor, uint requiredMinor) =>
        requiredMajor == Major && requiredMinor <= Minor;
}
