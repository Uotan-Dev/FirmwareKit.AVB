namespace FirmwareKit.AVB.Core;

/// <summary>
/// libavb version constants and helpers.
/// Equivalent to values provided by avb_version.h/avb_version.c.
/// <para>libavb版本常量和助手。</para>
/// <para>等价于avb_version.h/avb_version.c提供的值。</para>
/// </summary>
public static class AvbVersion
{
    /// <summary>
    /// Major version of this managed libavb implementation.
    /// <para>此托管libavb实现的主版本号。</para>
    /// </summary>
    public const uint Major = 1;

    /// <summary>
    /// Minor version of this managed libavb implementation.
    /// <para>此托管libavb实现的次版本号。</para>
    /// </summary>
    public const uint Minor = 3;

    /// <summary>
    /// Sub-version of this managed libavb implementation.
    /// <para>此托管libavb实现的子版本号。</para>
    /// </summary>
    public const uint Sub = 0;

    /// <summary>
    /// String representation of the libavb version.
    /// <para>libavb版本的字符串表示。</para>
    /// </summary>
    public const string VersionString = "1.3.0";

    /// <summary>
    /// Checks whether a VBMeta required version is compatible with this runtime.
    /// <para>检查VBMeta所需版本是否与此运行时兼容。</para>
    /// </summary>
    /// <param name="requiredMajor">The required major version.
    /// <para>所需的主版本。</para></param>
    /// <param name="requiredMinor">The required minor version.
    /// <para>所需的次版本。</para></param>
    /// <returns>Returns true if the current runtime version can parse the required VBMeta version.
    /// <para>如果当前运行时版本可以解析所需的VBMeta版本，则返回true。</para></returns>
    public static bool IsCompatible(uint requiredMajor, uint requiredMinor) =>
        requiredMajor == Major && requiredMinor <= Minor;
}