using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.VBMeta;

namespace FirmwareKit.AVB.Core;

/// <summary>
/// Managed helpers equivalent to libavb_user verification/verity controls.
/// <para>等效于libavb_user验证/校验控制的托管助手。</para>
/// </summary>
public static class AvbUser
{
    private const int VbmetaHeaderSize = AvbVBMetaImageHeader.Size;
    private const int FooterSize = AvbFooter.Size;

    /// <summary>
    /// Reads whether AVB verification is enabled for a slot.
    /// <para>读取槽位是否启用了AVB验证。</para>
    /// </summary>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for partition I/O.
    /// <para>用于分区I/O的<see cref="IAvbOps"/>实例。</para></param>
    /// <param name="abSuffix">The A/B slot suffix (e.g., "_a" or "_b").
    /// <para>A/B槽位后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="enabled">On success, receives whether verification is enabled.
    /// <para>成功时，接收是否启用验证。</para></param>
    /// <returns>Returns true if successfully read; otherwise, false.
    /// <para>如果成功读取则返回true，否则返回false。</para></returns>
    public static bool TryGetVerificationEnabled(IAvbOps ops, string abSuffix, out bool enabled)
    {
        enabled = false;
        if (!TryLoadTopLevelVBMetaHeader(ops, abSuffix, out var partitionName, out var headerBytes, out _))
        {
            return false;
        }

        var header = AvbVBMetaImageHeader.FromBytes(headerBytes);
        if (header.Magic != AvbVBMetaImageHeader.MagicHeader)
        {
            return false;
        }

        enabled = (header.Flags & (uint)AvbVBMetaImageFlags.VerificationDisabled) == 0;
        return true;
    }

    /// <summary>
    /// Sets AVB verification enabled/disabled for a slot.
    /// <para>设置槽位的AVB验证启用/禁用状态。</para>
    /// </summary>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for partition I/O.
    /// <para>用于分区I/O的<see cref="IAvbOps"/>实例。</para></param>
    /// <param name="abSuffix">The A/B slot suffix (e.g., "_a" or "_b").
    /// <para>A/B槽位后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="enableVerification">True to enable verification, false to disable.
    /// <para>为true时启用验证，为false时禁用验证。</para></param>
    /// <returns>Returns true if successfully written; otherwise, false.
    /// <para>如果成功写入则返回true，否则返回false。</para></returns>
    public static bool TrySetVerificationEnabled(IAvbOps ops, string abSuffix, bool enableVerification)
    {
        if (!TryLoadTopLevelVBMetaHeader(ops, abSuffix, out var partitionName, out var headerBytes, out var vbmetaOffset))
        {
            return false;
        }

        var header = AvbVBMetaImageHeader.FromBytes(headerBytes);
        if (header.Magic != AvbVBMetaImageHeader.MagicHeader)
        {
            return false;
        }

        var flags = header.Flags & ~(uint)AvbVBMetaImageFlags.VerificationDisabled;
        if (!enableVerification)
        {
            flags |= (uint)AvbVBMetaImageFlags.VerificationDisabled;
        }

        var updated = header with { Flags = flags };
        updated.ToBytes(headerBytes);

        return ops.WriteToPartition(partitionName, vbmetaOffset, VbmetaHeaderSize, headerBytes) == AvbIOResult.Ok;
    }

    /// <summary>
    /// Reads whether dm-verity hashtree is enabled for a slot.
    /// <para>读取槽位是否启用了dm-verity哈希树。</para>
    /// </summary>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for partition I/O.
    /// <para>用于分区I/O的<see cref="IAvbOps"/>实例。</para></param>
    /// <param name="abSuffix">The A/B slot suffix (e.g., "_a" or "_b").
    /// <para>A/B槽位后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="enabled">On success, receives whether dm-verity is enabled.
    /// <para>成功时，接收是否启用dm-verity。</para></param>
    /// <returns>Returns true if successfully read; otherwise, false.
    /// <para>如果成功读取则返回true，否则返回false。</para></returns>
    public static bool TryGetVerityEnabled(IAvbOps ops, string abSuffix, out bool enabled)
    {
        enabled = false;
        if (!TryLoadTopLevelVBMetaHeader(ops, abSuffix, out _, out var headerBytes, out _))
        {
            return false;
        }

        var header = AvbVBMetaImageHeader.FromBytes(headerBytes);
        if (header.Magic != AvbVBMetaImageHeader.MagicHeader)
        {
            return false;
        }

        enabled = (header.Flags & (uint)AvbVBMetaImageFlags.HashtreeDisabled) == 0;
        return true;
    }

    /// <summary>
    /// Sets dm-verity hashtree enabled/disabled for a slot.
    /// <para>设置槽位的dm-verity哈希树启用/禁用状态。</para>
    /// </summary>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for partition I/O.
    /// <para>用于分区I/O的<see cref="IAvbOps"/>实例。</para></param>
    /// <param name="abSuffix">The A/B slot suffix (e.g., "_a" or "_b").
    /// <para>A/B槽位后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="enableVerity">True to enable dm-verity, false to disable.
    /// <para>为true时启用dm-verity，为false时禁用dm-verity。</para></param>
    /// <returns>Returns true if successfully written; otherwise, false.
    /// <para>如果成功写入则返回true，否则返回false。</para></returns>
    public static bool TrySetVerityEnabled(IAvbOps ops, string abSuffix, bool enableVerity)
    {
        if (!TryLoadTopLevelVBMetaHeader(ops, abSuffix, out var partitionName, out var headerBytes, out var vbmetaOffset))
        {
            return false;
        }

        var header = AvbVBMetaImageHeader.FromBytes(headerBytes);
        if (header.Magic != AvbVBMetaImageHeader.MagicHeader)
        {
            return false;
        }

        var flags = header.Flags & ~(uint)AvbVBMetaImageFlags.HashtreeDisabled;
        if (!enableVerity)
        {
            flags |= (uint)AvbVBMetaImageFlags.HashtreeDisabled;
        }

        var updated = header with { Flags = flags };
        updated.ToBytes(headerBytes);

        return ops.WriteToPartition(partitionName, vbmetaOffset, VbmetaHeaderSize, headerBytes) == AvbIOResult.Ok;
    }

    private static bool TryLoadTopLevelVBMetaHeader(
        IAvbOps ops,
        string abSuffix,
        out string partitionName,
        out byte[] vbmetaHeader,
        out long vbmetaOffset)
    {
        partitionName = "vbmeta" + abSuffix;
        vbmetaOffset = 0;
        vbmetaHeader = new byte[VbmetaHeaderSize];

        if (!TryReadExact(ops, partitionName, vbmetaOffset, vbmetaHeader))
        {
            partitionName = "boot" + abSuffix;
            var footerBytes = new byte[FooterSize];
            if (!TryReadExact(ops, partitionName, -FooterSize, footerBytes))
            {
                return false;
            }

            var footer = AvbFooter.FromBytes(footerBytes);
            if (!footer.IsValid)
            {
                return false;
            }

            vbmetaOffset = (long)footer.VBMetaOffset;
            if (!TryReadExact(ops, partitionName, vbmetaOffset, vbmetaHeader))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryReadExact(IAvbOps ops, string partitionName, long offset, Span<byte> buffer)
    {
        var io = ops.ReadFromPartition(partitionName, offset, buffer.Length, buffer, out var bytesRead);
        return io == AvbIOResult.Ok && bytesRead == buffer.Length;
    }
}