
using Force.Crc32;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace FirmwareKit.AVB.Ab;
/// <summary>
/// Contains data about a single slot in the A/B boot flow.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbAbSlotData
{
    /// <summary>
    /// The priority of the slot (0-15). A higher value means higher priority.
    /// <para>槽的优先级（0-15）。值越高表示优先级越高。</para>
    /// </summary>
    public byte Priority;
    /// <summary>
    /// The number of remaining boot attempts (0-7).
    /// <para>剩余启动尝试次数（0-7）。</para>
    /// </summary>
    public byte TriesRemaining;
    /// <summary>
    /// Non-zero if the slot has been successfully booted.
    /// <para>如果槽已成功启动则非零。</para>
    /// </summary>
    public byte SuccessfulBoot;
    private readonly byte _reserved;

    /// <summary>
    /// The maximum priority value (15).
    /// <para>最大优先级值（15）。</para>
    /// </summary>
    public const byte MaxPriority = 15;
    /// <summary>
    /// The maximum number of tries remaining (7).
    /// <para>最大剩余尝试次数（7）。</para>
    /// </summary>
    public const byte MaxTriesRemaining = 7;

    /// <summary>
    /// Serializes the slot data to a byte span.
    /// <para>将槽数据序列化为字节跨度。</para>
    /// </summary>
    public readonly void ToBytes(Span<byte> data)
    {
        data[0] = Priority;
        data[1] = TriesRemaining;
        data[2] = SuccessfulBoot;
        data[3] = 0;
    }

    /// <summary>
    /// Deserializes the slot data from a byte span.
    /// <para>从字节跨度反序列化槽数据。</para>
    /// </summary>
    public static AvbAbSlotData FromBytes(ReadOnlySpan<byte> data)
    {
        return new AvbAbSlotData
        {
            Priority = data[0],
            TriesRemaining = data[1],
            SuccessfulBoot = data[2]
        };
    }
}

/// <summary>
/// A/B metadata structure used to track boot slots and their states.
/// Equivalent to 'AvbABData' in libavb_ab.
/// <para>用于跟踪启动槽及其状态的A/B元数据结构。</para>
/// <para>等价于libavb_ab中的'AvbABData'。</para>
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbAbData
{
    /// <summary>
    /// The magic string used to identify A/B metadata ("\0AB0").
    /// <para>用于识别A/B元数据的魔术字符串（"\0AB0"）。</para>
    /// </summary>
    public const string Magic = "\0AB0";
    /// <summary>
    /// Length of the magic string.
    /// <para>魔术字符串的长度。</para>
    /// </summary>
    public const int MagicLen = 4;
    /// <summary>
    /// The major version of the A/B metadata format.
    /// <para>A/B元数据格式的主版本。</para>
    /// </summary>
    public const byte MajorVersion = 1;
    /// <summary>
    /// The minor version of the A/B metadata format.
    /// <para>A/B元数据格式的次版本。</para>
    /// </summary>
    public const byte MinorVersion = 0;
    /// <summary>
    /// The total size of the <see cref="AvbAbData"/> structure (32 bytes).
    /// <para><see cref="AvbAbData"/>结构的总大小（32字节）。</para>
    /// </summary>
    public const int Size = 32;

    /// <summary>
    /// The magic bytes.
    /// <para>魔术字节。</para>
    /// </summary>
    public byte[] MagicBytes; // 4 bytes
    /// <summary>
    /// The major version number.
    /// <para>主版本号。</para>
    /// </summary>
    public byte VersionMajor;
    /// <summary>
    /// The minor version number.
    /// <para>次版本号。</para>
    /// </summary>
    public byte VersionMinor;
    private ushort _reserved1;
    /// <summary>
    /// Metadata for slot A.
    /// <para>槽A的元数据。</para>
    /// </summary>
    public AvbAbSlotData SlotA;
    /// <summary>
    /// Metadata for slot B.
    /// <para>槽B的元数据。</para>
    /// </summary>
    public AvbAbSlotData SlotB;
    private byte[] _reserved2; // 12 bytes
    /// <summary>
    /// CRC32 checksum of the metadata (excluding the CRC32 field itself).
    /// <para>元数据的CRC32校验和（不包括CRC32字段本身）。</para>
    /// </summary>
    public uint Crc32;

    /// <summary>
    /// Creates a default A/B metadata structure.
    /// <para>创建默认的A/B元数据结构。</para>
    /// </summary>
    public static AvbAbData CreateDefault()
    {
        return new AvbAbData
        {
            MagicBytes = System.Text.Encoding.ASCII.GetBytes(Magic),
            VersionMajor = MajorVersion,
            VersionMinor = MinorVersion,
            SlotA = new AvbAbSlotData { Priority = AvbAbSlotData.MaxPriority, TriesRemaining = AvbAbSlotData.MaxTriesRemaining, SuccessfulBoot = 0 },
            SlotB = new AvbAbSlotData { Priority = AvbAbSlotData.MaxPriority - 1, TriesRemaining = AvbAbSlotData.MaxTriesRemaining, SuccessfulBoot = 0 },
            _reserved2 = new byte[12]
        };
    }

    /// <summary>
    /// Serializes the A/B metadata to a byte array and computes the CRC32.
    /// <para>将A/B元数据序列化为字节数组并计算CRC32。</para>
    /// </summary>
    public readonly byte[] ToBytes()
    {
        var data = new byte[Size];
        (MagicBytes ?? []).CopyTo(data, 0);
        data[4] = VersionMajor;
        data[5] = VersionMinor;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(6, 2), _reserved1);
        SlotA.ToBytes(data.AsSpan(8, 4));
        SlotB.ToBytes(data.AsSpan(12, 4));
        if (_reserved2 != null && _reserved2.Length >= 12)
        {
            _reserved2.AsSpan(0, 12).CopyTo(data.AsSpan(16, 12));
        }

        // Compute CRC32 for the first 28 bytes
        var crc = AvbCrc32.Compute(data.AsSpan(0, 28));
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), crc);

        return data;
    }

    /// <summary>
    /// Deserializes the A/B metadata from a byte span.
    /// <para>从字节跨度反序列化A/B元数据。</para>
    /// </summary>
    public static AvbAbData FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException("Data too small for AvbAbData");
        }

        var ab = new AvbAbData
        {
            MagicBytes = data[0..4].ToArray(),
            VersionMajor = data[4],
            VersionMinor = data[5],
            _reserved1 = BinaryPrimitives.ReadUInt16BigEndian(data[6..8]),
            SlotA = AvbAbSlotData.FromBytes(data[8..12]),
            SlotB = AvbAbSlotData.FromBytes(data[12..16]),
            _reserved2 = data[16..28].ToArray(),
            Crc32 = BinaryPrimitives.ReadUInt32BigEndian(data[28..32])
        };

        return ab;
    }

    /// <summary>
    /// Verifies serialized A/B metadata and returns parsed host-order data.
    /// <para>验证序列化的A/B元数据并返回解析后的小端序数据。</para>
    /// </summary>
    public static bool TryVerifyAndByteswap(ReadOnlySpan<byte> data, out AvbAbData output)
    {
        output = default;

        if (data.Length < Size)
        {
            return false;
        }

        try
        {
            var parsed = FromBytes(data.Slice(0, Size));
            if (!parsed.IsValid())
            {
                return false;
            }

            output = parsed;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Updates CRC and returns byteswapped serialized representation.
    /// <para>更新CRC并返回字节交换的序列化表示。</para>
    /// </summary>
    public static byte[] UpdateCrcAndByteswap(AvbAbData data) => data.ToBytes();

    /// <summary>
    /// Checks if the A/B metadata is valid (magic and CRC32 match).
    /// <para>检查A/B元数据是否有效（魔术和CRC32匹配）。</para>
    /// </summary>
    public readonly bool IsValid()
    {
        if (MagicBytes == null || System.Text.Encoding.ASCII.GetString(MagicBytes) != Magic)
        {
            return false;
        }

        if (VersionMajor > MajorVersion)
        {
            return false;
        }

        var expectedCrc = AvbCrc32.Compute(ToBytes().AsSpan(0, 28));
        return Crc32 == expectedCrc;
    }
}

/// <summary>
/// Provides CRC32 computation consistent with libavb's implementation.
/// <para>提供与libavb实现一致的CRC32计算。</para>
/// </summary>
public static class AvbCrc32
{
    /// <summary>
    /// Computes the CRC32 checksum for the specified data buffer.
    /// <para>计算指定数据缓冲区的CRC32校验和。</para>
    /// </summary>
    /// <param name="data">The data to compute the checksum for.
    /// <para>要计算校验和的数据。</para></param>
    /// <returns>The computed CRC32 value.
    /// <para>计算出的CRC32值。</para></returns>
    public static uint Compute(ReadOnlySpan<byte> data) => Crc32Algorithm.Compute(data.ToArray());
}