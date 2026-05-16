using FirmwareKit.AVB.Utilities;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace FirmwareKit.AVB.Core;

/// <summary>
/// Represents the AVB footer structure found at the end of partitions when
/// the VBMeta header is not at the start. Equivalent to 'AvbFooter' in libavb.
/// <para>表示当VBMeta头不在开始位置时，在分区末尾找到的AVB footer结构。</para>
/// <para>等价于libavb中的'AvbFooter'。</para>
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly record struct AvbFooter
{
    /// <summary>
    /// The size of the AVB footer (64 bytes).
    /// <para>AVB footer的大小（64字节）。</para>
    /// </summary>
    public const int Size = 64;

    /// <summary>
    /// The magic value for the footer structure (0x66425641, "AVBf").
    /// <para>footer结构的魔术值（0x66425641，"AVBf"）。</para>
    /// </summary>
    public const uint MagicValueLiteral = 0x66425641;

    /// <summary>
    /// The length of the magic string.
    /// <para>魔术字符串的长度。</para>
    /// </summary>
    public const int MagicLen = 4;

    /// <summary>
    /// The expected major version of the footer.
    /// <para>期望的footer主版本。</para>
    /// </summary>
    public const uint ExpectedVersionMajor = 1;

    /// <summary>
    /// The expected minor version of the footer.
    /// <para>期望的footer次版本。</para>
    /// </summary>
    public const uint ExpectedVersionMinor = 0;

    /// <summary>
    /// Gets the raw magic value from the footer data.
    /// <para>从footer数据中获取原始魔术值。</para>
    /// </summary>
    public uint MagicValue { get; init; }

    /// <summary>
    /// Gets the major version of the footer.
    /// <para>获取footer的主版本。</para>
    /// </summary>
    public uint VersionMajor { get; init; }

    /// <summary>
    /// Gets the minor version of the footer.
    /// <para>获取footer的次版本。</para>
    /// </summary>
    public uint VersionMinor { get; init; }

    /// <summary>
    /// Gets the original size of the image on the partition before AVB metadata was added.
    /// <para>获取添加AVB元数据之前分区上图像的原始大小。</para>
    /// </summary>
    public ulong OriginalImageSize { get; init; }

    /// <summary>
    /// Gets the absolute offset of the VBMeta block within the partition.
    /// <para>获取分区内VBMeta块的绝对偏移量。</para>
    /// </summary>
    public ulong VBMetaOffset { get; init; }

    /// <summary>
    /// Gets the size of the VBMeta block in bytes.
    /// <para>获取VBMeta块的大小（以字节为单位）。</para>
    /// </summary>
    public ulong VBMetaSize { get; init; }

    private readonly InternalReserved _reserved;

    /// <summary>
    /// Initializes a new instance of the <see cref="AvbFooter"/> structure.
    /// <para>初始化<see cref="AvbFooter"/>结构的新实例。</para>
    /// </summary>
    /// <param name="magic">The magic value.
    /// <para>魔术值。</para></param>
    /// <param name="vMajor">The major version.
    /// <para>主版本。</para></param>
    /// <param name="vMinor">The minor version.
    /// <para>次版本。</para></param>
    /// <param name="originalImageSize">The original image size.
    /// <para>原始图像大小。</para></param>
    /// <param name="vbmetaOffset">The VBMeta block offset.
    /// <para>VBMeta块偏移量。</para></param>
    /// <param name="vbmetaSize">The VBMeta block size.
    /// <para>VBMeta块大小。</para></param>
    /// <param name="reserved">The reserved bytes.
    /// <para>保留字节。</para></param>
    private AvbFooter(
        uint magic, uint vMajor, uint vMinor,
        ulong originalImageSize, ulong vbmetaOffset, ulong vbmetaSize,
        InternalReserved reserved)
    {
        MagicValue = magic;
        VersionMajor = vMajor;
        VersionMinor = vMinor;
        OriginalImageSize = originalImageSize;
        VBMetaOffset = vbmetaOffset;
        VBMetaSize = vbmetaSize;
        _reserved = reserved;
    }

    [StructLayout(LayoutKind.Explicit, Size = 28)]
    private struct InternalReserved { }

    /// <summary>
    /// Gets the human-readable magic string "AVBf".
    /// <para>获取人类可读的魔术字符串"AVBf"。</para>
    /// </summary>
    public static string MagicString => "AVBf";

    /// <summary>
    /// Gets a value indicating whether the reserved field is valid (all zeros).
    /// <para>获取一个值，指示保留字段是否有效（全为零）。</para>
    /// </summary>
    public bool IsReservedValid
    {
        get
        {
            var temp = _reserved;
            var span = AvbCompat.CreateReadOnlySpan(ref temp, 1);
            foreach (var b in span)
            {
                if (b != 0) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the footer is valid according to its magic and version.
    /// <para>根据魔术值和版本获取footer是否有效的值。</para>
    /// </summary>
    public bool IsValid => MagicValue == MagicValueLiteral &&
                          VersionMajor <= ExpectedVersionMajor;

    /// <summary>
    /// Gets a value indicating whether the footer is structurally valid.
    /// <para>获取footer在结构上是否有效的值。</para>
    /// </summary>
    public bool IsFullyValid => IsValid && IsReservedValid;

    /// <summary>
    /// Deserializes an <see cref="AvbFooter"/> from a byte span.
    /// <para>从字节跨度反序列化<see cref="AvbFooter"/>。</para>
    /// </summary>
    /// <param name="data">The byte span containing the 64-byte footer.
    /// <para>包含64字节footer的字节跨度。</para></param>
    /// <returns>An initialized <see cref="AvbFooter"/> structure.
    /// <para>初始化的<see cref="AvbFooter"/>结构。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the input data is less than 64 bytes.
    /// <para>当输入数据小于64字节时抛出。</para></exception>
    public static AvbFooter FromBytes(ReadOnlySpan<byte> data)
    {
        return data.Length < Size
            ? throw new ArgumentException($"Data size {data.Length} is less than {Size}")
            : new AvbFooter(
            BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]),
            BinaryPrimitives.ReadUInt32BigEndian(data[4..8]),
            BinaryPrimitives.ReadUInt32BigEndian(data[8..12]),
            BinaryPrimitives.ReadUInt64BigEndian(data[12..20]),
            BinaryPrimitives.ReadUInt64BigEndian(data[20..28]),
            BinaryPrimitives.ReadUInt64BigEndian(data[28..36]),
            MemoryMarshal.Read<InternalReserved>(data[36..64])
        );
    }

    /// <summary>
    /// Attempts to parse a footer from a byte span.
    /// <para>尝试从字节跨度解析footer。</para>
    /// </summary>
    /// <param name="data">The byte span containing the 64-byte footer.
    /// <para>包含64字节footer的字节跨度。</para></param>
    /// <param name="footer">When this method returns, contains the parsed footer if successful.
    /// <para>当此方法返回时，如果成功则包含解析的footer。</para></param>
    /// <returns>Returns true if successfully parsed and the magic value is correct; otherwise, false.
    /// <para>如果成功解析且魔术值正确则返回true，否则返回false。</para></returns>
    public static bool TryFromBytes(ReadOnlySpan<byte> data, out AvbFooter footer)
    {
        footer = default;

        try
        {
            footer = FromBytes(data);
            return footer.IsValid;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Writes the footer data to a byte span.
    /// <para>将footer数据写入字节跨度。</para>
    /// </summary>
    /// <param name="data">The target byte span.
    /// <para>目标字节跨度。</para></param>
    /// <exception cref="ArgumentException">Thrown when target span is too small.
    /// <para>当目标跨度太小时抛出。</para></exception>
    public void ToBytes(Span<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException($"Buffer size {data.Length} is less than {Size}");
        }

        BinaryPrimitives.WriteUInt32LittleEndian(data[0..4], MagicValue);
        BinaryPrimitives.WriteUInt32BigEndian(data[4..8], VersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data[8..12], VersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data[12..20], OriginalImageSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[20..28], VBMetaOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[28..36], VBMetaSize);
        var tempReserved = _reserved;
#if NET8_0_OR_GREATER
        MemoryMarshal.Write(data[36..64], in tempReserved);
#else
        MemoryMarshal.Write(data[36..64], ref tempReserved);
#endif
    }
}