
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace FirmwareKit.AVB;
/// <summary>
/// Represents the AVB footer structure found at the end of partitions when 
/// the VBMeta header is not at the start. Equivalent to 'AvbFooter' in libavb.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly record struct AvbFooter
{
    /// <summary>The size of the AVB footer (64 bytes).</summary>
    public const int Size = 64;

    /// <summary>The magic value for the footer structure (0x66425641, "AVBf").</summary>
    public const uint MagicValueLiteral = 0x66425641;

    /// <summary>The length of the magic string.</summary>
    public const int MagicLen = 4;

    /// <summary>The expected major version of the footer.</summary>
    public const uint ExpectedVersionMajor = 1;

    /// <summary>The expected minor version of the footer.</summary>
    public const uint ExpectedVersionMinor = 0;

    /// <summary>Gets the raw magic value from the footer data.</summary>
    public uint MagicValue { get; init; }

    /// <summary>Gets the major version of the footer.</summary>
    public uint VersionMajor { get; init; }

    /// <summary>Gets the minor version of the footer.</summary>
    public uint VersionMinor { get; init; }

    /// <summary>Gets the original size of the image on the partition before AVB metadata was added.</summary>
    public ulong OriginalImageSize { get; init; }

    /// <summary>Gets the absolute offset of the VBMeta block within the partition.</summary>
    public ulong VBMetaOffset { get; init; }

    /// <summary>Gets the size of the VBMeta block in bytes.</summary>
    public ulong VBMetaSize { get; init; }

    private readonly InternalReserved _reserved;

    /// <summary>
    /// Initializes a new instance of the <see cref="AvbFooter"/> structure.
    /// </summary>
    /// <param name="magic">The magic value.</param>
    /// <param name="vMajor">The major version.</param>
    /// <param name="vMinor">The minor version.</param>
    /// <param name="originalImageSize">The original image size.</param>
    /// <param name="vbmetaOffset">The VBMeta block offset.</param>
    /// <param name="vbmetaSize">The VBMeta block size.</param>
    /// <param name="reserved">The reserved bytes.</param>
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

    /// <summary>Gets the human-readable magic string "AVBf".</summary>
    public static string MagicString => "AVBf";

    /// <summary>Gets a value indicating whether the reserved field is valid (all zeros).</summary>
    public bool IsReservedValid
    {
        get
        {
            var temp = _reserved;
            var span = MemoryMarshal.AsBytes(AvbCompat.CreateReadOnlySpanReadOnly(ref temp, 1));
            foreach (var b in span)
            {
                if (b != 0) return false;
            }
            return true;
        }
    }

    /// <summary>Gets a value indicating whether the footer is valid according to its magic and version.</summary>
    public bool IsValid => MagicValue == MagicValueLiteral &&
                          VersionMajor <= ExpectedVersionMajor;

    /// <summary>
    /// Deserializes an <see cref="AvbFooter"/> from a byte span.
    /// </summary>
    /// <param name="data">The byte span containing the 64-byte footer.</param>
    /// <returns>An initialized <see cref="AvbFooter"/> structure.</returns>
    /// <exception cref="ArgumentException">Thrown when the input data is less than 64 bytes.</exception>
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
    /// Writes the footer data to a byte span.
    /// </summary>
    /// <param name="data">The target byte span.</param>
    /// <exception cref="ArgumentException">Thrown when target span is too small.</exception>
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
