
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace FirmwareKit.AVB;
/// <summary>
/// Represents the structure of the VBMeta image header.
/// Equivalent to 'AvbVBMetaImageHeader' in libavb.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbVBMetaImageHeader
{
    /// <summary>The size of the VBMeta header (256 bytes).</summary>
    public const int Size = 256;

    /// <summary>The magic value for the VBMeta header ("AVB0").</summary>
    public const string MagicHeader = "AVB0";

    /// <summary>The length of the magic string.</summary>
    public const int MagicLen = 4;

    /// <summary>The size of the release string field.</summary>
    public const int ReleaseStringSize = 48;

    /// <summary>The expected major version of the VBMeta image.</summary>
    public const uint ExpectedVersionMajor = AvbVersion.Major;

    /// <summary>The maximum supported minor version of the VBMeta image.</summary>
    public const uint MaxSupportedVersionMinor = AvbVersion.Minor;

    /// <summary>The expected sub-version of the VBMeta image.</summary>
    public const uint ExpectedVersionSub = AvbVersion.Sub;

    private uint _magic0;

    /// <summary>Gets the required major version of libavb to parse this image.</summary>
    public uint RequiredLibavbVersionMajor { get; init; }

    /// <summary>Gets the required minor version of libavb to parse this image.</summary>
    public uint RequiredLibavbVersionMinor { get; init; }

    /// <summary>Gets the size of the authentication data block.</summary>
    public ulong AuthenticationDataBlockSize { get; init; }

    /// <summary>Gets the size of the auxiliary data block.</summary>
    public ulong AuxiliaryDataBlockSize { get; init; }

    /// <summary>Gets the algorithm type used for this image.</summary>
    public uint AlgorithmType { get; init; }

    /// <summary>Gets the offset of the hash within the authentication block.</summary>
    public ulong HashOffset { get; init; }

    /// <summary>Gets the size of the hash.</summary>
    public ulong HashSize { get; init; }

    /// <summary>Gets the offset of the signature within the authentication block.</summary>
    public ulong SignatureOffset { get; init; }

    /// <summary>Gets the size of the signature.</summary>
    public ulong SignatureSize { get; init; }

    /// <summary>Gets the offset of the public key within the auxiliary block.</summary>
    public ulong PublicKeyOffset { get; init; }

    /// <summary>Gets the size of the public key.</summary>
    public ulong PublicKeySize { get; init; }

    /// <summary>Gets the offset of the public key metadata within the auxiliary block.</summary>
    public ulong PublicKeyMetadataOffset { get; init; }

    /// <summary>
    /// Gets the size of the public key metadata. 
    /// Must be set to zero if there is no public key metadata.
    /// </summary>
    public ulong PublicKeyMetadataSize { get; init; }

    /// <summary>Gets the offset of the descriptors within the auxiliary block.</summary>
    public ulong DescriptorsOffset { get; init; }

    /// <summary>Gets the size of the descriptors block.</summary>
    public ulong DescriptorsSize { get; init; }

    /// <summary>
    /// Gets the rollback index which can be used to prevent rollback to older versions.
    /// </summary>
    public ulong RollbackIndex { get; init; }

    /// <summary>
    /// Gets the flags for this image from the <see cref="AvbVBMetaImageFlags"/> enumeration. 
    /// This must be set to zero if the vbmeta image is not a top-level image.
    /// </summary>
    public uint Flags { get; init; }

    /// <summary>
    /// Gets the location of the rollback index defined in this header.
    /// Only valid for the main vbmeta. For chained partitions, the rollback
    /// index location must be specified in the <see cref="AvbChainPartitionDescriptor"/>
    /// and this value must be set to 0.
    /// </summary>
    public uint RollbackIndexLocation { get; init; }

    private InternalReleaseString _releaseString;
    private InternalReserved _reserved;

    [StructLayout(LayoutKind.Explicit, Size = ReleaseStringSize)]
    private struct InternalReleaseString { }
    [StructLayout(LayoutKind.Explicit, Size = 80)]
    private struct InternalReserved { }

    /// <summary>Gets the human-readable magic string "AVB0".</summary>
    public readonly string Magic => Encoding.ASCII.GetString(BitConverter.GetBytes(_magic0));

    /// <summary>Gets a value indicating whether the reserved field is valid (all zeros).</summary>
    public readonly bool IsReservedValid
    {
        get
        {
            var temp = _reserved;
            var span = MemoryMarshal.AsBytes(AvbCompat.CreateReadOnlySpanReadOnly(ref temp, 1));
            foreach (var b in span)
            {
                if (b != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }

    /// <summary>Gets the release string associated with the image.</summary>
    public readonly string ReleaseString
    {
        get
        {
            var temp = _releaseString;
            var span = MemoryMarshal.AsBytes(AvbCompat.CreateReadOnlySpanReadOnly(ref temp, 1));
            var length = span.IndexOf((byte)0);
            if (length == -1)
            {
                length = ReleaseStringSize;
            }

            return Encoding.ASCII.GetString(span[..length].ToArray());
        }
    }

    /// <summary>Gets a value indicating whether the release string is valid (ends with a NUL byte).</summary>
    public readonly bool IsReleaseStringValid
    {
        get
        {
            var temp = _releaseString;
            var span = MemoryMarshal.AsBytes(AvbCompat.CreateReadOnlySpanReadOnly(ref temp, 1));
            return span[ReleaseStringSize - 1] == 0;
        }
    }

    /// <summary>
    /// Deserializes an <see cref="AvbVBMetaImageHeader"/> from a byte span.
    /// </summary>
    /// <param name="data">The byte span containing the 256-byte header.</param>
    /// <returns>An initialized <see cref="AvbVBMetaImageHeader"/> structure.</returns>
    /// <exception cref="ArgumentException">Thrown when the input data is less than 256 bytes.</exception>
    public static AvbVBMetaImageHeader FromBytes(ReadOnlySpan<byte> data)
    {
        return data.Length < Size
            ? throw new ArgumentException($"Data size {data.Length} is less than {Size}")
            : new AvbVBMetaImageHeader
            {
                _magic0 = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]),
                RequiredLibavbVersionMajor = BinaryPrimitives.ReadUInt32BigEndian(data[4..8]),
                RequiredLibavbVersionMinor = BinaryPrimitives.ReadUInt32BigEndian(data[8..12]),
                AuthenticationDataBlockSize = BinaryPrimitives.ReadUInt64BigEndian(data[12..20]),
                AuxiliaryDataBlockSize = BinaryPrimitives.ReadUInt64BigEndian(data[20..28]),
                AlgorithmType = BinaryPrimitives.ReadUInt32BigEndian(data[28..32]),
                HashOffset = BinaryPrimitives.ReadUInt64BigEndian(data[32..40]),
                HashSize = BinaryPrimitives.ReadUInt64BigEndian(data[40..48]),
                SignatureOffset = BinaryPrimitives.ReadUInt64BigEndian(data[48..56]),
                SignatureSize = BinaryPrimitives.ReadUInt64BigEndian(data[56..64]),
                PublicKeyOffset = BinaryPrimitives.ReadUInt64BigEndian(data[64..72]),
                PublicKeySize = BinaryPrimitives.ReadUInt64BigEndian(data[72..80]),
                PublicKeyMetadataOffset = BinaryPrimitives.ReadUInt64BigEndian(data[80..88]),
                PublicKeyMetadataSize = BinaryPrimitives.ReadUInt64BigEndian(data[88..96]),
                DescriptorsOffset = BinaryPrimitives.ReadUInt64BigEndian(data[96..104]),
                DescriptorsSize = BinaryPrimitives.ReadUInt64BigEndian(data[104..112]),
                RollbackIndex = BinaryPrimitives.ReadUInt64BigEndian(data[112..120]),
                Flags = BinaryPrimitives.ReadUInt32BigEndian(data[120..124]),
                RollbackIndexLocation = BinaryPrimitives.ReadUInt32BigEndian(data[124..128]),
                _releaseString = MemoryMarshal.Read<InternalReleaseString>(data[128..176]),
                _reserved = MemoryMarshal.Read<InternalReserved>(data[176..256])
            };
    }

    /// <summary>
    /// Serializes the <see cref="AvbVBMetaImageHeader"/> into a byte span.
    /// </summary>
    /// <param name="data">The destination byte span (must be at least 256 bytes).</param>
    /// <exception cref="ArgumentException">Thrown when the destination buffer is too small.</exception>
    public readonly void ToBytes(Span<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException($"Buffer size {data.Length} is less than {Size}");
        }
        // A lot of binary data write
        BinaryPrimitives.WriteUInt32LittleEndian(data[0..4], _magic0);
        BinaryPrimitives.WriteUInt32BigEndian(data[4..8], RequiredLibavbVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data[8..12], RequiredLibavbVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data[12..20], AuthenticationDataBlockSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[20..28], AuxiliaryDataBlockSize);
        BinaryPrimitives.WriteUInt32BigEndian(data[28..32], AlgorithmType);
        BinaryPrimitives.WriteUInt64BigEndian(data[32..40], HashOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[40..48], HashSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[48..56], SignatureOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[56..64], SignatureSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[64..72], PublicKeyOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[72..80], PublicKeySize);
        BinaryPrimitives.WriteUInt64BigEndian(data[80..88], PublicKeyMetadataOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[88..96], PublicKeyMetadataSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[96..104], DescriptorsOffset);
        BinaryPrimitives.WriteUInt64BigEndian(data[104..112], DescriptorsSize);
        BinaryPrimitives.WriteUInt64BigEndian(data[112..120], RollbackIndex);
        BinaryPrimitives.WriteUInt32BigEndian(data[120..124], Flags);
        BinaryPrimitives.WriteUInt32BigEndian(data[124..128], RollbackIndexLocation);
        var tempRelease = _releaseString;
        var tempReserved = _reserved;
#if NET8_0_OR_GREATER
        MemoryMarshal.Write(data[128..176], in tempRelease);
        MemoryMarshal.Write(data[176..256], in tempReserved);
#else
        MemoryMarshal.Write(data[128..176], ref tempRelease);
        MemoryMarshal.Write(data[176..256], ref tempReserved);
#endif
    }
}



