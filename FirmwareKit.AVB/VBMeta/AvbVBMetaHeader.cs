using FirmwareKit.AVB.Core;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace FirmwareKit.AVB.VBMeta;
/// <summary>
/// Represents the structure of the VBMeta image header.
/// Equivalent to 'AvbVBMetaImageHeader' in libavb.
/// <para>表示VBMeta镜像头的结构。</para>
/// <para>等价于libavb中的'AvbVBMetaImageHeader'。</para>
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbVBMetaImageHeader
{
    /// <summary>
    /// The size of the VBMeta header (256 bytes).
    /// <para>VBMeta头的大小（256字节）。</para>
    /// </summary>
    public const int Size = 256;

    /// <summary>
    /// The magic value for the VBMeta header ("AVB0").
    /// <para>VBMeta头的魔术值（"AVB0"）。</para>
    /// </summary>
    public const string MagicHeader = "AVB0";

    /// <summary>
    /// The length of the magic string.
    /// <para>魔术字符串的长度。</para>
    /// </summary>
    public const int MagicLen = 4;

    /// <summary>
    /// The size of the release string field.
    /// <para>发布字符串字段的大小。</para>
    /// </summary>
    public const int ReleaseStringSize = 48;

    /// <summary>
    /// The expected major version of the VBMeta image.
    /// <para>VBMeta镜像的预期主版本。</para>
    /// </summary>
    public const uint ExpectedVersionMajor = AvbVersion.Major;

    /// <summary>
    /// The maximum supported minor version of the VBMeta image.
    /// <para>VBMeta镜像支持的最大次版本。</para>
    /// </summary>
    public const uint MaxSupportedVersionMinor = AvbVersion.Minor;

    /// <summary>
    /// The expected sub-version of the VBMeta image.
    /// <para>VBMeta镜像的预期子版本。</para>
    /// </summary>
    public const uint ExpectedVersionSub = AvbVersion.Sub;

    private uint _magic0;

    /// <summary>
    /// Gets the required major version of libavb to parse this image.
    /// <para>获取解析此镜像所需的libavb主版本。</para>
    /// </summary>
    public uint RequiredLibavbVersionMajor { get; init; }

    /// <summary>
    /// Gets the required minor version of libavb to parse this image.
    /// <para>获取解析此镜像所需的libavb次版本。</para>
    /// </summary>
    public uint RequiredLibavbVersionMinor { get; init; }

    /// <summary>
    /// Gets the size of the authentication data block.
    /// <para>获取认证数据块的大小。</para>
    /// </summary>
    public ulong AuthenticationDataBlockSize { get; init; }

    /// <summary>
    /// Gets the size of the auxiliary data block.
    /// <para>获取辅助数据块的大小。</para>
    /// </summary>
    public ulong AuxiliaryDataBlockSize { get; init; }

    /// <summary>
    /// Gets the algorithm type used for this image.
    /// <para>获取为此镜像使用的算法类型。</para>
    /// </summary>
    public uint AlgorithmType { get; init; }

    /// <summary>
    /// Gets the offset of the hash within the authentication block.
    /// <para>获取认证块中哈希的偏移量。</para>
    /// </summary>
    public ulong HashOffset { get; init; }

    /// <summary>
    /// Gets the size of the hash.
    /// <para>获取哈希的大小。</para>
    /// </summary>
    public ulong HashSize { get; init; }

    /// <summary>
    /// Gets the offset of the signature within the authentication block.
    /// <para>获取认证块中签名的偏移量。</para>
    /// </summary>
    public ulong SignatureOffset { get; init; }

    /// <summary>
    /// Gets the size of the signature.
    /// <para>获取签名的大小。</para>
    /// </summary>
    public ulong SignatureSize { get; init; }

    /// <summary>
    /// Gets the offset of the public key within the auxiliary block.
    /// <para>获取辅助块中公钥的偏移量。</para>
    /// </summary>
    public ulong PublicKeyOffset { get; init; }

    /// <summary>
    /// Gets the size of the public key.
    /// <para>获取公钥的大小。</para>
    /// </summary>
    public ulong PublicKeySize { get; init; }

    /// <summary>
    /// Gets the offset of the public key metadata within the auxiliary block.
    /// <para>获取辅助块中公钥元数据的偏移量。</para>
    /// </summary>
    public ulong PublicKeyMetadataOffset { get; init; }

    /// <summary>
    /// Gets the size of the public key metadata.
    /// Must be set to zero if there is no public key metadata.
    /// <para>获取公钥元数据的大小。</para>
    /// <para>如果没有公钥元数据，则必须设置为零。</para>
    /// </summary>
    public ulong PublicKeyMetadataSize { get; init; }

    /// <summary>
    /// Gets the offset of the descriptors within the auxiliary block.
    /// <para>获取辅助块中描述符的偏移量。</para>
    /// </summary>
    public ulong DescriptorsOffset { get; init; }

    /// <summary>
    /// Gets the size of the descriptors block.
    /// <para>获取描述符块的大小。</para>
    /// </summary>
    public ulong DescriptorsSize { get; init; }

    /// <summary>
    /// Gets the rollback index which can be used to prevent rollback to older versions.
    /// <para>获取可用于防止回滚到旧版本的回滚索引。</para>
    /// </summary>
    public ulong RollbackIndex { get; init; }

    /// <summary>
    /// Gets the flags for this image from the <see cref="AvbVBMetaImageFlags"/> enumeration.
    /// This must be set to zero if the vbmeta image is not a top-level image.
    /// <para>从<see cref="AvbVBMetaImageFlags"/>枚举中获取此镜像的标志。</para>
    /// <para>如果vbmeta镜像不是顶级镜像，则必须设置为零。</para>
    /// </summary>
    public uint Flags { get; init; }

    /// <summary>
    /// Gets the location of the rollback index defined in this header.
    /// Only valid for the main vbmeta. For chained partitions, the rollback index location must be specified in the <see cref="AvbChainPartitionDescriptor"/> and this value must be set to 0.
    /// <para>获取此头中定义的回滚索引的位置。</para>
    /// <para>仅对主vbmeta有效。对于链式分区，回滚索引位置必须在<see cref="AvbChainPartitionDescriptor"/>中指定，此值必须设置为0。</para>
    /// </summary>
    public uint RollbackIndexLocation { get; init; }

    private InternalReleaseString _releaseString;
    private InternalReserved _reserved;

    [StructLayout(LayoutKind.Explicit, Size = ReleaseStringSize)]
    private struct InternalReleaseString { }
    [StructLayout(LayoutKind.Explicit, Size = 80)]
    private struct InternalReserved { }

    /// <summary>
    /// Gets the human-readable magic string "AVB0".
    /// <para>获取人类可读的魔术字符串"AVB0"。</para>
    /// </summary>
    public readonly string Magic => Encoding.ASCII.GetString(BitConverter.GetBytes(_magic0));

    /// <summary>
    /// Gets a value indicating whether the reserved field is valid (all zeros).
    /// <para>获取一个值，指示保留字段是否有效（全为零）。</para>
    /// </summary>
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

    /// <summary>
    /// Gets the release string associated with the image.
    /// <para>获取与镜像关联的发布字符串。</para>
    /// </summary>
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

    /// <summary>
    /// Gets a value indicating whether the release string is valid (ends with a NUL byte).
    /// <para>获取一个值，指示发布字符串是否有效（以NUL字节结尾）。</para>
    /// </summary>
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
    /// <para>从字节跨度反序列化<see cref="AvbVBMetaImageHeader"/>。</para>
    /// </summary>
    /// <param name="data">The byte span containing the 256-byte header.
    /// <para>包含256字节头的字节跨度。</para></param>
    /// <returns>An initialized <see cref="AvbVBMetaImageHeader"/> structure.
    /// <para>初始化的<see cref="AvbVBMetaImageHeader"/>结构。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the input data is less than 256 bytes.
    /// <para>当输入数据小于256字节时抛出。</para></exception>
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
    /// Attempts to deserialize an <see cref="AvbVBMetaImageHeader"/> from bytes.
    /// <para>尝试从字节反序列化<see cref="AvbVBMetaImageHeader"/>。</para>
    /// </summary>
    /// <param name="data">The byte span containing the 256-byte header.
    /// <para>包含256字节头的字节跨度。</para></param>
    /// <param name="header">When this method returns, contains the parsed header if successful.
    /// <para>当此方法返回时，如果成功则包含解析的头。</para></param>
    /// <returns>Returns true if successfully parsed; otherwise, false.
    /// <para>如果成功解析则返回true，否则返回false。</para></returns>
    public static bool TryFromBytes(ReadOnlySpan<byte> data, out AvbVBMetaImageHeader header)
    {
        header = default;
        if (data.Length < Size)
        {
            return false;
        }

        try
        {
            header = FromBytes(data);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Serializes the <see cref="AvbVBMetaImageHeader"/> into a byte span.
    /// <para>将<see cref="AvbVBMetaImageHeader"/>序列化为字节跨度。</para>
    /// </summary>
    /// <param name="data">The destination byte span (must be at least 256 bytes).
    /// <para>目标字节跨度（必须至少为256字节）。</para></param>
    /// <exception cref="ArgumentException">Thrown when the destination buffer is too small.
    /// <para>当目标缓冲区太小时抛出。</para></exception>
    public readonly void ToBytes(Span<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException($"Buffer size {data.Length} is less than {Size}");
        }
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