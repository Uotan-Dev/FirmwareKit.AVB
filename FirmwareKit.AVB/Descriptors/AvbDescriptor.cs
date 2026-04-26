using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.VBMeta;
using System.Buffers.Binary;
using System.Text;

namespace FirmwareKit.AVB.Descriptors;
/// <summary>
/// Base class for all AVB descriptors.
/// Equivalent to 'AvbDescriptor' in libavb.
/// <para>所有AVB描述符的基类。</para>
/// <para>等价于libavb中的'AvbDescriptor'。</para>
/// </summary>
public abstract record AvbDescriptor
{
    /// <summary>
    /// Gets the tag identifying the type of descriptor.
    /// <para>获取标识描述符类型的标签。</para>
    /// </summary>
    public AvbDescriptorTag Tag { get; init; }

    /// <summary>
    /// Gets the number of bytes following the 16-byte descriptor header.
    /// <para>获取16字节描述符头之后的字节数。</para>
    /// </summary>
    public ulong NumBytesFollowing { get; init; }

    /// <summary>
    /// Deserializes a descriptor from a byte span.
    /// <para>从字节跨度反序列化描述符。</para>
    /// </summary>
    /// <param name="data">The byte span containing the descriptor data.
    /// <para>包含描述符数据的字节跨度。</para></param>
    /// <returns>A specialized <see cref="AvbDescriptor"/> instance.
    /// <para>专门的<see cref="AvbDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is malformed.
    /// <para>当数据格式错误时抛出。</para></exception>
    public static AvbDescriptor FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16)
        {
            return new UnknownAvbDescriptor { Tag = 0, NumBytesFollowing = 0, Data = data.ToArray() };
        }

        var tag = (AvbDescriptorTag)BinaryPrimitives.ReadUInt64BigEndian(data[0..8]);
        var numBytesFollowing = BinaryPrimitives.ReadUInt64BigEndian(data[8..16]);

        if ((numBytesFollowing & 0x07) != 0)
        {
            return new UnknownAvbDescriptor { Tag = tag, NumBytesFollowing = numBytesFollowing, Data = data.ToArray() };
        }

        if (data.Length < 16 + (int)numBytesFollowing)
        {
            return new UnknownAvbDescriptor { Tag = tag, NumBytesFollowing = numBytesFollowing, Data = data.ToArray() };
        }

        var body = data[16..(16 + (int)numBytesFollowing)];

        try
        {
            return tag switch
            {
                AvbDescriptorTag.Hash => AvbHashDescriptor.ParseBody(body),
                AvbDescriptorTag.Hashtree => AvbHashtreeDescriptor.ParseBody(body),
                AvbDescriptorTag.Property => AvbPropertyDescriptor.ParseBody(body),
                AvbDescriptorTag.ChainPartition => AvbChainPartitionDescriptor.ParseBody(body),
                AvbDescriptorTag.KernelCmdline => AvbKernelCmdlineDescriptor.ParseBody(body),
                _ => new UnknownAvbDescriptor { Tag = tag, NumBytesFollowing = numBytesFollowing, Data = body.ToArray() }
            };
        }
        catch (ArgumentException)
        {
            return new UnknownAvbDescriptor { Tag = tag, NumBytesFollowing = numBytesFollowing, Data = body.ToArray() };
        }
    }

    /// <summary>
    /// Attempts to parse a descriptor from the supplied buffer.
    /// <para>尝试从提供的缓冲区解析描述符。</para>
    /// </summary>
    /// <param name="data">The byte span containing the descriptor data.
    /// <para>包含描述符数据的字节跨度。</para></param>
    /// <param name="descriptor">When this method returns, contains the parsed descriptor if successful.
    /// <para>当此方法返回时，如果成功则包含解析的描述符。</para></param>
    /// <returns>Returns true if successfully parsed; otherwise, false.
    /// <para>如果成功解析则返回true，否则返回false。</para></returns>
    public static bool TryFromBytes(ReadOnlySpan<byte> data, out AvbDescriptor descriptor)
    {
        descriptor = default!;

        try
        {
            descriptor = FromBytes(data);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Enumerates all descriptors from a vbmeta auxiliary descriptor block.
    /// <para>枚举vbmeta辅助描述符块中的所有描述符。</para>
    /// </summary>
    /// <param name="data">The auxiliary data block bytes.
    /// <para>辅助数据块字节。</para></param>
    /// <returns>A list of all descriptors found in the data.
    /// <para>数据中找到的所有描述符的列表。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is malformed.
    /// <para>当数据格式错误时抛出。</para></exception>
    public static List<AvbDescriptor> Enumerate(ReadOnlySpan<byte> data)
    {
        var descriptors = new List<AvbDescriptor>();
        var offset = 0;
        while (offset < data.Length)
        {
            if (data.Length - offset < 16)
            {
                throw new ArgumentException("Data too small for descriptor header");
            }

            var numBytesFollowing = BinaryPrimitives.ReadUInt64BigEndian(data.Slice(offset + 8, 8));
            if ((numBytesFollowing & 0x07) != 0)
            {
                throw new ArgumentException("Descriptor size is not divisible by 8");
            }

            var totalSize = 16 + checked((int)numBytesFollowing);
            if (data.Length - offset < totalSize)
            {
                throw new ArgumentException("Data too small for descriptor content");
            }

            descriptors.Add(FromBytes(data.Slice(offset, totalSize)));
            offset += totalSize;
        }

        return descriptors;
    }

    /// <summary>
    /// Iterates over all descriptors inside a VBMeta image.
    /// <para>遍历VBMeta镜像中的所有描述符。</para>
    /// </summary>
    /// <param name="vbmetaImage">The complete VBMeta image bytes.
    /// <para>完整的VBMeta镜像字节。</para></param>
    /// <param name="callback">Invoked for each descriptor; return false to stop iteration early.
    /// <para>为每个描述符调用；返回false以提前停止迭代。</para></param>
    /// <returns>Returns true if all descriptors were visited successfully; otherwise, false.
    /// <para>如果所有描述符都被成功遍历则返回true，否则返回false。</para></returns>
    public static bool ForEach(ReadOnlySpan<byte> vbmetaImage, Action<AvbDescriptor> callback)
    {
        if (callback is null)
        {
            throw new ArgumentNullException(nameof(callback));
        }

        try
        {
            var image = new AvbVBMetaImage(vbmetaImage.ToArray());
            foreach (var descriptor in image.GetDescriptors())
            {
                callback(descriptor);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns all descriptors inside a VBMeta image.
    /// <para>返回VBMeta镜像中的所有描述符。</para>
    /// </summary>
    /// <param name="vbmetaImage">The complete VBMeta image bytes.
    /// <para>完整的VBMeta镜像字节。</para></param>
    /// <returns>An array containing every descriptor in the image.
    /// <para>包含镜像中每个描述符的数组。</para></returns>
    public static AvbDescriptor[] GetAll(ReadOnlySpan<byte> vbmetaImage)
    {
        var image = new AvbVBMetaImage(vbmetaImage.ToArray());
        return image.GetDescriptors().ToArray();
    }

    /// <summary>
    /// Looks up a property descriptor by key in a VBMeta image.
    /// <para>在VBMeta镜像中通过键查找属性描述符。</para>
    /// </summary>
    /// <param name="vbmetaImage">The complete VBMeta image bytes.
    /// <para>完整的VBMeta镜像字节。</para></param>
    /// <param name="key">The property key to search for.
    /// <para>要搜索的属性键。</para></param>
    /// <param name="value">On success, receives the property value.
    /// <para>成功时，接收属性值。</para></param>
    /// <returns>Returns true if found; otherwise, false.
    /// <para>如果找到则返回true，否则返回false。</para></returns>
    public static bool TryLookupProperty(ReadOnlySpan<byte> vbmetaImage, string key, out string? value)
    {
        value = null;

        if (string.IsNullOrEmpty(key))
        {
            return false;
        }

        try
        {
            var image = new AvbVBMetaImage(vbmetaImage.ToArray());
            foreach (var descriptor in image.GetDescriptors())
            {
                if (descriptor is AvbPropertyDescriptor property &&
                    string.Equals(property.Key, key, StringComparison.Ordinal))
                {
                    value = Encoding.UTF8.GetString(property.Value);
                    return true;
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Looks up a property descriptor and parses its value as an unsigned 64-bit integer.
    /// <para>查找属性描述符并将其值解析为无符号64位整数。</para>
    /// </summary>
    /// <param name="vbmetaImage">The complete VBMeta image bytes.
    /// <para>完整的VBMeta镜像字节。</para></param>
    /// <param name="key">The property key to search for.
    /// <para>要搜索的属性键。</para></param>
    /// <param name="value">On success, receives the parsed integer value.
    /// <para>成功时，接收解析的整数值。</para></param>
    /// <returns>Returns true if found and parsed successfully; otherwise, false.
    /// <para>如果找到且解析成功则返回true，否则返回false。</para></returns>
    public static bool TryLookupPropertyUInt64(ReadOnlySpan<byte> vbmetaImage, string key, out ulong value)
    {
        value = 0;

        if (!TryLookupProperty(vbmetaImage, key, out var stringValue) || stringValue is null)
        {
            return false;
        }

        if (stringValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ulong.TryParse(
                stringValue.Substring(2),
                System.Globalization.NumberStyles.AllowHexSpecifier,
                System.Globalization.CultureInfo.InvariantCulture,
                out value);
        }

        return ulong.TryParse(
            stringValue,
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out value);
    }
}

/// <summary>
/// Represents a descriptor whose type is not recognized by the current parser.
/// <para>表示其类型不被当前解析器识别的描述符。</para>
/// </summary>
public sealed record UnknownAvbDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets the raw bytes of the descriptor body.
    /// <para>获取描述符主体的原始字节。</para>
    /// </summary>
    public byte[] Data { get; init; } = [];
}

/// <summary>
/// A descriptor containing a kernel command-line fragment.
/// Equivalent to 'AvbKernelCmdlineDescriptor' in libavb.
/// <para>包含内核命令行片段的描述符。</para>
/// <para>等价于libavb中的'AvbKernelCmdlineDescriptor'。</para>
/// </summary>
public sealed record AvbKernelCmdlineDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets flags for the command-line descriptor.
    /// <para>获取命令行描述符的标志。</para>
    /// </summary>
    public AvbKernelCmdlineFlags Flags { get; init; }

    /// <summary>
    /// Gets the kernel command-line string.
    /// <para>获取内核命令行字符串。</para>
    /// </summary>
    public string KernelCmdline { get; init; } = string.Empty;

    /// <summary>
    /// Parses the body of a kernel command-line descriptor.
    /// <para>解析内核命令行描述符的主体。</para>
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.
    /// <para>包含描述符主体的字节跨度。</para></param>
    /// <returns>A new <see cref="AvbKernelCmdlineDescriptor"/> instance.
    /// <para>新的<see cref="AvbKernelCmdlineDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is too small.
    /// <para>当数据太小时抛出。</para></exception>
    internal static AvbKernelCmdlineDescriptor ParseBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 8)
        {
            throw new ArgumentException("Data too small for kernel cmdline descriptor header");
        }

        var flags = BinaryPrimitives.ReadUInt32BigEndian(body[0..4]);
        var kernelCmdlineLen = BinaryPrimitives.ReadUInt32BigEndian(body[4..8]);

        if (body.Length < 8 + kernelCmdlineLen)
        {
            throw new ArgumentException("Data too small for kernel cmdline content");
        }

        var kernelCmdline = Encoding.UTF8.GetString(body.Slice(8, (int)kernelCmdlineLen).ToArray());

        return new AvbKernelCmdlineDescriptor
        {
            Tag = AvbDescriptorTag.KernelCmdline,
            NumBytesFollowing = (ulong)body.Length,
            Flags = (AvbKernelCmdlineFlags)flags,
            KernelCmdline = Encoding.UTF8.GetString(body.Slice(8, (int)kernelCmdlineLen).ToArray())
        };
    }
}

/// <summary>
/// A descriptor containing partition hash information.
/// Equivalent to 'AvbHashDescriptor' in libavb.
/// <para>包含分区哈希信息的描述符。</para>
/// <para>等价于libavb中的'AvbHashDescriptor'。</para>
/// </summary>
public sealed record AvbHashDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets the size of the partition image (excluding VBMeta if appended).
    /// <para>获取分区镜像的大小（如果附加了VBMeta则不包括）。</para>
    /// </summary>
    public ulong ImageSize { get; init; }

    /// <summary>
    /// Gets the name of the hash algorithm as a string (e.g., "sha256").
    /// <para>获取哈希算法的名称作为字符串（例如"sha256"）。</para>
    /// </summary>
    public string HashAlgorithm { get; init; } = string.Empty;

    /// <summary>
    /// Gets the name of the partition this descriptor pertains to.
    /// <para>获取此描述符所属的分区名称。</para>
    /// </summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the salt used for hashing.
    /// <para>获取用于哈希的盐值。</para>
    /// </summary>
    public byte[] Salt { get; init; } = [];

    /// <summary>
    /// Gets the expected digest of the partition.
    /// <para>获取分区的预期摘要。</para>
    /// </summary>
    public byte[] Digest { get; init; } = [];

    /// <summary>
    /// Gets flags for the hash descriptor.
    /// <para>获取哈希描述符的标志。</para>
    /// </summary>
    public AvbHashDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a hash descriptor.
    /// <para>解析哈希描述符的主体。</para>
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.
    /// <para>包含描述符主体的字节跨度。</para></param>
    /// <returns>A new <see cref="AvbHashDescriptor"/> instance.
    /// <para>新的<see cref="AvbHashDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is too small.
    /// <para>当数据太小时抛出。</para></exception>
    internal static AvbHashDescriptor ParseBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 116)
        {
            throw new ArgumentException("Data too small for hash descriptor header");
        }

        var imageSize = BinaryPrimitives.ReadUInt64BigEndian(body[0..8]);
        var hashAlgo = Encoding.ASCII.GetString(body[8..40].ToArray()).TrimEnd('\0');
        var partitionNameLen = BinaryPrimitives.ReadUInt32BigEndian(body[40..44]);
        var saltLen = BinaryPrimitives.ReadUInt32BigEndian(body[44..48]);
        var digestLen = BinaryPrimitives.ReadUInt32BigEndian(body[48..52]);
        var flags = BinaryPrimitives.ReadUInt32BigEndian(body[52..56]);

        if (body.Length < 116 + partitionNameLen + saltLen + digestLen)
        {
            throw new ArgumentException("Data too small for hash descriptor content");
        }

        var offset = 116;
        var partitionName = Encoding.UTF8.GetString(body.Slice(offset, (int)partitionNameLen).ToArray());
        offset += (int)partitionNameLen;
        var salt = body.Slice(offset, (int)saltLen).ToArray();
        offset += (int)saltLen;
        var digest = body.Slice(offset, (int)digestLen).ToArray();

        return new AvbHashDescriptor
        {
            Tag = AvbDescriptorTag.Hash,
            NumBytesFollowing = (ulong)body.Length,
            ImageSize = imageSize,
            HashAlgorithm = hashAlgo,
            PartitionName = partitionName,
            Salt = salt,
            Digest = digest,
            Flags = (AvbHashDescriptorFlags)flags
        };
    }
}

/// <summary>
/// A descriptor containing a custom key-value property.
/// Equivalent to 'AvbPropertyDescriptor' in libavb.
/// <para>包含自定义键值属性的描述符。</para>
/// <para>等价于libavb中的'AvbPropertyDescriptor'。</para>
/// </summary>
public sealed record AvbPropertyDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets the key (property name).
    /// <para>获取键（属性名称）。</para>
    /// </summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>
    /// Gets the raw bytes of the property value.
    /// <para>获取属性值的原始字节。</para>
    /// </summary>
    public byte[] Value { get; init; } = [];

    /// <summary>
    /// Parses the body of a property descriptor.
    /// <para>解析属性描述符的主体。</para>
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.
    /// <para>包含描述符主体的字节跨度。</para></param>
    /// <returns>A new <see cref="AvbPropertyDescriptor"/> instance.
    /// <para>新的<see cref="AvbPropertyDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is malformed.
    /// <para>当数据格式错误时抛出。</para></exception>
    internal static AvbPropertyDescriptor ParseBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 16)
        {
            throw new ArgumentException("Data too small for property descriptor header");
        }

        var keyLen = BinaryPrimitives.ReadUInt64BigEndian(body[0..8]);
        var valLen = BinaryPrimitives.ReadUInt64BigEndian(body[8..16]);

        if (body.Length < 16 + (int)keyLen + 1 + (int)valLen + 1)
        {
            throw new ArgumentException("Data too small for property descriptor content");
        }

        var offset = 16;
        if (body[offset + (int)keyLen] != 0)
        {
            throw new ArgumentException("Key in property descriptor must be NUL terminated");
        }

        if (body[offset + (int)keyLen + 1 + (int)valLen] != 0)
        {
            throw new ArgumentException("Value in property descriptor must be NUL terminated");
        }

        var key = Encoding.UTF8.GetString(body.Slice(offset, (int)keyLen).ToArray());
        var value = body.Slice(offset + (int)keyLen + 1, (int)valLen).ToArray();

        return new AvbPropertyDescriptor
        {
            Tag = AvbDescriptorTag.Property,
            NumBytesFollowing = (ulong)body.Length,
            Key = key,
            Value = value
        };
    }
}

/// <summary>
/// A descriptor containing Hashtree/dm-verity information.
/// Equivalent to 'AvbHashtreeDescriptor' in libavb.
/// <para>包含Hashtree/dm-verity信息的描述符。</para>
/// <para>等价于libavb中的'AvbHashtreeDescriptor'。</para>
/// </summary>
public sealed record AvbHashtreeDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets the version of dm-verity to use.
    /// <para>获取要使用的dm-verity版本。</para>
    /// </summary>
    public uint DmVerityVersion { get; init; }

    /// <summary>
    /// Gets the size of the partition image.
    /// <para>获取分区镜像的大小。</para>
    /// </summary>
    public ulong ImageSize { get; init; }

    /// <summary>
    /// Gets the offset within partition of the hashtree.
    /// <para>获取分区内哈希树的偏移量。</para>
    /// </summary>
    public ulong TreeOffset { get; init; }

    /// <summary>
    /// Gets the size of the hashtree.
    /// <para>获取哈希树的大小。</para>
    /// </summary>
    public ulong TreeSize { get; init; }

    /// <summary>
    /// Gets the block size of the data blocks.
    /// <para>获取数据块的块大小。</para>
    /// </summary>
    public uint DataBlockSize { get; init; }

    /// <summary>
    /// Gets the block size of the hash blocks.
    /// <para>获取哈希块的块大小。</para>
    /// </summary>
    public uint HashBlockSize { get; init; }

    /// <summary>
    /// Gets the number of FEC roots if FEC is enabled.
    /// <para>如果启用了FEC，获取FEC根的数量。</para>
    /// </summary>
    public uint FecNumRoots { get; init; }

    /// <summary>
    /// Gets the offset of the FEC block.
    /// <para>获取FEC块的偏移量。</para>
    /// </summary>
    public ulong FecOffset { get; init; }

    /// <summary>
    /// Gets the size of the FEC block.
    /// <para>获取FEC块的大小。</para>
    /// </summary>
    public ulong FecSize { get; init; }

    /// <summary>
    /// Gets the name of the hash algorithm (e.g., "sha1").
    /// <para>获取哈希算法的名称（例如"sha1"）。</para>
    /// </summary>
    public string HashAlgorithm { get; init; } = string.Empty;

    /// <summary>
    /// Gets the name of the partition.
    /// <para>获取分区的名称。</para>
    /// </summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the salt used for the hashtree.
    /// <para>获取用于哈希树的盐值。</para>
    /// </summary>
    public byte[] Salt { get; init; } = [];

    /// <summary>
    /// Gets the expected root digest of the hashtree.
    /// <para>获取哈希树的预期根摘要。</para>
    /// </summary>
    public byte[] RootDigest { get; init; } = [];

    /// <summary>
    /// Gets flags for the hashtree descriptor.
    /// <para>获取哈希树描述符的标志。</para>
    /// </summary>
    public AvbHashtreeDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a hashtree descriptor.
    /// <para>解析哈希树描述符的主体。</para>
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.
    /// <para>包含描述符主体的字节跨度。</para></param>
    /// <returns>A new <see cref="AvbHashtreeDescriptor"/> instance.
    /// <para>新的<see cref="AvbHashtreeDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is too small.
    /// <para>当数据太小时抛出。</para></exception>
    internal static AvbHashtreeDescriptor ParseBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 164)
        {
            throw new ArgumentException("Data too small for hashtree descriptor header");
        }

        var dmVersion = BinaryPrimitives.ReadUInt32BigEndian(body[0..4]);
        var imageSize = BinaryPrimitives.ReadUInt64BigEndian(body[4..12]);
        var treeOffset = BinaryPrimitives.ReadUInt64BigEndian(body[12..20]);
        var treeSize = BinaryPrimitives.ReadUInt64BigEndian(body[20..28]);
        var dataBlockSize = BinaryPrimitives.ReadUInt32BigEndian(body[28..32]);
        var hashBlockSize = BinaryPrimitives.ReadUInt32BigEndian(body[32..36]);
        var fecNumRoots = BinaryPrimitives.ReadUInt32BigEndian(body[36..40]);
        var fecOffset = BinaryPrimitives.ReadUInt64BigEndian(body[40..48]);
        var fecSize = BinaryPrimitives.ReadUInt64BigEndian(body[48..56]);
        var hashAlgo = Encoding.ASCII.GetString(body[56..88].ToArray()).TrimEnd('\0');
        var partitionNameLen = BinaryPrimitives.ReadUInt32BigEndian(body[88..92]);
        var saltLen = BinaryPrimitives.ReadUInt32BigEndian(body[92..96]);
        var rootDigestLen = BinaryPrimitives.ReadUInt32BigEndian(body[96..100]);
        var flags = BinaryPrimitives.ReadUInt32BigEndian(body[100..104]);

        if (body.Length < 164 + partitionNameLen + saltLen + rootDigestLen)
        {
            throw new ArgumentException("Data too small for hashtree descriptor content");
        }

        var offset = 164;
        var partitionName = Encoding.UTF8.GetString(body.Slice(offset, (int)partitionNameLen).ToArray());
        offset += (int)partitionNameLen;
        var salt = body.Slice(offset, (int)saltLen).ToArray();
        offset += (int)saltLen;
        var rootDigest = body.Slice(offset, (int)rootDigestLen).ToArray();

        return new AvbHashtreeDescriptor
        {
            Tag = AvbDescriptorTag.Hashtree,
            NumBytesFollowing = (ulong)body.Length,
            DmVerityVersion = dmVersion,
            ImageSize = imageSize,
            TreeOffset = treeOffset,
            TreeSize = treeSize,
            DataBlockSize = dataBlockSize,
            HashBlockSize = hashBlockSize,
            FecNumRoots = fecNumRoots,
            FecOffset = fecOffset,
            FecSize = fecSize,
            HashAlgorithm = hashAlgo,
            PartitionName = partitionName,
            Salt = salt,
            RootDigest = rootDigest,
            Flags = (AvbHashtreeDescriptorFlags)flags
        };
    }
}

/// <summary>
/// A descriptor containing information about a chained partition.
/// Equivalent to 'AvbChainPartitionDescriptor' in libavb.
/// <para>包含链式分区信息的描述符。</para>
/// <para>等价于libavb中的'AvbChainPartitionDescriptor'。</para>
/// </summary>
public sealed record AvbChainPartitionDescriptor : AvbDescriptor
{
    /// <summary>
    /// Gets the index of the rollback counter to use for this partition.
    /// <para>获取用于此分区的回滚计数器的索引。</para>
    /// </summary>
    public uint RollbackIndexLocation { get; init; }

    /// <summary>
    /// Gets the name of the chained partition.
    /// <para>获取链式分区的名称。</para>
    /// </summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the public key used for this chained partition.
    /// <para>获取用于此链式分区的公钥。</para>
    /// </summary>
    public byte[] PublicKey { get; init; } = [];

    /// <summary>
    /// Gets flags for the chained partition.
    /// <para>获取链式分区的标志。</para>
    /// </summary>
    public AvbChainPartitionDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a chain partition descriptor.
    /// <para>解析链式分区描述符的主体。</para>
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.
    /// <para>包含描述符主体的字节跨度。</para></param>
    /// <returns>A new <see cref="AvbChainPartitionDescriptor"/> instance.
    /// <para>新的<see cref="AvbChainPartitionDescriptor"/>实例。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the data is malformed.
    /// <para>当数据格式错误时抛出。</para></exception>
    internal static AvbChainPartitionDescriptor ParseBody(ReadOnlySpan<byte> body)
    {
        if (body.Length < 76)
        {
            throw new ArgumentException("Data too small for chain partition descriptor header");
        }

        var rollbackIndexLocation = BinaryPrimitives.ReadUInt32BigEndian(body[0..4]);
        if (rollbackIndexLocation < 1)
        {
            throw new ArgumentException("Invalid rollback index location in chain partition descriptor");
        }

        var partitionNameLen = BinaryPrimitives.ReadUInt32BigEndian(body[4..8]);
        var publicKeyLen = BinaryPrimitives.ReadUInt32BigEndian(body[8..12]);
        var flags = BinaryPrimitives.ReadUInt32BigEndian(body[12..16]);

        if (body.Length < 76 + partitionNameLen + publicKeyLen)
        {
            throw new ArgumentException("Data too small for chain partition descriptor content");
        }

        var offset = 76;
        var partitionName = Encoding.UTF8.GetString(body.Slice(offset, (int)partitionNameLen).ToArray());
        offset += (int)partitionNameLen;
        var publicKey = body.Slice(offset, (int)publicKeyLen).ToArray();

        return new AvbChainPartitionDescriptor
        {
            Tag = AvbDescriptorTag.ChainPartition,
            NumBytesFollowing = (ulong)body.Length,
            RollbackIndexLocation = rollbackIndexLocation,
            PartitionName = partitionName,
            PublicKey = publicKey,
            Flags = (AvbChainPartitionDescriptorFlags)flags
        };
    }
}