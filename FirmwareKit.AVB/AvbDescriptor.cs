
using System.Buffers.Binary;
using System.Text;

namespace FirmwareKit.AVB;
/// <summary>
/// Base class for all AVB descriptors. 
/// Equivalent to 'AvbDescriptor' in libavb.
/// </summary>
public abstract record AvbDescriptor
{
    /// <summary>Gets the tag identifying the type of descriptor.</summary>
    public AvbDescriptorTag Tag { get; init; }

    /// <summary>Gets the number of bytes following the 16-byte descriptor header.</summary>
    public ulong NumBytesFollowing { get; init; }

    /// <summary>
    /// Parses a descriptor from a byte span.
    /// </summary>
    /// <param name="data">The byte span containing the descriptor data.</param>
    /// <returns>A specialized <see cref="AvbDescriptor"/> instance.</returns>
    /// <exception cref="ArgumentException">Thrown when the data is malformed.</exception>
    public static AvbDescriptor FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16)
        {
            throw new ArgumentException("Data too small for descriptor header");
        }

        var tag = (AvbDescriptorTag)BinaryPrimitives.ReadUInt64BigEndian(data[0..8]);
        var numBytesFollowing = BinaryPrimitives.ReadUInt64BigEndian(data[8..16]);

        if ((numBytesFollowing & 0x07) != 0)
        {
            throw new ArgumentException("Descriptor size is not divisible by 8");
        }

        var body = data[16..(16 + (int)numBytesFollowing)];

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
}

/// <summary>
/// Represents a descriptor whose type is not recognized by the current parser.
/// </summary>
public sealed record UnknownAvbDescriptor : AvbDescriptor
{
    /// <summary>Gets the raw bytes of the descriptor body.</summary>
    public byte[] Data { get; init; } = [];
}

/// <summary>
/// A descriptor containing a kernel command-line fragment.
/// Equivalent to 'AvbKernelCmdlineDescriptor' in libavb.
/// </summary>
public sealed record AvbKernelCmdlineDescriptor : AvbDescriptor
{
    /// <summary>Gets flags for the command-line descriptor.</summary>
    public AvbKernelCmdlineFlags Flags { get; init; }

    /// <summary>Gets the kernel command-line string.</summary>
    public string KernelCmdline { get; init; } = string.Empty;

    /// <summary>
    /// Parses the body of a kernel command-line descriptor.
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.</param>
    /// <returns>A new <see cref="AvbKernelCmdlineDescriptor"/> instance.</returns>
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
/// </summary>
public sealed record AvbHashDescriptor : AvbDescriptor
{
    /// <summary>Gets the size of the partition image (excluding VBMeta if appended).</summary>
    public ulong ImageSize { get; init; }

    /// <summary>Gets the name of the hash algorithm as a string (e.g., "sha256").</summary>
    public string HashAlgorithm { get; init; } = string.Empty;

    /// <summary>Gets the name of the partition this descriptor pertains to.</summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>Gets the salt used for hashing.</summary>
    public byte[] Salt { get; init; } = [];

    /// <summary>Gets the expected digest of the partition.</summary>
    public byte[] Digest { get; init; } = [];

    /// <summary>Gets flags for the hash descriptor.</summary>
    public AvbHashDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a hash descriptor.
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.</param>
    /// <returns>A new <see cref="AvbHashDescriptor"/> instance.</returns>
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
/// </summary>
public sealed record AvbPropertyDescriptor : AvbDescriptor
{
    /// <summary>Gets the key (property name).</summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>Gets the raw bytes of the property value.</summary>
    public byte[] Value { get; init; } = [];

    /// <summary>
    /// Parses the body of a property descriptor.
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.</param>
    /// <returns>A new <see cref="AvbPropertyDescriptor"/> instance.</returns>
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
        // Followed by a NUL byte, then value
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
/// </summary>
public sealed record AvbHashtreeDescriptor : AvbDescriptor
{
    /// <summary>Gets the version of dm-verity to use.</summary>
    public uint DmVerityVersion { get; init; }

    /// <summary>Gets the size of the partition image.</summary>
    public ulong ImageSize { get; init; }

    /// <summary>Gets the offset within partition of the hashtree.</summary>
    public ulong TreeOffset { get; init; }

    /// <summary>Gets the size of the hashtree.</summary>
    public ulong TreeSize { get; init; }

    /// <summary>Gets the block size of the data blocks.</summary>
    public uint DataBlockSize { get; init; }

    /// <summary>Gets the block size of the hash blocks.</summary>
    public uint HashBlockSize { get; init; }

    /// <summary>Gets the number of FEC roots if FEC is enabled.</summary>
    public uint FecNumRoots { get; init; }

    /// <summary>Gets the offset of the FEC block.</summary>
    public ulong FecOffset { get; init; }

    /// <summary>Gets the size of the FEC block.</summary>
    public ulong FecSize { get; init; }

    /// <summary>Gets the name of the hash algorithm (e.g., "sha1").</summary>
    public string HashAlgorithm { get; init; } = string.Empty;

    /// <summary>Gets the name of the partition.</summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>Gets the salt used for the hashtree.</summary>
    public byte[] Salt { get; init; } = [];

    /// <summary>Gets the expected root digest of the hashtree.</summary>
    public byte[] RootDigest { get; init; } = [];

    /// <summary>Gets flags for the hashtree descriptor.</summary>
    public AvbHashtreeDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a hashtree descriptor.
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.</param>
    /// <returns>A new <see cref="AvbHashtreeDescriptor"/> instance.</returns>
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
/// </summary>
public sealed record AvbChainPartitionDescriptor : AvbDescriptor
{
    /// <summary>Gets the index of the rollback counter to use for this partition.</summary>
    public uint RollbackIndexLocation { get; init; }

    /// <summary>Gets the name of the chained partition.</summary>
    public string PartitionName { get; init; } = string.Empty;

    /// <summary>Gets the public key used for this chained partition.</summary>
    public byte[] PublicKey { get; init; } = [];

    /// <summary>Gets flags for the chained partition.</summary>
    public AvbChainPartitionDescriptorFlags Flags { get; init; }

    /// <summary>
    /// Parses the body of a chain partition descriptor.
    /// </summary>
    /// <param name="body">The byte span containing the descriptor body.</param>
    /// <returns>A new <see cref="AvbChainPartitionDescriptor"/> instance.</returns>
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

