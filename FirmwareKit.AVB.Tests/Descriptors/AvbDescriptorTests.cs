using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.VBMeta;
using System.Buffers.Binary;
using System.Text;

namespace FirmwareKit.AVB.Tests;

public class AvbDescriptorTests
{
    [Fact]
    public void KernelCmdlineDescriptor_Parse_ShouldSucceed()
    {
        // Specify 40 bytes of data past the end of the descriptor struct.
        // Fixed body size for KernelCmdline is 8 bytes.
        // Total bytes following header = 8 + 40 = 48.
        var numBytesFollowing = 48UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.KernelCmdline);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var flags = 0x11223344U;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16, 4), flags);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20, 4), 40); // cmdline len

        var cmdline = "console=ttyS0,115200 root=/dev/mmcblk0p1";
        // Fill padding with some data
        Encoding.UTF8.GetBytes(cmdline).CopyTo(data.AsSpan(24));

        var descriptor = AvbDescriptor.FromBytes(data);

        Assert.IsType<AvbKernelCmdlineDescriptor>(descriptor);
        var kcd = (AvbKernelCmdlineDescriptor)descriptor;
        Assert.Equal(AvbDescriptorTag.KernelCmdline, kcd.Tag);
        Assert.Equal(numBytesFollowing, kcd.NumBytesFollowing);
        Assert.Equal((AvbKernelCmdlineFlags)flags, kcd.Flags);
        Assert.Equal(cmdline, kcd.KernelCmdline);
    }

    [Fact]
    public void HashtreeDescriptor_Parse_ShouldSucceed()
    {
        // Hashtree fixed body size is 164.
        // Payload: partition_name_len(10) + salt_len(10) + root_digest_len(10) = 30.
        // Total bytes following = 164 + 30 = 194.
        // But wait, it must be divisible by 8. So 194 + 6 = 200.
        var numBytesFollowing = 200UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hashtree);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        var n32 = 0x11223344U;
        var n64 = 0x1122334455667788UL;

        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 0, 4), n32); // dm_verity_version
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 4, 8), n64); // image_size
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 12, 8), n64 + 1); // tree_offset
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 20, 8), n64 + 2); // tree_size
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 28, 4), n32 + 1); // data_block_size
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 32, 4), n32 + 2); // hash_block_size
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 36, 4), n32 + 3); // fec_num_roots
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 40, 8), n64 + 3); // fec_offset
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 48, 8), n64 + 4); // fec_size

        var algo = "sha1";
        Encoding.ASCII.GetBytes(algo).CopyTo(data.AsSpan(offset + 56, 32));

        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 88, 4), 10); // partition_name_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 92, 4), 10); // salt_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 96, 4), 10); // root_digest_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 100, 4), (uint)AvbHashtreeDescriptorFlags.DoNotUseAb);

        var descriptor = AvbDescriptor.FromBytes(data);

        Assert.IsType<AvbHashtreeDescriptor>(descriptor);
        var htd = (AvbHashtreeDescriptor)descriptor;
        Assert.Equal(n32, htd.DmVerityVersion);
        Assert.Equal(n64, htd.ImageSize);
        Assert.Equal(algo, htd.HashAlgorithm);
        Assert.Equal(AvbHashtreeDescriptorFlags.DoNotUseAb, htd.Flags);
    }

    [Fact]
    public void HashDescriptor_Parse_ShouldSucceed()
    {
        // Hash fixed body size is 116.
        // Payload: partition_name(10) + salt(10) + digest(10) = 30.
        // Total = 116 + 30 = 146. Padding to multiple of 8 = 152.
        var numBytesFollowing = 152UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        var n64 = 0x1122334455667788UL;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset, 8), n64); // image_size

        var algo = "sha256";
        Encoding.ASCII.GetBytes(algo).CopyTo(data.AsSpan(offset + 8, 32));

        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 40, 4), 10); // partition_name_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 44, 4), 10); // salt_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 48, 4), 10); // digest_len
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 52, 4), (uint)AvbHashDescriptorFlags.DoNotUseAb);

        var descriptor = AvbDescriptor.FromBytes(data);

        Assert.IsType<AvbHashDescriptor>(descriptor);
        var hd = (AvbHashDescriptor)descriptor;
        Assert.Equal(n64, hd.ImageSize);
        Assert.Equal(algo, hd.HashAlgorithm);
        Assert.Equal(AvbHashDescriptorFlags.DoNotUseAb, hd.Flags);
    }

    [Fact]
    public void PropertyDescriptor_Parse_ShouldSucceed()
    {
        // Property fixed body size is 16.
        // Payload: key(3) + \0(1) + value(4) + \0(1) = 9.
        // Total = 16 + 9 = 25. Padding to multiple of 8 = 32.
        var numBytesFollowing = 32UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Property);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset, 8), 3); // key_len ("foo")
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 8, 8), 4); // value_len

        var key = "foo";
        Encoding.UTF8.GetBytes(key).CopyTo(data.AsSpan(offset + 16));
        data[offset + 16 + 3] = 0; // NUL

        var val = new byte[] { 1, 2, 3, 4 };
        val.CopyTo(data.AsSpan(offset + 16 + 4));
        data[offset + 16 + 4 + 4] = 0; // NUL

        var descriptor = AvbDescriptor.FromBytes(data);

        Assert.IsType<AvbPropertyDescriptor>(descriptor);
        var pd = (AvbPropertyDescriptor)descriptor;
        Assert.Equal(key, pd.Key);
        Assert.Equal(val, pd.Value);
    }

    [Fact]
    public void PropertyLookup_ShouldFindStringAndIntegerValues()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var authSize = 64;
        var auxSize = 128;
        var totalSize = headerSize + authSize + auxSize;
        var data = new byte[totalSize];

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), (ulong)authSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), (ulong)auxSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(96, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(104, 8), 48);

        var auxOffset = headerSize + authSize;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(auxOffset, 8), (ulong)AvbDescriptorTag.Property);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(auxOffset + 8, 8), 32);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(auxOffset + 16, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(auxOffset + 24, 8), 5);

        Encoding.UTF8.GetBytes("test").CopyTo(data.AsSpan(auxOffset + 32));
        data[auxOffset + 36] = 0;
        Encoding.UTF8.GetBytes("12345").CopyTo(data.AsSpan(auxOffset + 37));
        data[auxOffset + 42] = 0;

        Assert.True(AvbDescriptor.TryLookupProperty(data, "test", out var stringValue));
        Assert.Equal("12345", stringValue);
        Assert.True(AvbDescriptor.TryLookupPropertyUInt64(data, "test", out var parsedValue));
        Assert.Equal(12345UL, parsedValue);
    }

    [Fact]
    public void KernelCmdlineDescriptor_BadTag_ShouldReturnUnknown()
    {
        var numBytesFollowing = 48UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), 0xf00dd00dUL);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20, 4), 40);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void KernelCmdlineDescriptor_CmdlineOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 48UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.KernelCmdline);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20, 4), 41);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashtreeDescriptor_BadTag_ShouldReturnUnknown()
    {
        var numBytesFollowing = 200UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), 0xf00dd00dUL);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashtreeDescriptor_PartitionNameOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 200UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hashtree);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 88, 4), 30);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 92, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 96, 4), 10);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashtreeDescriptor_SaltOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 200UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hashtree);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 88, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 92, 4), 30);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 96, 4), 10);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashtreeDescriptor_RootDigestOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 200UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hashtree);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 88, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 92, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 96, 4), 30);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashDescriptor_BadTag_ShouldReturnUnknown()
    {
        var numBytesFollowing = 152UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), 0xf00dd00dUL);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashDescriptor_PartitionNameOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 152UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 40, 4), 30);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 44, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 48, 4), 10);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashDescriptor_SaltOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 152UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 40, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 44, 4), 30);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 48, 4), 10);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void HashDescriptor_DigestOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 152UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 40, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 44, 4), 10);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 48, 4), 30);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void PropertyDescriptor_BadTag_ShouldReturnUnknown()
    {
        var numBytesFollowing = 32UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), 0xf00dd00dUL);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void PropertyDescriptor_KeyOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 32UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Property);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset, 8), 22);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 8, 8), 17);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void PropertyDescriptor_ValueOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 32UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Property);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset, 8), 16);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(offset + 8, 8), 23);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void ChainPartitionDescriptor_Parse_ShouldSucceed()
    {
        var partitionNameLen = 20u;
        var publicKeyLen = 16u;
        var numBytesFollowing = 76UL + partitionNameLen + publicKeyLen;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.ChainPartition);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset, 4), 42);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 4, 4), partitionNameLen);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 8, 4), publicKeyLen);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 12, 4), 0);

        var descriptor = AvbDescriptor.FromBytes(data);

        Assert.IsType<AvbChainPartitionDescriptor>(descriptor);
        var cpd = (AvbChainPartitionDescriptor)descriptor;
        Assert.Equal(AvbDescriptorTag.ChainPartition, cpd.Tag);
        Assert.Equal(42U, cpd.RollbackIndexLocation);
        Assert.Equal((int)partitionNameLen, cpd.PartitionName.Length);
        Assert.Equal((int)publicKeyLen, cpd.PublicKey.Length);
    }

    [Fact]
    public void ChainPartitionDescriptor_BadTag_ShouldReturnUnknown()
    {
        var numBytesFollowing = 56UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), 0xf00dd00dUL);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void ChainPartitionDescriptor_ZeroRollbackIndexLocation_ShouldReturnUnknown()
    {
        var numBytesFollowing = 56UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.ChainPartition);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 4, 4), 16);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 8, 4), 17);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 12, 4), 0);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void ChainPartitionDescriptor_PartitionNameOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 56UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.ChainPartition);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset, 4), 42);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 4, 4), 24);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 8, 4), 17);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 12, 4), 0);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void ChainPartitionDescriptor_PublicKeyOverflow_ShouldReturnUnknown()
    {
        var numBytesFollowing = 56UL;
        var data = new byte[16 + numBytesFollowing];

        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.ChainPartition);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), numBytesFollowing);

        var offset = 16;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset, 4), 42);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 4, 4), 16);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 8, 4), 25);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(offset + 12, 4), 0);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }

    [Fact]
    public void Descriptor_NumBytesFollowingNotMultipleOf8_ShouldReturnUnknown()
    {
        var data = new byte[24];
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(8, 8), 7);

        var descriptor = AvbDescriptor.FromBytes(data);
        Assert.IsType<UnknownAvbDescriptor>(descriptor);
    }
}