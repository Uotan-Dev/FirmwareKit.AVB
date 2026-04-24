using System.Buffers.Binary;

namespace FirmwareKit.AVB.Tests;

public class AvbUserTests
{
    [Fact]
    public void TryGetVerificationEnabled_ShouldReadFromVbmetaPartition()
    {
        var ops = new FakePartitionOps();
        ops.Partitions["vbmeta_a"] = BuildHeader(flags: 0);

        var ok = AvbUser.TryGetVerificationEnabled(ops, "_a", out var enabled);

        Assert.True(ok);
        Assert.True(enabled);
    }

    [Fact]
    public void TrySetVerificationEnabled_ShouldUpdateFlag()
    {
        var ops = new FakePartitionOps();
        ops.Partitions["vbmeta_a"] = BuildHeader(flags: 0);

        var ok = AvbUser.TrySetVerificationEnabled(ops, "_a", enableVerification: false);

        Assert.True(ok);
        var flags = BinaryPrimitives.ReadUInt32BigEndian(ops.Partitions["vbmeta_a"].AsSpan(120, 4));
        Assert.True((flags & (uint)AvbVBMetaImageFlags.VerificationDisabled) != 0);
    }

    [Fact]
    public void TryGetVerityEnabled_ShouldFallbackToBootFooter()
    {
        var ops = new FakePartitionOps();
        var boot = new byte[2048];

        var header = BuildHeader(flags: (uint)AvbVBMetaImageFlags.HashtreeDisabled);
        header.CopyTo(boot, 1024);

        var footer = BuildFooter(vbmetaOffset: 1024, vbmetaSize: (ulong)AvbVBMetaImageHeader.Size);
        footer.CopyTo(boot, boot.Length - AvbFooter.Size);

        ops.Partitions["boot_a"] = boot;

        var ok = AvbUser.TryGetVerityEnabled(ops, "_a", out var enabled);

        Assert.True(ok);
        Assert.False(enabled);
    }

    [Fact]
    public void TrySetVerityEnabled_ShouldFallbackToBootAndWriteHeader()
    {
        var ops = new FakePartitionOps();
        var boot = new byte[2048];

        var header = BuildHeader(flags: 0);
        header.CopyTo(boot, 1024);

        var footer = BuildFooter(vbmetaOffset: 1024, vbmetaSize: (ulong)AvbVBMetaImageHeader.Size);
        footer.CopyTo(boot, boot.Length - AvbFooter.Size);

        ops.Partitions["boot_a"] = boot;

        var ok = AvbUser.TrySetVerityEnabled(ops, "_a", enableVerity: false);

        Assert.True(ok);
        var flags = BinaryPrimitives.ReadUInt32BigEndian(ops.Partitions["boot_a"].AsSpan(1024 + 120, 4));
        Assert.True((flags & (uint)AvbVBMetaImageFlags.HashtreeDisabled) != 0);
    }

    private static byte[] BuildHeader(uint flags)
    {
        var header = new byte[AvbVBMetaImageHeader.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), 0x30425641); // AVB0
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(120, 4), flags);
        // release string must be NUL-terminated
        header[128] = (byte)'t';
        header[129] = 0;
        return header;
    }

    private static byte[] BuildFooter(ulong vbmetaOffset, ulong vbmetaSize)
    {
        var footer = new byte[AvbFooter.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(footer.AsSpan(0, 4), AvbFooter.MagicValueLiteral);
        BinaryPrimitives.WriteUInt32BigEndian(footer.AsSpan(4, 4), AvbFooter.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(footer.AsSpan(8, 4), AvbFooter.ExpectedVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(footer.AsSpan(12, 8), 0UL);
        BinaryPrimitives.WriteUInt64BigEndian(footer.AsSpan(20, 8), vbmetaOffset);
        BinaryPrimitives.WriteUInt64BigEndian(footer.AsSpan(28, 8), vbmetaSize);
        return footer;
    }

    private sealed class FakePartitionOps : IAvbOps
    {
        public Dictionary<string, byte[]> Partitions { get; } = [];

        public AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (!Partitions.TryGetValue(partitionName, out var part))
            {
                return AvbIOResult.ErrorNoSuchPartition;
            }

            var actualOffset = offset >= 0 ? offset : part.Length + offset;
            if (actualOffset < 0 || actualOffset > part.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            if (actualOffset + numBytes > part.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            part.AsSpan((int)actualOffset, numBytes).CopyTo(buffer);
            bytesRead = numBytes;
            return AvbIOResult.Ok;
        }

        public AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer)
        {
            if (!Partitions.TryGetValue(partitionName, out var part))
            {
                return AvbIOResult.ErrorNoSuchPartition;
            }

            var actualOffset = offset >= 0 ? offset : part.Length + offset;
            if (actualOffset < 0 || actualOffset > part.Length || actualOffset + numBytes > part.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            buffer.Slice(0, numBytes).CopyTo(part.AsSpan((int)actualOffset, numBytes));
            return AvbIOResult.Ok;
        }

        public AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid)
        {
            isValid = true;
            return AvbIOResult.Ok;
        }

        public AvbIOResult ReadRollbackIndex(int rollbackIndexLocation, out ulong rollbackIndex)
        {
            rollbackIndex = 0;
            return AvbIOResult.Ok;
        }

        public AvbIOResult WriteRollbackIndex(int rollbackIndexLocation, ulong rollbackIndex) => AvbIOResult.Ok;

        public AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked)
        {
            isUnlocked = false;
            return AvbIOResult.Ok;
        }

        public AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid)
        {
            guid = string.Empty;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult GetSizeOfPartition(string partitionName, out long size)
        {
            if (Partitions.TryGetValue(partitionName, out var part))
            {
                size = part.Length;
                return AvbIOResult.Ok;
            }

            size = 0;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData)
        {
            preloadedData = ReadOnlySpan<byte>.Empty;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult ReadPersistentValue(string name, int bufferSize, Span<byte> outBuffer, out int outBytesRead)
        {
            outBytesRead = 0;
            return AvbIOResult.ErrorNoSuchValue;
        }

        public AvbIOResult WritePersistentValue(string name, int valueSize, ReadOnlySpan<byte> value) => AvbIOResult.Ok;

        public AvbIOResult ValidatePublicKeyForPartition(string partition, ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isTrusted, out uint rollbackIndexLocation)
        {
            isTrusted = true;
            rollbackIndexLocation = 0;
            return AvbIOResult.Ok;
        }

        public AvbIOResult ReadAbMetadata(out AvbAbData data)
        {
            data = default;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult WriteAbMetadata(AvbAbData data) => AvbIOResult.Ok;
    }
}
