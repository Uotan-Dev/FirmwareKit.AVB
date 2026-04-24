using System.Buffers.Binary;

namespace FirmwareKit.AVB.Tests;

public class AvbVBMetaImageTests
{
    [Fact]
    public void VerifyIntegrity_NoneAlgorithm_ShouldReturnOkNotSigned()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var authSize = 64;
        var auxSize = 64;
        var totalSize = headerSize + authSize + auxSize;
        var data = new byte[totalSize];

        // Header
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641); // AVB0
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbVBMetaImageHeader.MaxSupportedVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), (ulong)authSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), (ulong)auxSize);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), (uint)AvbAlgorithmType.None);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.OkNotSigned, result);
    }

    [Fact]
    public void GetDescriptors_ShouldExtractDescriptorsCorrectly()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var authSize = 64;
        // Auxiliary data contains descriptors
        // Descriptor 1: Property (32 bytes following)
        // Descriptor 2: Hash (152 bytes following)
        // Total aux size needed: multiple of 64
        // Descriptor headers are 16 bytes each. 
        // D1 total = 16 + 32 = 48
        // D2 total = 16 + 152 = 168
        // Total = 48 + 168 = 216. Round up to 64: 256.
        var auxSize = 256;
        var totalSize = headerSize + authSize + auxSize;
        var data = new byte[totalSize];

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), (ulong)authSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), (ulong)auxSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(96, 8), 0); // DescriptorsOffset
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(104, 8), 216); // DescriptorsSize

        var auxOffset = headerSize + authSize;
        var d1Offset = auxOffset;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(d1Offset, 8), (ulong)AvbDescriptorTag.Property);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(d1Offset + 8, 8), 32);

        var d2Offset = d1Offset + 48;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(d2Offset, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(d2Offset + 8, 8), 152);

        var image = new AvbVBMetaImage(data);
        var descriptors = image.GetDescriptors();

        Assert.Equal(2, descriptors.Count);
        Assert.IsType<AvbPropertyDescriptor>(descriptors[0]);
        Assert.IsType<AvbHashDescriptor>(descriptors[1]);
    }
}