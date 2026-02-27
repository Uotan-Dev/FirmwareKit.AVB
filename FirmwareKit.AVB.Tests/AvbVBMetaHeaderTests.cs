using System.Buffers.Binary;
using System.Text;

namespace LibAVBSharp.Tests;

public class AvbVBMetaHeaderTests
{
    [Fact]
    public void FromBytes_ValidHeader_ShouldParseCorrectly()
    {
        var data = new byte[AvbVBMetaImageHeader.Size];
        var n32 = 0x11223344U;
        var n64 = 0x1122334455667788UL;

        // Magic "AVB0" is 0x30425641 in LittleEndian
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbVBMetaImageHeader.MaxSupportedVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), n64);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), n64 + 1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), n32);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(32, 8), n64 + 2);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(40, 8), n64 + 3);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(48, 8), n64 + 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(56, 8), n64 + 5);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(64, 8), n64 + 6);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(72, 8), n64 + 7);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(80, 8), n64 + 8);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(88, 8), n64 + 9);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(96, 8), n64 + 10);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(104, 8), n64 + 11);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(112, 8), n64 + 12);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(120, 4), n32 + 1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(124, 4), n32 + 2);

        var release = "1.3.0-test";
        Encoding.ASCII.GetBytes(release).CopyTo(data.AsSpan(128, release.Length));
        data[128 + release.Length] = 0; // NUL terminator
        data[128 + 47] = 0; // Ensure last byte is NUL

        var header = AvbVBMetaImageHeader.FromBytes(data);

        Assert.Equal(AvbVBMetaImageHeader.MagicHeader, header.Magic);
        Assert.Equal(AvbVBMetaImageHeader.ExpectedVersionMajor, header.RequiredLibavbVersionMajor);
        Assert.Equal(AvbVBMetaImageHeader.MaxSupportedVersionMinor, header.RequiredLibavbVersionMinor);
        Assert.Equal(n64, header.AuthenticationDataBlockSize);
        Assert.Equal(n64 + 1, header.AuxiliaryDataBlockSize);
        Assert.Equal(n32, header.AlgorithmType);
        Assert.Equal(n64 + 2, header.HashOffset);
        Assert.Equal(n64 + 3, header.HashSize);
        Assert.Equal(n64 + 4, header.SignatureOffset);
        Assert.Equal(n64 + 5, header.SignatureSize);
        Assert.Equal(n64 + 6, header.PublicKeyOffset);
        Assert.Equal(n64 + 7, header.PublicKeySize);
        Assert.Equal(n64 + 8, header.PublicKeyMetadataOffset);
        Assert.Equal(n64 + 9, header.PublicKeyMetadataSize);
        Assert.Equal(n64 + 10, header.DescriptorsOffset);
        Assert.Equal(n64 + 11, header.DescriptorsSize);
        Assert.Equal(n64 + 12, header.RollbackIndex);
        Assert.Equal(n32 + 1, header.Flags);
        Assert.Equal(n32 + 2, header.RollbackIndexLocation);
        Assert.Equal(release, header.ReleaseString);
        Assert.True(header.IsReleaseStringValid);
    }
}