using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.VBMeta;
using System.Buffers.Binary;

namespace FirmwareKit.AVB.Tests;

public class AvbVBMetaImageTests
{
    private static byte[] BuildMinimalVBMeta(ulong authBlockSize = 64, ulong auxBlockSize = 64, uint algorithmType = (uint)AvbAlgorithmType.None)
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var totalSize = headerSize + (int)authBlockSize + (int)auxBlockSize;
        var data = new byte[totalSize];

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbVBMetaImageHeader.MaxSupportedVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), authBlockSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), auxBlockSize);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), algorithmType);

        return data;
    }

    [Fact]
    public void VerifyIntegrity_NoneAlgorithm_ShouldReturnOkNotSigned()
    {
        var data = BuildMinimalVBMeta();
        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.OkNotSigned, result);
    }

    [Fact]
    public void VerifyIntegrity_BadMagic_ShouldReturnInvalidVBMetaHeader()
    {
        var data = BuildMinimalVBMeta();
        data[0] = (byte)'Z';

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_MajorVersionCheck_ShouldReturnUnsupportedVersion()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor + 1);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.UnsupportedVersion, result);
    }

    [Fact]
    public void VerifyIntegrity_MinorVersionCheck_ShouldReturnUnsupportedVersion()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbVBMetaImageHeader.MaxSupportedVersionMinor + 1);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.UnsupportedVersion, result);
    }

    [Fact]
    public void VerifyIntegrity_NulTerminatedReleaseString_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        for (var n = 128; n < 128 + 48; n++)
        {
            data[n] = (byte)'a';
        }

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_BlockSizesAddUpToMoreThanLength_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        var size = (ulong)data.Length & ~0x3FUL;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), size);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_BlockSizesNotMultipleOf64_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta(authBlockSize: 32);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_HashOutOfBounds_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(32, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(40, 8), 64);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_SignatureOutOfBounds_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(48, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(56, 8), 64);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_PublicKeyOutOfBounds_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(64, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(72, 8), 64);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_PublicKeyMetadataOutOfBounds_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(80, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(88, 8), 64);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_InvalidAlgorithmField_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), 7u);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_VbmetaImageSmallerThanHeader_ShouldThrow()
    {
        var data = new byte[1];
        Assert.Throws<ArgumentException>(() => new AvbVBMetaImage(data));
    }

    [Fact]
    public void VerifyIntegrity_BiggerLength_ShouldStillReturnOkNotSigned()
    {
        var data = BuildMinimalVBMeta();
        var biggerData = new byte[data.Length + 8192];
        data.CopyTo(biggerData, 0);

        var image = new AvbVBMetaImage(biggerData);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.OkNotSigned, result);
    }

    [Fact]
    public void VerifyIntegrity_ModificationInHeader_ShouldDetectTampering()
    {
        var data = BuildMinimalVBMeta();
        var image = new AvbVBMetaImage(data);
        Assert.Equal(AvbVBMetaVerifyResult.OkNotSigned, image.VerifyIntegrity());

        data[176] ^= 0x80;
        var modifiedImage = new AvbVBMetaImage(data);
        var result = modifiedImage.VerifyIntegrity();
        Assert.NotEqual(AvbVBMetaVerifyResult.Ok, result);
    }

    [Fact]
    public void VerifyIntegrity_ModificationInAuxiliaryBlock_ShouldDetectTampering()
    {
        var data = BuildMinimalVBMeta();
        var auxOffset = AvbVBMetaImageHeader.Size + 64;
        data[auxOffset] ^= 0x80;

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();
        Assert.NotEqual(AvbVBMetaVerifyResult.Ok, result);
    }

    [Fact]
    public void VBMetaHeaderStructSize_ShouldBe256()
    {
        Assert.Equal(256, AvbVBMetaImageHeader.Size);
    }

    [Fact]
    public void GetDescriptors_ShouldExtractDescriptorsCorrectly()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var authSize = 64;
        var auxSize = 256;
        var totalSize = headerSize + authSize + auxSize;
        var data = new byte[totalSize];

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), (ulong)authSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), (ulong)auxSize);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(96, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(104, 8), 216);

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

    [Fact]
    public void VerifyIntegrity_PublicKeyBlockTooSmall_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta(authBlockSize: 64, auxBlockSize: 128, algorithmType: (uint)AvbAlgorithmType.Sha256Rsa2048);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(64, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(72, 8), 300);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_BlockSizesAddUpToLessThanLength_AuthOverflow_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        var overflowSize = 0xffffffffffffffc0UL;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), overflowSize);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_BlockSizesAddUpToLessThanLength_AuxOverflow_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        var overflowSize = 0xffffffffffffffc0UL;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), overflowSize);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_HashOutOfBounds_OverflowCheck_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(32, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(40, 8), 0xfffffffffffffffeUL);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_SignatureOutOfBounds_OverflowCheck_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(48, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(56, 8), 0xfffffffffffffffeUL);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_PublicKeyOutOfBounds_OverflowCheck_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(64, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(72, 8), 0xfffffffffffffffeUL);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VerifyIntegrity_PublicKeyMetadataOutOfBounds_OverflowCheck_ShouldReturnInvalidHeader()
    {
        var data = BuildMinimalVBMeta();
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(80, 8), 4);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(88, 8), 0xfffffffffffffffeUL);

        var image = new AvbVBMetaImage(data);
        var result = image.VerifyIntegrity();

        Assert.Equal(AvbVBMetaVerifyResult.InvalidVBMetaHeader, result);
    }

    [Fact]
    public void VBMetaHeader_ByteSwapRoundTrip_ShouldPreserveAllFields()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var data = new byte[headerSize];

        uint n32 = 0x11223344;
        ulong n64 = 0x1122334455667788;

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), n32); n32++;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), n32); n32++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), n64); n64++;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), n32); n32++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(32, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(40, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(48, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(56, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(64, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(72, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(80, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(88, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(96, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(104, 8), n64); n64++;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(112, 8), n64); n64++;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(120, 4), n32); n32++;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(124, 4), 0);

        var header = AvbVBMetaImageHeader.FromBytes(data);

        n32 = 0x11223344;
        n64 = 0x1122334455667788;

        Assert.Equal(n32, header.RequiredLibavbVersionMajor); n32++;
        Assert.Equal(n32, header.RequiredLibavbVersionMinor); n32++;
        Assert.Equal(n64, header.AuthenticationDataBlockSize); n64++;
        Assert.Equal(n64, header.AuxiliaryDataBlockSize); n64++;
        Assert.Equal(n32, header.AlgorithmType); n32++;
        Assert.Equal(n64, header.HashOffset); n64++;
        Assert.Equal(n64, header.HashSize); n64++;
        Assert.Equal(n64, header.SignatureOffset); n64++;
        Assert.Equal(n64, header.SignatureSize); n64++;
        Assert.Equal(n64, header.PublicKeyOffset); n64++;
        Assert.Equal(n64, header.PublicKeySize); n64++;
        Assert.Equal(n64, header.PublicKeyMetadataOffset); n64++;
        Assert.Equal(n64, header.PublicKeyMetadataSize); n64++;
        Assert.Equal(n64, header.DescriptorsOffset); n64++;
        Assert.Equal(n64, header.DescriptorsSize); n64++;
        Assert.Equal(n64, header.RollbackIndex); n64++;
        Assert.Equal(n32, header.Flags); n32++;
    }

    [Fact]
    public void VBMetaHeader_SerializationRoundTrip_ShouldPreserveAllFields()
    {
        var headerSize = AvbVBMetaImageHeader.Size;
        var original = new byte[headerSize];

        BinaryPrimitives.WriteUInt32LittleEndian(original.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt32BigEndian(original.AsSpan(4, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(original.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(12, 8), 64);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(20, 8), 64);
        BinaryPrimitives.WriteUInt32BigEndian(original.AsSpan(28, 4), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(32, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(40, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(48, 8), 64);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(56, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(64, 8), 64);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(72, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(80, 8), 64);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(88, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(96, 8), 64);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(104, 8), 0);
        BinaryPrimitives.WriteUInt64BigEndian(original.AsSpan(112, 8), 42);
        BinaryPrimitives.WriteUInt32BigEndian(original.AsSpan(120, 4), 3);
        BinaryPrimitives.WriteUInt32BigEndian(original.AsSpan(124, 4), 5);

        var header = AvbVBMetaImageHeader.FromBytes(original);

        var reserialized = new byte[headerSize];
        header.ToBytes(reserialized);

        Assert.Equal(original, reserialized);
    }
}
