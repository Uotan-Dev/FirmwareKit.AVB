using System.Buffers.Binary;

namespace LibAVBSharp.Tests;

public class AvbFooterTests
{
    [Fact]
    public void FromBytes_ValidFooter_ShouldParseCorrectly()
    {
        var data = new byte[AvbFooter.Size];
        var n64 = 0x1122334455667788UL;

        // Magic: "AVBf" (Little-endian uint 0x66425641)
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), AvbFooter.MagicValueLiteral);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbFooter.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbFooter.ExpectedVersionMinor);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(12, 8), n64);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(20, 8), n64 + 1);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(28, 8), n64 + 2);
        // Reserved (36..64) are zeros by default

        var footer = AvbFooter.FromBytes(data);

        Assert.True(footer.IsValid);
        Assert.Equal(AvbFooter.ExpectedVersionMajor, footer.VersionMajor);
        Assert.Equal(AvbFooter.ExpectedVersionMinor, footer.VersionMinor);
        Assert.Equal(n64, footer.OriginalImageSize);
        Assert.Equal(n64 + 1, footer.VBMetaOffset);
        Assert.Equal(n64 + 2, footer.VBMetaSize);
    }

    [Fact]
    public void IsValid_BadMagic_ShouldReturnFalse()
    {
        var data = new byte[AvbFooter.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x78425641); // 'xVBf'
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbFooter.ExpectedVersionMajor);

        var footer = AvbFooter.FromBytes(data);
        Assert.False(footer.IsValid);
    }

    [Fact]
    public void IsValid_BadMajorVersion_ShouldReturnFalse()
    {
        var data = new byte[AvbFooter.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), AvbFooter.MagicValueLiteral);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbFooter.ExpectedVersionMajor + 1);

        var footer = AvbFooter.FromBytes(data);
        Assert.False(footer.IsValid);
    }

    [Fact]
    public void IsValid_BiggerMinorVersion_ShouldReturnTrue()
    {
        var data = new byte[AvbFooter.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), AvbFooter.MagicValueLiteral);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), AvbFooter.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8, 4), AvbFooter.ExpectedVersionMinor + 1);

        var footer = AvbFooter.FromBytes(data);
        Assert.True(footer.IsValid);
        Assert.Equal(AvbFooter.ExpectedVersionMinor + 1, footer.VersionMinor);
    }
}