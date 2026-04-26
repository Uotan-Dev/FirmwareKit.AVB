using FirmwareKit.AVB.Security;

namespace FirmwareKit.AVB.Tests;

public class AvbRsaPublicKeyHeaderTests
{
    [Fact]
    public void ParseAndSerialize_RoundTrip()
    {
        var header = new AvbRsaPublicKeyHeader
        {
            KeyNumBits = 4096,
            N0Inv = 0xAABBCCDD
        };

        var bytes = header.ToBytes();
        var parsed = AvbRsaPublicKeyHeader.FromBytes(bytes);

        Assert.Equal(header.KeyNumBits, parsed.KeyNumBits);
        Assert.Equal(header.N0Inv, parsed.N0Inv);
        Assert.True(parsed.IsValid);
    }

    [Fact]
    public void TryFromBytes_InvalidHeader_ReturnsFalse()
    {
        var invalid = new byte[AvbRsaPublicKeyHeader.Size];
        // key_num_bits = 1024 (too small)
        invalid[3] = 0x00;
        invalid[2] = 0x04;

        Assert.False(AvbRsaPublicKeyHeader.TryFromBytes(invalid, out _));
    }
}
