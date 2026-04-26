using FirmwareKit.AVB.Ab;

namespace FirmwareKit.AVB.Tests;

public class AvbAbDataHelpersTests
{
    [Fact]
    public void TryVerifyAndByteswap_ReturnsTrue_ForValidData()
    {
        var data = AvbAbData.CreateDefault();
        var bytes = data.ToBytes();

        Assert.True(AvbAbData.TryVerifyAndByteswap(bytes, out var parsed));
        Assert.True(parsed.IsValid());
        Assert.Equal(data.VersionMajor, parsed.VersionMajor);
    }

    [Fact]
    public void TryVerifyAndByteswap_ReturnsFalse_ForCorruptedData()
    {
        var bytes = AvbAbData.CreateDefault().ToBytes();
        bytes[0] = (byte)'X';

        Assert.False(AvbAbData.TryVerifyAndByteswap(bytes, out _));
    }

    [Fact]
    public void UpdateCrcAndByteswap_ProducesValidSerializedData()
    {
        var source = AvbAbData.CreateDefault();
        var bytes = AvbAbData.UpdateCrcAndByteswap(source);

        var parsed = AvbAbData.FromBytes(bytes);
        Assert.True(parsed.IsValid());
    }
}