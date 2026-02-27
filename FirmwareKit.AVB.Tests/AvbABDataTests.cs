using System.Text;

namespace LibAVBSharp.Tests;

public class AvbABDataTests
{
    [Fact]
    public void InitData()
    {
        var data = AvbAbData.CreateDefault();
        Assert.Equal("\0AB0", Encoding.ASCII.GetString(data.MagicBytes));
        Assert.Equal(15, data.SlotA.Priority);
        Assert.Equal(7, data.SlotA.TriesRemaining);
        Assert.Equal(0, data.SlotA.SuccessfulBoot);
        Assert.Equal(14, data.SlotB.Priority);
        Assert.Equal(7, data.SlotB.TriesRemaining);
        Assert.Equal(0, data.SlotB.SuccessfulBoot);
        Assert.Equal(0u, data.Crc32);
    }

    [Fact]
    public void DataSerialization()
    {
        var data = AvbAbData.CreateDefault();
        var bytes = data.ToBytes();

        var restored = AvbAbData.FromBytes(bytes);
        Assert.Equal("\0AB0", Encoding.ASCII.GetString(restored.MagicBytes));
        Assert.Equal(data.VersionMajor, restored.VersionMajor);
        Assert.Equal(data.VersionMinor, restored.VersionMinor);
        Assert.Equal(data.SlotA, restored.SlotA);
        Assert.Equal(data.SlotB, restored.SlotB);
        Assert.True(restored.IsValid());
    }

    [Fact]
    public void CatchBadCRC()
    {
        var data = AvbAbData.CreateDefault();
        var bytes = data.ToBytes();

        // Corrupt CRC
        bytes[31] ^= 0xFF;

        var restored = AvbAbData.FromBytes(bytes);
        Assert.False(restored.IsValid());
    }

    [Fact]
    public void CatchUnsupportedMajorVersion()
    {
        var data = AvbAbData.CreateDefault();
        data.VersionMajor = 2; // Current is 1
        var bytes = data.ToBytes();

        var restored = AvbAbData.FromBytes(bytes);
        Assert.False(restored.IsValid());
    }
}