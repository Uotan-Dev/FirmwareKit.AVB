using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Tests;

public class AvbOpsBaseTests
{
    [Fact]
    public void PersistentValues_ShouldRoundTrip()
    {
        var ops = new FakeOpsBase();

        var write = ops.WritePersistentValue("k", 3, new byte[] { 1, 2, 3 });
        Span<byte> output = stackalloc byte[8];
        var read = ops.ReadPersistentValue("k", output.Length, output, out var bytesRead);

        Assert.Equal(AvbIOResult.Ok, write);
        Assert.Equal(AvbIOResult.Ok, read);
        Assert.Equal(3, bytesRead);
        Assert.Equal((byte)1, output[0]);
        Assert.Equal((byte)2, output[1]);
        Assert.Equal((byte)3, output[2]);
    }

    [Fact]
    public void AbMetadata_ShouldRoundTripThroughMiscPartition()
    {
        var ops = new FakeOpsBase();
        var data = AvbAbData.CreateDefault();

        var write = ops.WriteAbMetadata(data);
        var read = ops.ReadAbMetadata(out var restored);

        Assert.Equal(AvbIOResult.Ok, write);
        Assert.Equal(AvbIOResult.Ok, read);
        Assert.True(restored.IsValid());
        Assert.Equal(data.SlotA.Priority, restored.SlotA.Priority);
        Assert.Equal(data.SlotB.Priority, restored.SlotB.Priority);
    }

    private sealed class FakeOpsBase : AvbOpsBase
    {
        private readonly Dictionary<string, byte[]> _parts = new(StringComparer.Ordinal)
        {
            ["misc"] = new byte[8192]
        };

        public override AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead)
        {
            bytesRead = 0;
            if (!_parts.TryGetValue(partitionName, out var part))
            {
                return AvbIOResult.ErrorNoSuchPartition;
            }

            var actualOffset = offset >= 0 ? offset : part.Length + offset;
            if (actualOffset < 0 || actualOffset + numBytes > part.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            part.AsSpan((int)actualOffset, numBytes).CopyTo(buffer);
            bytesRead = numBytes;
            return AvbIOResult.Ok;
        }

        public override AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer)
        {
            if (!_parts.TryGetValue(partitionName, out var part))
            {
                return AvbIOResult.ErrorNoSuchPartition;
            }

            var actualOffset = offset >= 0 ? offset : part.Length + offset;
            if (actualOffset < 0 || actualOffset + numBytes > part.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            buffer.Slice(0, numBytes).CopyTo(part.AsSpan((int)actualOffset, numBytes));
            return AvbIOResult.Ok;
        }

        public override AvbIOResult GetSizeOfPartition(string partitionName, out long size)
        {
            if (!_parts.TryGetValue(partitionName, out var part))
            {
                size = 0;
                return AvbIOResult.ErrorNoSuchPartition;
            }

            size = part.Length;
            return AvbIOResult.Ok;
        }
    }
}
