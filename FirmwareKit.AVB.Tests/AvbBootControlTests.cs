namespace FirmwareKit.AVB.Tests;

public class AvbBootControlTests
{
    [Fact]
    public void MarkBootSuccessful_ShouldMarkCurrentSlot()
    {
        var ops = new FakeBootOps();
        var control = new AvbBootControl(ops, () => "_b");

        var io = control.MarkBootSuccessful();

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal((byte)1, ops.Metadata.SlotB.SuccessfulBoot);
    }

    [Fact]
    public void SetActiveBootSlot_ShouldPromoteSlot()
    {
        var ops = new FakeBootOps();
        var control = new AvbBootControl(ops);

        var io = control.SetActiveBootSlot(1);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal(AvbAbSlotData.MaxPriority, ops.Metadata.SlotB.Priority);
    }

    [Fact]
    public void IsSlotBootable_ShouldReflectMetadata()
    {
        var ops = new FakeBootOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 0;
        ops.Metadata = md;
        var control = new AvbBootControl(ops);

        var io = control.IsSlotBootable(0, out var bootable);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(bootable);
    }

    private sealed class FakeBootOps : IAvbOps
    {
        public AvbAbData Metadata { get; set; } = AvbAbData.CreateDefault();

        public AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead)
        {
            bytesRead = 0;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer) => AvbIOResult.ErrorNoSuchPartition;

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
            data = Metadata;
            return AvbIOResult.Ok;
        }

        public AvbIOResult WriteAbMetadata(AvbAbData data)
        {
            Metadata = data;
            return AvbIOResult.Ok;
        }
    }
}
