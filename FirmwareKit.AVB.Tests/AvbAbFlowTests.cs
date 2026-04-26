using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Tests;

public class AvbAbFlowTests
{
    [Fact]
    public void MarkSlotActive_ShouldPromoteSlotAndResetState()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 10;
        md.SlotA.TriesRemaining = 1;
        md.SlotA.SuccessfulBoot = 1;
        md.SlotB.Priority = 11;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(0);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal(AvbAbSlotData.MaxPriority, ops.Metadata.SlotA.Priority);
        Assert.Equal(AvbAbSlotData.MaxTriesRemaining, ops.Metadata.SlotA.TriesRemaining);
        Assert.Equal((byte)0, ops.Metadata.SlotA.SuccessfulBoot);
    }

    [Fact]
    public void MarkSlotActive_WhenBothMaxPriority_ShouldDemoteOtherSlot()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = AvbAbSlotData.MaxPriority;
        md.SlotB.Priority = AvbAbSlotData.MaxPriority;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(0);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal(AvbAbSlotData.MaxPriority, ops.Metadata.SlotA.Priority);
        Assert.Equal((byte)(AvbAbSlotData.MaxPriority - 1), ops.Metadata.SlotB.Priority);
    }

    [Fact]
    public void MarkSlotUnbootable_ShouldClearSlotState()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotB.Priority = 14;
        md.SlotB.TriesRemaining = 3;
        md.SlotB.SuccessfulBoot = 1;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotUnbootable(1);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal((byte)0, ops.Metadata.SlotB.Priority);
        Assert.Equal((byte)0, ops.Metadata.SlotB.TriesRemaining);
        Assert.Equal((byte)0, ops.Metadata.SlotB.SuccessfulBoot);
    }

    [Fact]
    public void MarkSlotSuccessful_ShouldSetSuccessfulBootAndClearTries()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 8;
        md.SlotA.TriesRemaining = 4;
        md.SlotA.SuccessfulBoot = 0;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotSuccessful(0);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal((byte)0, ops.Metadata.SlotA.TriesRemaining);
        Assert.Equal((byte)1, ops.Metadata.SlotA.SuccessfulBoot);
    }

    [Fact]
    public void SelectSlot_NoBootableSlots_ShouldReturnNoBootableSlot()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 0;
        md.SlotA.TriesRemaining = 0;
        md.SlotA.SuccessfulBoot = 0;
        md.SlotB.Priority = 0;
        md.SlotB.TriesRemaining = 0;
        md.SlotB.SuccessfulBoot = 0;
        ops.Metadata = AvbAbData.FromBytes(md.ToBytes());
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.Equal(AvbAbFlowResult.ErrorNoBootableSlot, result);
        Assert.Equal(string.Empty, suffix);
        Assert.Null(verifyData);
    }

    [Fact]
    public void SelectSlot_ReadMetadataOom_ShouldReturnErrorOom()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorOom
        };
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.Equal(AvbAbFlowResult.ErrorOom, result);
        Assert.Equal(string.Empty, suffix);
        Assert.Null(verifyData);
    }

    [Fact]
    public void SlotIndexAndSuffixHelpers_ShouldMatchExpectedValues()
    {
        Assert.Equal(0, AvbAbFlow.GetSlotIndex("_a"));
        Assert.Equal(1, AvbAbFlow.GetSlotIndex("_b"));
        Assert.Equal(-1, AvbAbFlow.GetSlotIndex("_x"));

        Assert.Equal("_a", AvbAbFlow.GetSlotSuffix(0));
        Assert.Equal("_b", AvbAbFlow.GetSlotSuffix(1));
        Assert.Equal(string.Empty, AvbAbFlow.GetSlotSuffix(9));
    }

    [Fact]
    public void ResultToString_ShouldMatchLibAvbNaming()
    {
        Assert.Equal("OK", AvbAbFlow.ResultToString(AvbAbFlowResult.Ok));
        Assert.Equal("ERROR_NO_BOOTABLE_SLOTS", AvbAbFlow.ResultToString(AvbAbFlowResult.ErrorNoBootableSlot));
    }

    [Fact]
    public void SelectSlot_UninitializedMetadata_ShouldInitializeDefault()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorNoSuchValue
        };
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.NotEqual(AvbAbFlowResult.Ok, result);
        Assert.Equal(AvbAbSlotData.MaxPriority, ops.Metadata.SlotA.Priority);
        Assert.Equal(AvbAbSlotData.MaxTriesRemaining, ops.Metadata.SlotA.TriesRemaining);
    }

    [Fact]
    public void SelectSlot_InvalidMetadata_ShouldResetToDefault()
    {
        var ops = new FakeAbFlowOps();
        var badData = AvbAbData.CreateDefault();
        badData.VersionMajor = 99;
        ops.Metadata = badData;
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.NotEqual(AvbAbFlowResult.Ok, result);
    }

    [Fact]
    public void MarkSlotActive_InvalidSlotIndex_ShouldReturnErrorIO()
    {
        var ops = new FakeAbFlowOps();
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(5);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotUnbootable_InvalidSlotIndex_ShouldReturnErrorIO()
    {
        var ops = new FakeAbFlowOps();
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotUnbootable(5);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotSuccessful_InvalidSlotIndex_ShouldReturnErrorIO()
    {
        var ops = new FakeAbFlowOps();
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotSuccessful(5);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotSuccessful_UnbootableSlot_ShouldNotModify()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 0;
        md.SlotA.TriesRemaining = 0;
        md.SlotA.SuccessfulBoot = 0;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotSuccessful(0);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal((byte)0, ops.Metadata.SlotA.SuccessfulBoot);
        Assert.Equal((byte)0, ops.Metadata.SlotA.TriesRemaining);
    }

    [Fact]
    public void MarkSlotActive_ReadMetadataFail_ShouldReturnError()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorIo
        };
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(0);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotUnbootable_ReadMetadataFail_ShouldReturnError()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorIo
        };
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotUnbootable(0);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotSuccessful_ReadMetadataFail_ShouldReturnError()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorIo
        };
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotSuccessful(0);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void MarkSlotActive_WriteMetadataFail_ShouldReturnError()
    {
        var ops = new FakeAbFlowOps
        {
            WriteAbMetadataResult = AvbIOResult.ErrorIo
        };
        var md = ops.Metadata;
        md.SlotA.Priority = 5;
        md.SlotA.TriesRemaining = 3;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(0);

        Assert.Equal(AvbIOResult.ErrorIo, io);
    }

    [Fact]
    public void SelectSlot_WriteMetadataFail_ShouldReturnErrorIO()
    {
        var ops = new FakeAbFlowOps
        {
            WriteAbMetadataResult = AvbIOResult.ErrorIo
        };
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.Equal(AvbAbFlowResult.ErrorIo, result);
    }

    [Fact]
    public void MarkSlotActive_SlotB_ShouldDemoteSlotA()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = AvbAbSlotData.MaxPriority;
        md.SlotB.Priority = 10;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var io = flow.MarkSlotActive(1);

        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal(AvbAbSlotData.MaxPriority, ops.Metadata.SlotB.Priority);
        Assert.Equal(AvbAbSlotData.MaxTriesRemaining, ops.Metadata.SlotB.TriesRemaining);
        Assert.Equal((byte)0, ops.Metadata.SlotB.SuccessfulBoot);
        Assert.Equal((byte)(AvbAbSlotData.MaxPriority - 1), ops.Metadata.SlotA.Priority);
    }

    [Fact]
    public void NormalizeSlot_PriorityWithoutTries_ShouldClearPriority()
    {
        var ops = new FakeAbFlowOps();
        var md = ops.Metadata;
        md.SlotA.Priority = 15;
        md.SlotA.TriesRemaining = 0;
        md.SlotA.SuccessfulBoot = 0;
        md.SlotB.Priority = 0;
        md.SlotB.TriesRemaining = 0;
        md.SlotB.SuccessfulBoot = 0;
        ops.Metadata = md;
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.NotEqual(AvbAbFlowResult.Ok, result);
    }

    [Fact]
    public void SelectSlot_ErrorOom_ShouldReturnErrorOom()
    {
        var ops = new FakeAbFlowOps
        {
            ReadAbMetadataResult = AvbIOResult.ErrorOom
        };
        var flow = new AvbAbFlow(ops);

        var result = flow.SelectSlot(out var suffix, out var verifyData);

        Assert.Equal(AvbAbFlowResult.ErrorOom, result);
    }

    private sealed class FakeAbFlowOps : IAvbOps
    {
        public AvbAbData Metadata { get; set; } = AvbAbData.CreateDefault();

        public AvbIOResult ReadAbMetadataResult { get; set; } = AvbIOResult.Ok;

        public AvbIOResult WriteAbMetadataResult { get; set; } = AvbIOResult.Ok;

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
            return ReadAbMetadataResult;
        }

        public AvbIOResult WriteAbMetadata(AvbAbData data)
        {
            if (WriteAbMetadataResult == AvbIOResult.Ok)
            {
                Metadata = data;
            }

            return WriteAbMetadataResult;
        }
    }
}