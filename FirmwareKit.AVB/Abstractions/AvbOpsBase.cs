namespace FirmwareKit.AVB;

/// <summary>
/// Convenience managed base class for implementing <see cref="IAvbOps"/>.
/// </summary>
/// <remarks>
/// This class provides sane defaults for non-platform-specific operations
/// (rollback storage, persistent values, A/B metadata helpers, and key trust policy).
/// Override members as needed for production integration.
/// </remarks>
public abstract class AvbOpsBase : IAvbOps
{
    private readonly Dictionary<int, ulong> _rollbackIndexes = [];
    private readonly Dictionary<string, byte[]> _persistentValues = new(StringComparer.Ordinal);

    private const int AbMetadataMiscOffset = 2048;

    /// <inheritdoc />
    public abstract AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead);

    /// <inheritdoc />
    public abstract AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer);

    /// <inheritdoc />
    public virtual AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid)
    {
        isValid = true;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult ReadRollbackIndex(int rollbackIndexLocation, out ulong rollbackIndex)
    {
        rollbackIndex = _rollbackIndexes.TryGetValue(rollbackIndexLocation, out var value) ? value : 0;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult WriteRollbackIndex(int rollbackIndexLocation, ulong rollbackIndex)
    {
        _rollbackIndexes[rollbackIndexLocation] = rollbackIndex;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked)
    {
        isUnlocked = false;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid)
    {
        guid = string.Empty;
        return AvbIOResult.ErrorNoSuchPartition;
    }

    /// <inheritdoc />
    public abstract AvbIOResult GetSizeOfPartition(string partitionName, out long size);

    /// <inheritdoc />
    public virtual AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData)
    {
        preloadedData = ReadOnlySpan<byte>.Empty;
        return AvbIOResult.ErrorNoSuchPartition;
    }

    /// <inheritdoc />
    public virtual AvbIOResult ReadPersistentValue(string name, int bufferSize, Span<byte> outBuffer, out int outBytesRead)
    {
        outBytesRead = 0;
        if (!_persistentValues.TryGetValue(name, out var value))
        {
            return AvbIOResult.ErrorNoSuchValue;
        }

        if (bufferSize < value.Length || outBuffer.Length < value.Length)
        {
            return AvbIOResult.ErrorInsufficientSpace;
        }

        value.AsSpan().CopyTo(outBuffer);
        outBytesRead = value.Length;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult WritePersistentValue(string name, int valueSize, ReadOnlySpan<byte> value)
    {
        if (valueSize == 0)
        {
            _persistentValues.Remove(name);
            return AvbIOResult.Ok;
        }

        if (valueSize < 0 || value.Length < valueSize)
        {
            return AvbIOResult.ErrorInvalidValueSize;
        }

        _persistentValues[name] = value.Slice(0, valueSize).ToArray();
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult ValidatePublicKeyForPartition(
        string partition,
        ReadOnlySpan<byte> publicKeyData,
        ReadOnlySpan<byte> publicKeyMetadata,
        out bool isTrusted,
        out uint rollbackIndexLocation)
    {
        rollbackIndexLocation = 0;
        return ValidateVBMetaPublicKey(publicKeyData, publicKeyMetadata, out isTrusted);
    }

    /// <inheritdoc />
    public virtual AvbIOResult ReadAbMetadata(out AvbAbData data)
    {
        data = default;
        Span<byte> buffer = stackalloc byte[AvbAbData.Size];

        var io = ReadFromPartition("misc", AbMetadataMiscOffset, AvbAbData.Size, buffer, out var read);
        if (io != AvbIOResult.Ok || read != AvbAbData.Size)
        {
            return io == AvbIOResult.Ok ? AvbIOResult.ErrorIo : io;
        }

        data = AvbAbData.FromBytes(buffer);
        if (!data.IsValid())
        {
            data = AvbAbData.CreateDefault();
            return WriteAbMetadata(data);
        }

        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public virtual AvbIOResult WriteAbMetadata(AvbAbData data)
    {
        var bytes = data.ToBytes();
        return WriteToPartition("misc", AbMetadataMiscOffset, bytes.Length, bytes);
    }
}
