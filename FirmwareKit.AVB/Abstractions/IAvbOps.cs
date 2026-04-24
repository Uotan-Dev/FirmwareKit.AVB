namespace FirmwareKit.AVB;

/// <summary>
/// Defines the operation interface for Android Verified Boot (AVB), equivalent to the 'AvbOps' struct 
/// in libavb. Implementing this interface allows the library to interact with device storage and properties.
/// </summary>
public interface IAvbOps
{
    /// <summary>
    /// Reads data from a specific partition.
    /// </summary>
    /// <param name="partitionName">The name of the partition to read from (e.g., "boot", "vbmeta").</param>
    /// <param name="offset">The byte offset within the partition.</param>
    /// <param name="numBytes">The number of bytes to read.</param>
    /// <param name="buffer">The output buffer to store the read data.</param>
    /// <param name="bytesRead">The actual number of bytes read.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead);

    /// <summary>
    /// Writes data to a specific partition.
    /// </summary>
    /// <param name="partitionName">The name of the partition to write to.</param>
    /// <param name="offset">The byte offset within the partition.</param>
    /// <param name="numBytes">The number of bytes to write.</param>
    /// <param name="buffer">The data buffer containing the bytes to write.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer);

    /// <summary>
    /// Validates a VBMeta public key against the device's root of trust.
    /// </summary>
    /// <param name="publicKeyData">The binary data of the public key to validate.</param>
    /// <param name="publicKeyMetadata">The optional public key metadata.</param>
    /// <param name="isValid">Set to <c>true</c> if the public key is trusted; otherwise, <c>false</c>.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid);

    /// <summary>
    /// Reads the rollback index for the specified location.
    /// </summary>
    /// <param name="rollbackIndexLocation">The index location (0 to 31).</param>
    /// <param name="rollbackIndex">The stored rollback index.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ReadRollbackIndex(int rollbackIndexLocation, out ulong rollbackIndex);

    /// <summary>
    /// Writes a new rollback index for the specified location.
    /// </summary>
    /// <param name="rollbackIndexLocation">The index location (0 to 31).</param>
    /// <param name="rollbackIndex">The new rollback index value.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult WriteRollbackIndex(int rollbackIndexLocation, ulong rollbackIndex);

    /// <summary>
    /// Checks if the device is currently unlocked (verification bypassed).
    /// </summary>
    /// <param name="isUnlocked">Set to <c>true</c> if the device is unlocked; otherwise, <c>false</c>.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked);

    /// <summary>
    /// Retrieves a unique GUID for the specified partition.
    /// </summary>
    /// <param name="partitionName">The partition name.</param>
    /// <param name="guid">The unique identifier (e.g., PARTUUID) of the partition.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid);

    /// <summary>
    /// Gets the total size of the specified partition.
    /// </summary>
    /// <param name="partitionName">The partition name.</param>
    /// <param name="size">The total partition size in bytes.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult GetSizeOfPartition(string partitionName, out long size);

    /// <summary>
    /// Checks if a partition is preloaded into memory (e.g., by the bootloader).
    /// </summary>
    /// <param name="partitionName">The partition name.</param>
    /// <param name="numBytes">The number of bytes required.</param>
    /// <param name="preloadedData">The span containing preloaded data if available.</param>
    /// <returns><see cref="AvbIOResult.Ok"/> if preloaded; otherwise, <see cref="AvbIOResult.ErrorNoSuchPartition"/>.</returns>
    AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData);

    /// <summary>
    /// Reads a persistent value from secure storage.
    /// </summary>
    /// <param name="name">The name of the persistent value.</param>
    /// <param name="bufferSize">The size of the output buffer.</param>
    /// <param name="outBuffer">The output buffer to store the value.</param>
    /// <param name="outBytesRead">The actual number of bytes read.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ReadPersistentValue(string name, int bufferSize, Span<byte> outBuffer, out int outBytesRead);

    /// <summary>
    /// Writes a persistent value to secure storage.
    /// </summary>
    /// <param name="name">The name of the persistent value.</param>
    /// <param name="valueSize">The size of the value to write.</param>
    /// <param name="value">The binary value to store.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult WritePersistentValue(string name, int valueSize, ReadOnlySpan<byte> value);

    /// <summary>
    /// Validates a public key for a specific partition (Chained partitions).
    /// </summary>
    /// <param name="partition">The name of the chained partition.</param>
    /// <param name="publicKeyData">The binary data of the public key.</param>
    /// <param name="publicKeyMetadata">The optional public key metadata.</param>
    /// <param name="isTrusted">Set to <c>true</c> if the public key is trusted; otherwise, <c>false</c>.</param>
    /// <param name="rollbackIndexLocation">Returns the rollback index location for this partition.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ValidatePublicKeyForPartition(string partition, ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isTrusted, out uint rollbackIndexLocation);

    /// <summary>
    /// Reads A/B metadata from persistent or recovery storage.
    /// </summary>
    /// <param name="data">The output A/B metadata structure.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult ReadAbMetadata(out AvbAbData data);

    /// <summary>
    /// Writes A/B metadata to persistent or recovery storage.
    /// </summary>
    /// <param name="data">The A/B metadata to store.</param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.</returns>
    AvbIOResult WriteAbMetadata(AvbAbData data);
}
