using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Abstractions;

/// <summary>
/// Defines the operation interface for Android Verified Boot (AVB), equivalent to the 'AvbOps' struct
/// in libavb. Implementing this interface allows the library to interact with device storage and properties.
/// <para>定义Android Verified Boot (AVB)的操作接口，等价于libavb中的'AvbOps'结构。</para>
/// <para>实现此接口允许库与设备存储和属性进行交互。</para>
/// </summary>
public interface IAvbOps
{
    /// <summary>
    /// Reads data from a specific partition.
    /// <para>从特定分区读取数据。</para>
    /// </summary>
    /// <param name="partitionName">The name of the partition to read from (e.g., "boot", "vbmeta").
    /// <para>要读取的分区名称（例如"boot"，"vbmeta"）。</para></param>
    /// <param name="offset">The byte offset within the partition.
    /// <para>分区内的字节偏移量。</para></param>
    /// <param name="numBytes">The number of bytes to read.
    /// <para>要读取的字节数。</para></param>
    /// <param name="buffer">The output buffer to store the read data.
    /// <para>存储读取数据的输出缓冲区。</para></param>
    /// <param name="bytesRead">The actual number of bytes read.
    /// <para>实际读取的字节数。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead);

    /// <summary>
    /// Writes data to a specific partition.
    /// <para>向特定分区写入数据。</para>
    /// </summary>
    /// <param name="partitionName">The name of the partition to write to.
    /// <para>要写入的分区名称。</para></param>
    /// <param name="offset">The byte offset within the partition.
    /// <para>分区内的字节偏移量。</para></param>
    /// <param name="numBytes">The number of bytes to write.
    /// <para>要写入的字节数。</para></param>
    /// <param name="buffer">The data buffer containing the bytes to write.
    /// <para>包含要写入字节的数据缓冲区。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer);

    /// <summary>
    /// Validates a VBMeta public key against the device's root of trust.
    /// <para>根据设备的信任根验证VBMeta公钥。</para>
    /// </summary>
    /// <param name="publicKeyData">The binary data of the public key to validate.
    /// <para>要验证的公钥的二进制数据。</para></param>
    /// <param name="publicKeyMetadata">The optional public key metadata.
    /// <para>可选的公钥元数据。</para></param>
    /// <param name="isValid">Set to <c>true</c> if the public key is trusted; otherwise, <c>false</c>.
    /// <para>如果公钥受信任则设置为<c>true</c>；否则为<c>false</c>。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid);

    /// <summary>
    /// Reads the rollback index for the specified location.
    /// <para>读取指定位置的回滚索引。</para>
    /// </summary>
    /// <param name="rollbackIndexLocation">The index location (0 to 31).
    /// <para>索引位置（0到31）。</para></param>
    /// <param name="rollbackIndex">The stored rollback index.
    /// <para>存储的回滚索引。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ReadRollbackIndex(int rollbackIndexLocation, out ulong rollbackIndex);

    /// <summary>
    /// Writes a new rollback index for the specified location.
    /// <para>为指定位置写入新的回滚索引。</para>
    /// </summary>
    /// <param name="rollbackIndexLocation">The index location (0 to 31).
    /// <para>索引位置（0到31）。</para></param>
    /// <param name="rollbackIndex">The new rollback index value.
    /// <para>新的回滚索引值。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult WriteRollbackIndex(int rollbackIndexLocation, ulong rollbackIndex);

    /// <summary>
    /// Checks if the device is currently unlocked (verification bypassed).
    /// <para>检查设备当前是否解锁（验证已绕过）。</para>
    /// </summary>
    /// <param name="isUnlocked">Set to <c>true</c> if the device is unlocked; otherwise, <c>false</c>.
    /// <para>如果设备已解锁则设置为<c>true</c>；否则为<c>false</c>。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked);

    /// <summary>
    /// Retrieves a unique GUID for the specified partition.
    /// <para>检索指定分区的唯一GUID。</para>
    /// </summary>
    /// <param name="partitionName">The partition name.
    /// <para>分区名称。</para></param>
    /// <param name="guid">The unique identifier (e.g., PARTUUID) of the partition.
    /// <para>分区的唯一标识符（例如PARTUUID）。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid);

    /// <summary>
    /// Gets the total size of the specified partition.
    /// <para>获取指定分区的总大小。</para>
    /// </summary>
    /// <param name="partitionName">The partition name.
    /// <para>分区名称。</para></param>
    /// <param name="size">The total partition size in bytes.
    /// <para>分区总大小（以字节为单位）。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult GetSizeOfPartition(string partitionName, out long size);

    /// <summary>
    /// Checks if a partition is preloaded into memory (e.g., by the bootloader).
    /// <para>检查分区是否已预加载到内存中（例如由引导加载程序）。</para>
    /// </summary>
    /// <param name="partitionName">The partition name.
    /// <para>分区名称。</para></param>
    /// <param name="numBytes">The number of bytes required.
    /// <para>需要的字节数。</para></param>
    /// <param name="preloadedData">The span containing preloaded data if available.
    /// <para>如果可用，包含预加载数据的跨度。</para></param>
    /// <returns><see cref="AvbIOResult.Ok"/> if preloaded; otherwise, <see cref="AvbIOResult.ErrorNoSuchPartition"/>.
    /// <para>如果已预加载则为<see cref="AvbIOResult.Ok"/>；否则为<see cref="AvbIOResult.ErrorNoSuchPartition"/>。</para></returns>
    AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData);

    /// <summary>
    /// Reads a persistent value from secure storage.
    /// <para>从安全存储中读取持久值。</para>
    /// </summary>
    /// <param name="name">The name of the persistent value.
    /// <para>持久值的名称。</para></param>
    /// <param name="bufferSize">The size of the output buffer.
    /// <para>输出缓冲区的大小。</para></param>
    /// <param name="outBuffer">The output buffer to store the value.
    /// <para>存储值的输出缓冲区。</para></param>
    /// <param name="outBytesRead">The actual number of bytes read.
    /// <para>实际读取的字节数。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ReadPersistentValue(string name, int bufferSize, Span<byte> outBuffer, out int outBytesRead);

    /// <summary>
    /// Writes a persistent value to secure storage.
    /// <para>向安全存储写入持久值。</para>
    /// </summary>
    /// <param name="name">The name of the persistent value.
    /// <para>持久值的名称。</para></param>
    /// <param name="valueSize">The size of the value to write.
    /// <para>要写入的值的大小。</para></param>
    /// <param name="value">The binary value to store.
    /// <para>要存储的二进制值。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult WritePersistentValue(string name, int valueSize, ReadOnlySpan<byte> value);

    /// <summary>
    /// Validates a public key for a specific partition (Chained partitions).
    /// <para>验证特定分区（链式分区）的公钥。</para>
    /// </summary>
    /// <param name="partition">The name of the chained partition.
    /// <para>链式分区的名称。</para></param>
    /// <param name="publicKeyData">The binary data of the public key.
    /// <para>公钥的二进制数据。</para></param>
    /// <param name="publicKeyMetadata">The optional public key metadata.
    /// <para>可选的公钥元数据。</para></param>
    /// <param name="isTrusted">Set to <c>true</c> if the public key is trusted; otherwise, <c>false</c>.
    /// <para>如果公钥受信任则设置为<c>true</c>；否则为<c>false</c>。</para></param>
    /// <param name="rollbackIndexLocation">Returns the rollback index location for this partition.
    /// <para>返回此分区的回滚索引位置。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ValidatePublicKeyForPartition(string partition, ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isTrusted, out uint rollbackIndexLocation);

    /// <summary>
    /// Reads A/B metadata from persistent or recovery storage.
    /// <para>从持久或恢复存储中读取A/B元数据。</para>
    /// </summary>
    /// <param name="data">The output A/B metadata structure.
    /// <para>输出的A/B元数据结构。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult ReadAbMetadata(out AvbAbData data);

    /// <summary>
    /// Writes A/B metadata to persistent or recovery storage.
    /// <para>向持久或恢复存储写入A/B元数据。</para>
    /// </summary>
    /// <param name="data">The A/B metadata to store.
    /// <para>要存储的A/B元数据。</para></param>
    /// <returns>An <see cref="AvbIOResult"/> indicating the success or failure of the operation.
    /// <para>指示操作成功或失败的<see cref="AvbIOResult"/>。</para></returns>
    AvbIOResult WriteAbMetadata(AvbAbData data);
}