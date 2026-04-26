using FirmwareKit.AVB.Abstractions;

namespace FirmwareKit.AVB.Enums;

/// <summary>
/// Tags for different types of AVB descriptors.
/// <para>不同类型AVB描述符的标签。</para>
/// </summary>
public enum AvbDescriptorTag : ulong
{
    /// <summary>
    /// The property descriptor.
    /// <para>属性描述符。</para>
    /// </summary>
    Property = 0,
    /// <summary>
    /// The hashtree descriptor.
    /// <para>哈希树描述符。</para>
    /// </summary>
    Hashtree = 1,
    /// <summary>
    /// The hash descriptor.
    /// <para>哈希描述符。</para>
    /// </summary>
    Hash = 2,
    /// <summary>
    /// The kernel command-line descriptor.
    /// <para>内核命令行描述符。</para>
    /// </summary>
    KernelCmdline = 3,
    /// <summary>
    /// The chain partition descriptor.
    /// <para>链式分区描述符。</para>
    /// </summary>
    ChainPartition = 4,
}

/// <summary>
/// Flags used in kernel command-line descriptors.
/// <para>内核命令行描述符中使用的标志。</para>
/// </summary>
[Flags]
public enum AvbKernelCmdlineFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Apply the descriptor only if hashtree is NOT disabled.
    /// <para>仅当哈希树未禁用时应用描述符。</para>
    /// </summary>
    UseOnlyIfHashtreeNotDisabled = 1 << 0,
    /// <summary>
    /// Apply the descriptor only if hashtree IS disabled.
    /// <para>仅当哈希树已禁用时应用描述符。</para>
    /// </summary>
    UseOnlyIfHashtreeDisabled = 1 << 1,
}

/// <summary>
/// Digest types used in AVB.
/// <para>AVB中使用的摘要类型。</para>
/// </summary>
public enum AvbDigestType : uint
{
    /// <summary>
    /// SHA-256 digest.
    /// <para>SHA-256摘要。</para>
    /// </summary>
    Sha256 = 0,
    /// <summary>
    /// SHA-512 digest.
    /// <para>SHA-512摘要。</para>
    /// </summary>
    Sha512 = 1,
}

/// <summary>
/// Flags for hashtree descriptors.
/// <para>哈希树描述符的标志。</para>
/// </summary>
[Flags]
public enum AvbHashtreeDescriptorFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Do not append A/B suffix to the partition name.
    /// <para>不要向分区名称追加A/B后缀。</para>
    /// </summary>
    DoNotUseAb = 1 << 0,
    /// <summary>
    /// Check at most once.
    /// <para>最多检查一次。</para>
    /// </summary>
    CheckAtMostOnce = 1 << 1,
}

/// <summary>
/// Flags for hash descriptors.
/// <para>哈希描述符的标志。</para>
/// </summary>
[Flags]
public enum AvbHashDescriptorFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Do not append A/B suffix to the partition name.
    /// <para>不要向分区名称追加A/B后缀。</para>
    /// </summary>
    DoNotUseAb = 1 << 0,
}

/// <summary>
/// Flags for chain partition descriptors.
/// <para>链式分区描述符的标志。</para>
/// </summary>
[Flags]
public enum AvbChainPartitionDescriptorFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Do not append A/B suffix to the partition name.
    /// <para>不要向分区名称追加A/B后缀。</para>
    /// </summary>
    DoNotUseAb = 1 << 0,
}

/// <summary>
/// Flags for VBMeta images.
/// <para>VBMeta镜像的标志。</para>
/// </summary>
[Flags]
public enum AvbVBMetaImageFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Hashtree image verification will be disabled.
    /// <para>哈希树镜像验证将被禁用。</para>
    /// </summary>
    HashtreeDisabled = 1 << 0,
    /// <summary>
    /// Verification will be disabled and descriptors will not be parsed.
    /// <para>验证将被禁用，描述符将不会被解析。</para>
    /// </summary>
    VerificationDisabled = 1 << 1,
}

/// <summary>
/// Result of a VBMeta image integrity verification.
/// <para>VBMeta镜像完整性验证的结果。</para>
/// </summary>
public enum AvbVBMetaVerifyResult
{
    /// <summary>
    /// Verification successful.
    /// <para>验证成功。</para>
    /// </summary>
    Ok,
    /// <summary>
    /// Image is valid but not signed.
    /// <para>镜像有效但未签名。</para>
    /// </summary>
    OkNotSigned,
    /// <summary>
    /// The VBMeta header is invalid.
    /// <para>VBMeta头无效。</para>
    /// </summary>
    InvalidVBMetaHeader,
    /// <summary>
    /// The AVB version is unsupported.
    /// <para>AVB版本不受支持。</para>
    /// </summary>
    UnsupportedVersion,
    /// <summary>
    /// The image hash does not match the header.
    /// <para>镜像哈希与头不匹配。</para>
    /// </summary>
    HashMismatch,
    /// <summary>
    /// The signature does not match the public key.
    /// <para>签名与公钥不匹配。</para>
    /// </summary>
    SignatureMismatch,
}

/// <summary>
/// AVB algorithm types combining a hash and an RSA key size.
/// <para>结合哈希和RSA密钥大小的AVB算法类型。</para>
/// </summary>
public enum AvbAlgorithmType : uint
{
    /// <summary>
    /// No algorithm (unprotected).
    /// <para>无算法（未受保护）。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// SHA256 with constant-time RSA-2048.
    /// <para>带常量时间RSA-2048的SHA256。</para>
    /// </summary>
    Sha256Rsa2048 = 1,
    /// <summary>
    /// SHA256 with constant-time RSA-4096.
    /// <para>带常量时间RSA-4096的SHA256。</para>
    /// </summary>
    Sha256Rsa4096 = 2,
    /// <summary>
    /// SHA256 with constant-time RSA-8192.
    /// <para>带常量时间RSA-8192的SHA256。</para>
    /// </summary>
    Sha256Rsa8192 = 3,
    /// <summary>
    /// SHA512 with constant-time RSA-2048.
    /// <para>带常量时间RSA-2048的SHA512。</para>
    /// </summary>
    Sha512Rsa2048 = 4,
    /// <summary>
    /// SHA512 with constant-time RSA-4096.
    /// <para>带常量时间RSA-4096的SHA512。</para>
    /// </summary>
    Sha512Rsa4096 = 5,
    /// <summary>
    /// SHA512 with constant-time RSA-8192.
    /// <para>带常量时间RSA-8192的SHA512。</para>
    /// </summary>
    Sha512Rsa8192 = 6,
}

/// <summary>
/// Result codes for A/B flow operations.
/// <para>A/B流程操作的结果代码。</para>
/// </summary>
public enum AvbAbFlowResult
{
    /// <summary>
    /// Success.
    /// <para>成功。</para>
    /// </summary>
    Ok,
    /// <summary>
    /// Success, but with a recoverable verification error.
    /// <para>成功，但有可恢复的验证错误。</para>
    /// </summary>
    OkWithVerificationError,
    /// <summary>
    /// Out of memory.
    /// <para>内存不足。</para>
    /// </summary>
    ErrorOom,
    /// <summary>
    /// I/O error.
    /// <para>I/O错误。</para>
    /// </summary>
    ErrorIo,
    /// <summary>
    /// No bootable slots found.
    /// <para>未找到可启动的槽位。</para>
    /// </summary>
    ErrorNoBootableSlot,
    /// <summary>
    /// Invalid argument provided.
    /// <para>提供了无效的参数。</para>
    /// </summary>
    ErrorInvalidArgument,
}

/// <summary>
/// Result codes for slot verification operations.
/// <para>槽位验证操作的结果代码。</para>
/// </summary>
public enum AvbSlotVerifyResult
{
    /// <summary>
    /// Success.
    /// <para>成功。</para>
    /// </summary>
    Ok,
    /// <summary>
    /// Out of memory.
    /// <para>内存不足。</para>
    /// </summary>
    ErrorOom,
    /// <summary>
    /// I/O error.
    /// <para>I/O错误。</para>
    /// </summary>
    ErrorIo,
    /// <summary>
    /// Verification failed or partition data corrupted.
    /// <para>验证失败或分区数据损坏。</para>
    /// </summary>
    ErrorVerification,
    /// <summary>
    /// Rollback index check failed.
    /// <para>回滚索引检查失败。</para>
    /// </summary>
    ErrorRollbackIndex,
    /// <summary>
    /// Public key rejected.
    /// <para>公钥被拒绝。</para>
    /// </summary>
    ErrorPublicKeyRejected,
    /// <summary>
    /// Metadata (VBMeta, Header, etc.) is invalid.
    /// <para>元数据（VBMeta、头文件等）无效。</para>
    /// </summary>
    ErrorInvalidMetadata,
    /// <summary>
    /// The required AVB version is not supported.
    /// <para>所需的AVB版本不受支持。</para>
    /// </summary>
    ErrorUnsupportedVersion,
    /// <summary>
    /// Invalid argument provided.
    /// <para>提供了无效的参数。</para>
    /// </summary>
    ErrorInvalidArgument,
}

/// <summary>
/// Enumeration for hashtree error handling modes.
/// <para>哈希树错误处理模式的枚举。</para>
/// </summary>
public enum AvbHashtreeErrorMode
{
    /// <summary>
    /// Restart the device and invalidate the slot on error.
    /// <para>出错时重启设备并使槽位无效。</para>
    /// </summary>
    RestartAndInvalidate,
    /// <summary>
    /// Restart the device on error.
    /// <para>出错时重启设备。</para>
    /// </summary>
    Restart,
    /// <summary>
    /// Return EIO (I/O error) on data corruption.
    /// <para>数据损坏时返回EIO（I/O错误）。</para>
    /// </summary>
    Eio,
    /// <summary>
    /// Log the error but continue.
    /// <para>记录错误但继续。</para>
    /// </summary>
    Logging,
    /// <summary>
    /// Managed mode: Switch between Restart and Eio.
    /// <para>托管模式：在Restart和Eio之间切换。</para>
    /// </summary>
    ManagedRestartAndEio,
    /// <summary>
    /// Panic the kernel immediately.
    /// <para>立即使内核崩溃。</para>
    /// </summary>
    Panic,
}

/// <summary>
/// Flags for slot verification.
/// <para>槽位验证的标志。</para>
/// </summary>
[Flags]
public enum AvbSlotVerifyFlags : uint
{
    /// <summary>
    /// No flags.
    /// <para>无标志。</para>
    /// </summary>
    None = 0,
    /// <summary>
    /// Allow verification errors (e.g., for unlocked devices).
    /// <para>允许验证错误（例如，对于解锁的设备）。</para>
    /// </summary>
    AllowVerificationError = 1 << 0,
    /// <summary>
    /// Indicates that the restart was caused by a hashtree corruption.
    /// <para>表示重启是由哈希树损坏引起的。</para>
    /// </summary>
    RestartCausedByHashtreeCorruption = 1 << 1,
    /// <summary>
    /// Do not look for a dedicated 'vbmeta' partition.
    /// <para>不要寻找专用的'vbmeta'分区。</para>
    /// </summary>
    NoVbmetaPartition = 1 << 2,
}

/// <summary>
/// Generic I/O result codes for <see cref="IAvbOps"/>.
/// <para><see cref="IAvbOps"/>的通用I/O结果代码。</para>
/// </summary>
public enum AvbIOResult
{
    /// <summary>
    /// I/O operation successful.
    /// <para>I/O操作成功。</para>
    /// </summary>
    Ok,
    /// <summary>
    /// Out of memory.
    /// <para>内存不足。</para>
    /// </summary>
    ErrorOom,
    /// <summary>
    /// Generic I/O error.
    /// <para>通用I/O错误。</para>
    /// </summary>
    ErrorIo,
    /// <summary>
    /// Requested partition does not exist.
    /// <para>请求的分区不存在。</para>
    /// </summary>
    ErrorNoSuchPartition,
    /// <summary>
    /// Requested range is outside the partition boundaries.
    /// <para>请求的范围超出分区边界。</para>
    /// </summary>
    ErrorRangeOutsidePartition,
    /// <summary>
    /// Requested persistent value does not exist.
    /// <para>请求的持久值不存在。</para>
    /// </summary>
    ErrorNoSuchValue,
    /// <summary>
    /// The value size is invalid for the requested operation.
    /// <para>请求操作的值大小无效。</para>
    /// </summary>
    ErrorInvalidValueSize,
    /// <summary>
    /// The provided buffer has insufficient space.
    /// <para>提供的缓冲区空间不足。</para>
    /// </summary>
    ErrorInsufficientSpace,
}

/// <summary>
/// Lock state for certificate-based verified boot.
/// Equivalent to 'AvbCertLockState' in libavb_cert examples.
/// <para>基于证书的验证启动的锁定状态。</para>
/// <para>等价于libavb_cert示例中的'AvbCertLockState'。</para>
/// </summary>
public enum AvbCertLockState
{
    /// <summary>
    /// Device is locked; verification errors are not allowed.
    /// <para>设备已锁定；不允许验证错误。</para>
    /// </summary>
    Locked,
    /// <summary>
    /// Device is unlocked; verification errors are allowed.
    /// <para>设备已解锁；允许验证错误。</para>
    /// </summary>
    Unlocked,
}

/// <summary>
/// Slot state indicating whether the slot has been marked as successfully booted.
/// Equivalent to 'AvbCertSlotState' in libavb_cert examples.
/// <para>指示槽位是否已标记为成功启动的槽位状态。</para>
/// <para>等价于libavb_cert示例中的'AvbCertSlotState'。</para>
/// </summary>
public enum AvbCertSlotState
{
    /// <summary>
    /// The slot has been marked as successfully booted.
    /// <para>槽位已标记为成功启动。</para>
    /// </summary>
    MarkedSuccessful,
    /// <summary>
    /// The slot has not been marked as successfully booted.
    /// <para>槽位未标记为成功启动。</para>
    /// </summary>
    NotMarkedSuccessful,
}

/// <summary>
/// Indicates whether OEM-specific bootloader data is used.
/// Equivalent to 'AvbCertOemDataState' in libavb_cert examples.
/// <para>指示是否使用OEM特定的引导加载程序数据。</para>
/// <para>等价于libavb_cert示例中的'AvbCertOemDataState'。</para>
/// </summary>
public enum AvbCertOemDataState
{
    /// <summary>
    /// OEM-specific bootloader data is used; verify 'oem_bootloader' partition.
    /// <para>使用OEM特定的引导加载程序数据；验证'oem_bootloader'分区。</para>
    /// </summary>
    Used,
    /// <summary>
    /// OEM-specific bootloader data is not used; skip 'oem_bootloader' partition.
    /// <para>不使用OEM特定的引导加载程序数据；跳过'oem_bootloader'分区。</para>
    /// </summary>
    NotUsed,
}