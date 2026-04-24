namespace FirmwareKit.AVB;

/// <summary>
/// Tags for different types of AVB descriptors.
/// </summary>
public enum AvbDescriptorTag : ulong
{
    /// <summary>The property descriptor.</summary>
    Property = 0,
    /// <summary>The hashtree descriptor.</summary>
    Hashtree = 1,
    /// <summary>The hash descriptor.</summary>
    Hash = 2,
    /// <summary>The kernel command-line descriptor.</summary>
    KernelCmdline = 3,
    /// <summary>The chain partition descriptor.</summary>
    ChainPartition = 4,
}

/// <summary>
/// Flags used in kernel command-line descriptors.
/// </summary>
[Flags]
public enum AvbKernelCmdlineFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Apply the descriptor only if hashtree is NOT disabled.</summary>
    UseOnlyIfHashtreeNotDisabled = 1 << 0,
    /// <summary>Apply the descriptor only if hashtree IS disabled.</summary>
    UseOnlyIfHashtreeDisabled = 1 << 1,
}

/// <summary>
/// Digest types used in AVB.
/// </summary>
public enum AvbDigestType : uint
{
    /// <summary>SHA-256 digest.</summary>
    Sha256 = 0,
    /// <summary>SHA-512 digest.</summary>
    Sha512 = 1,
}

/// <summary>
/// Flags for hashtree descriptors.
/// </summary>
[Flags]
public enum AvbHashtreeDescriptorFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Do not append A/B suffix to the partition name.</summary>
    DoNotUseAb = 1 << 0,
    /// <summary>Check at most once.</summary>
    CheckAtMostOnce = 1 << 1,
}

/// <summary>
/// Flags for hash descriptors.
/// </summary>
[Flags]
public enum AvbHashDescriptorFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Do not append A/B suffix to the partition name.</summary>
    DoNotUseAb = 1 << 0,
}

/// <summary>
/// Flags for chain partition descriptors.
/// </summary>
[Flags]
public enum AvbChainPartitionDescriptorFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Do not append A/B suffix to the partition name.</summary>
    DoNotUseAb = 1 << 0,
}

/// <summary>
/// Flags for VBMeta images.
/// </summary>
[Flags]
public enum AvbVBMetaImageFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Hashtree image verification will be disabled.</summary>
    HashtreeDisabled = 1 << 0,
    /// <summary>Verification will be disabled and descriptors will not be parsed.</summary>
    VerificationDisabled = 1 << 1,
}

/// <summary>
/// Result of a VBMeta image integrity verification.
/// </summary>
public enum AvbVBMetaVerifyResult
{
    /// <summary>Verification successful.</summary>
    Ok,
    /// <summary>Image is valid but not signed.</summary>
    OkNotSigned,
    /// <summary>The VBMeta header is invalid.</summary>
    InvalidVBMetaHeader,
    /// <summary>The AVB version is unsupported.</summary>
    UnsupportedVersion,
    /// <summary>The image hash does not match the header.</summary>
    HashMismatch,
    /// <summary>The signature does not match the public key.</summary>
    SignatureMismatch,
}

/// <summary>
/// AVB algorithm types combining a hash and an RSA key size.
/// </summary>
public enum AvbAlgorithmType : uint
{
    /// <summary>No algorithm (unprotected).</summary>
    None = 0,
    /// <summary>SHA256 with constant-time RSA-2048.</summary>
    Sha256Rsa2048 = 1,
    /// <summary>SHA256 with constant-time RSA-4096.</summary>
    Sha256Rsa4096 = 2,
    /// <summary>SHA256 with constant-time RSA-8192.</summary>
    Sha256Rsa8192 = 3,
    /// <summary>SHA512 with constant-time RSA-2048.</summary>
    Sha512Rsa2048 = 4,
    /// <summary>SHA512 with constant-time RSA-4096.</summary>
    Sha512Rsa4096 = 5,
    /// <summary>SHA512 with constant-time RSA-8192.</summary>
    Sha512Rsa8192 = 6,
}

/// <summary>
/// Result codes for A/B flow operations.
/// </summary>
public enum AvbAbFlowResult
{
    /// <summary>Success.</summary>
    Ok,
    /// <summary>Success, but with a recoverable verification error.</summary>
    OkWithVerificationError,
    /// <summary>Out of memory.</summary>
    ErrorOom,
    /// <summary>I/O error.</summary>
    ErrorIo,
    /// <summary>No bootable slots found.</summary>
    ErrorNoBootableSlot,
    /// <summary>Invalid argument provided.</summary>
    ErrorInvalidArgument,
}

/// <summary>
/// Result codes for slot verification operations.
/// </summary>
public enum AvbSlotVerifyResult
{
    /// <summary>Success.</summary>
    Ok,
    /// <summary>Out of memory.</summary>
    ErrorOom,
    /// <summary>I/O error.</summary>
    ErrorIo,
    /// <summary>Verification failed or partition data corrupted.</summary>
    ErrorVerification,
    /// <summary>Rollback index check failed.</summary>
    ErrorRollbackIndex,
    /// <summary>Public key rejected.</summary>
    ErrorPublicKeyRejected,
    /// <summary>Metadata (VBMeta, Header, etc.) is invalid.</summary>
    ErrorInvalidMetadata,
    /// <summary>The required AVB version is not supported.</summary>
    ErrorUnsupportedVersion,
    /// <summary>Invalid argument provided.</summary>
    ErrorInvalidArgument,
}

/// <summary>
/// Enumeration for hashtree error handling modes.
/// </summary>
public enum AvbHashtreeErrorMode
{
    /// <summary>Restart the device and invalidate the slot on error.</summary>
    RestartAndInvalidate,
    /// <summary>Restart the device on error.</summary>
    Restart,
    /// <summary>Return EIO (I/O error) on data corruption.</summary>
    Eio,
    /// <summary>Log the error but continue.</summary>
    Logging,
    /// <summary>Managed mode: Switch between Restart and Eio.</summary>
    ManagedRestartAndEio,
    /// <summary>Panic the kernel immediately.</summary>
    Panic,
}

/// <summary>
/// Flags for slot verification.
/// </summary>
[Flags]
public enum AvbSlotVerifyFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0,
    /// <summary>Allow verification errors (e.g., for unlocked devices).</summary>
    AllowVerificationError = 1 << 0,
    /// <summary>Indicates that the restart was caused by a hashtree corruption.</summary>
    RestartCausedByHashtreeCorruption = 1 << 1,
    /// <summary>Do not look for a dedicated 'vbmeta' partition.</summary>
    NoVbmetaPartition = 1 << 2,
}

/// <summary>
/// Generic I/O result codes for <see cref="IAvbOps"/>.
/// </summary>
public enum AvbIOResult
{
    /// <summary>I/O operation successful.</summary>
    Ok,
    /// <summary>Out of memory.</summary>
    ErrorOom,
    /// <summary>Generic I/O error.</summary>
    ErrorIo,
    /// <summary>Requested partition does not exist.</summary>
    ErrorNoSuchPartition,
    /// <summary>Requested range is outside the partition boundaries.</summary>
    ErrorRangeOutsidePartition,
    /// <summary>Requested persistent value does not exist.</summary>
    ErrorNoSuchValue,
    /// <summary>The value size is invalid for the requested operation.</summary>
    ErrorInvalidValueSize,
    /// <summary>The provided buffer has insufficient space.</summary>
    ErrorInsufficientSpace,
}
