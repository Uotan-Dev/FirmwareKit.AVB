using System.Security.Cryptography;

namespace FirmwareKit.AVB;
/// <summary>
/// Contains data from a loaded and verified VBMeta image.
/// Equivalent to 'AvbVBMetaData' in libavb.
/// </summary>
/// <param name="PartitionName">The name of the partition the VBMeta image was loaded from.</param>
/// <param name="VbMetaBytes">The raw bytes of the VBMeta image.</param>
/// <param name="VerifyResult">The result of verifying the VBMeta image.</param>
public record AvbVBMetaData(string PartitionName, byte[] VbMetaBytes, AvbVBMetaVerifyResult VerifyResult);

/// <summary>
/// Contains data from a loaded and verified partition.
/// Equivalent to 'AvbPartitionData' in libavb.
/// </summary>
/// <param name="PartitionName">The name of the partition.</param>
/// <param name="Data">The loaded partition data (if requested and successful).</param>
/// <param name="DataSize">The size of the data in bytes.</param>
/// <param name="Preloaded">Whether the data was preloaded.</param>
/// <param name="VerifyResult">The result of verifying the partition.</param>
/// <param name="Digest">The calculated digest of the partition data.</param>
/// <param name="DigestType">The algorithm used to calculate the digest.</param>
public record AvbPartitionData(
    string PartitionName,
    byte[] Data,
    long DataSize,
    bool Preloaded,
    AvbSlotVerifyResult VerifyResult,
    byte[] Digest,
    AvbDigestType DigestType);

/// <summary>
/// High-level data structure returned by <see cref="AvbSlotVerifier.VerifySlot"/>.
/// Equivalent to 'AvbSlotVerifyData' in libavb.
/// </summary>
public class AvbSlotVerifyData
{
    /// <summary>Gets or sets the A/B suffix used for the slot (e.g., "_a" or "_b").</summary>
    public string AbSuffix { get; set; } = string.Empty;

    /// <summary>Gets the list of loaded VBMeta images.</summary>
    public List<AvbVBMetaData> VbmetaImages { get; } = [];

    /// <summary>Gets the list of loaded/verified partitions.</summary>
    public List<AvbPartitionData> LoadedPartitions { get; } = [];

    /// <summary>Gets the additional command-line substitutions (e.g., for persistent digests).</summary>
    public Dictionary<string, string> AdditionalSubstitutions { get; } = [];

    /// <summary>Gets or sets the generated kernel command-line fragment.</summary>
    public string Cmdline { get; set; } = string.Empty;

    /// <summary>Gets or sets the multi-partition VBMeta digest.</summary>
    public byte[] VbmetaDigest { get; set; } = [];

    /// <summary>Gets or sets the public key of the top-level VBMeta image.</summary>
    public byte[] ToplevelPublicKey { get; set; } = [];

    /// <summary>Gets or sets the flags from the top-level VBMeta image header.</summary>
    public uint ToplevelVBMetaFlags { get; set; }

    /// <summary>Gets or sets the algorithm type used by the top-level VBMeta image.</summary>
    public AvbAlgorithmType ToplevelAlgorithmType { get; set; }

    /// <summary>Gets or sets the final hashtree error mode resolved for the kernel.</summary>
    public AvbHashtreeErrorMode ResolvedHashtreeErrorMode { get; set; }

    /// <summary>Gets the rollback indexes for each of the 32 possible locations.</summary>
    public ulong[] RollbackIndexes { get; } = new ulong[32];
}

/// <summary>
/// Provides high-level Android Verified Boot (AVB) slot verification logic.
/// Equivalent to the 'avb_slot_verify.c' implementation in libavb.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="AvbSlotVerifier"/> class.
/// </remarks>
/// <param name="ops">The <see cref="IAvbOps"/> implementation for platform I/O.</param>
public class AvbSlotVerifier(IAvbOps ops)
{
    private readonly IAvbOps _ops = ops;
    private const string PersistentDigestPrefix = "avb.persistent_digest.";
    private const string ManagedVerityModeKey = "avb.managed_verity_mode";
    private const int MaxVbmetaImages = 32;
    private const int MaxLoadedPartitions = 32;

    /// <summary>
    /// High-level function that loads and verifies partitions for a specific slot.
    /// Equivalent to 'avb_slot_verify()' in libavb.
    /// </summary>
    /// <param name="requestedPartitions">List of extra partitions to load and verify.</param>
    /// <param name="abSuffix">The A/B suffix for the slot to verify (e.g., "_a" or "_b").</param>
    /// <param name="flags">Verification flags.</param>
    /// <param name="hashtreeErrorMode">The initial hashtree error mode.</param>
    /// <param name="outData">The result of the verification, containing loaded partition data and VBMeta information.</param>
    /// <returns>A value from <see cref="AvbSlotVerifyResult"/> indicating overall verification success.</returns>
    public AvbSlotVerifyResult VerifySlot(
        string[]? requestedPartitions,
        string abSuffix,
        AvbSlotVerifyFlags flags,
        AvbHashtreeErrorMode hashtreeErrorMode,
        out AvbSlotVerifyData? outData)
    {
        outData = null;
        var slotData = new AvbSlotVerifyData { AbSuffix = abSuffix };
        var allowVerificationError = (flags & AvbSlotVerifyFlags.AllowVerificationError) != 0;

        if (hashtreeErrorMode == AvbHashtreeErrorMode.Logging && !allowVerificationError)
        {
            return AvbSlotVerifyResult.ErrorInvalidArgument;
        }

        AvbSlotVerifyResult ret;
        if ((flags & AvbSlotVerifyFlags.NoVbmetaPartition) != 0)
        {
            if (requestedPartitions == null || requestedPartitions.Length == 0)
            {
                return AvbSlotVerifyResult.ErrorInvalidArgument;
            }

            foreach (var part in requestedPartitions)
            {
                ret = LoadAndVerifyVBMeta(
                    part,
                    abSuffix,
                    flags,
                    allowVerificationError,
                    0,
                    0,
                    null,
                    requestedPartitions,
                    slotData,
                    out _);
                if (!AllowErrorAndContinue(ret, allowVerificationError) && ret != AvbSlotVerifyResult.Ok)
                {
                    return ret;
                }
            }
            ret = AvbSlotVerifyResult.Ok;
        }
        else
        {
            ret = LoadAndVerifyVBMeta(
                "vbmeta",
                abSuffix,
                flags,
                allowVerificationError,
                0,
                0,
                null,
                requestedPartitions,
                slotData,
                out _);
            if (!AllowErrorAndContinue(ret, allowVerificationError) && ret != AvbSlotVerifyResult.Ok)
            {
                return ret;
            }
        }

        if (ret == AvbSlotVerifyResult.Ok || (allowVerificationError && IsRecoverable(ret)))
        {
            if (slotData.VbmetaImages.Count > 0 &&
                (slotData.ToplevelVBMetaFlags & (uint)AvbVBMetaImageFlags.VerificationDisabled) != 0)
            {
                // Verification disabled: only set basic command line
                slotData.Cmdline = _ops.GetUniqueGuidForPartition("system" + abSuffix, out _) == AvbIOResult.Ok ? "root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)" : "";
            }
            else
            {
                slotData.ResolvedHashtreeErrorMode = hashtreeErrorMode;

                // Calculate VBMeta Digest (AOSP avb_slot_verify.c: calculate_vbmeta_digest)
                var topAlgo = slotData.ToplevelAlgorithmType;
                var digestType = topAlgo <= AvbAlgorithmType.Sha256Rsa8192 ? AvbDigestType.Sha256 : AvbDigestType.Sha512;

                slotData.VbmetaDigest = CalculateVBMetaDigest(slotData, digestType);

                // avb_manage_hashtree_error_mode
                if (hashtreeErrorMode == AvbHashtreeErrorMode.ManagedRestartAndEio)
                {
                    var manageRet = ManageHashtreeErrorMode(flags, slotData, out var managedMode);
                    if (manageRet != AvbIOResult.Ok)
                    {
                        return manageRet == AvbIOResult.ErrorOom ? AvbSlotVerifyResult.ErrorOom : AvbSlotVerifyResult.ErrorIo;
                    }
                    slotData.ResolvedHashtreeErrorMode = managedMode;
                }

                // Generate full command line including descriptors and options
                slotData.Cmdline = AvbCmdlineGenerator.Generate(slotData, _ops, flags, hashtreeErrorMode);
            }

            // Substitute $(ANDROID_SYSTEM_PARTUUID) and friends (AOSP avb_sub_cmdline equivalent)
            if (!string.IsNullOrEmpty(slotData.Cmdline))
            {
                slotData.Cmdline = AvbCmdlineGenerator.SubstituteTokens(slotData.Cmdline, slotData, _ops, abSuffix);
            }

            outData = slotData;
            return ret;
        }

        return ret;
    }
    /// <summary>
    /// Manages the hashtree error mode for and from persistent storage.
    /// Equivalent to 'avb_manage_hashtree_error_mode()' in libavb.
    /// </summary>
    /// <param name="flags">The verification flags.</param>
    /// <param name="data">The verification data.</param>
    /// <param name="outMode">The resolved hashtree error mode.</param>
    /// <returns>The result of the I/O operation.</returns>
    private AvbIOResult ManageHashtreeErrorMode(
        AvbSlotVerifyFlags flags,
        AvbSlotVerifyData data,
        out AvbHashtreeErrorMode outMode)
    {
        outMode = AvbHashtreeErrorMode.Restart;

        var restartCausedByCorruption = (flags & AvbSlotVerifyFlags.RestartCausedByHashtreeCorruption) != 0;

        var currentDigest = CalculateVBMetaDigest(data, AvbDigestType.Sha256);

        if (restartCausedByCorruption)
        {
            if (_ops.WritePersistentValue(ManagedVerityModeKey, currentDigest.Length, currentDigest) != AvbIOResult.Ok)
            {
                return AvbIOResult.ErrorIo;
            }
            outMode = AvbHashtreeErrorMode.Eio;
            return AvbIOResult.Ok;
        }

        var storedDigest = new byte[32]; // SHA256
        var ioRet = _ops.ReadPersistentValue(ManagedVerityModeKey, 32, storedDigest, out var read);

        if (ioRet == AvbIOResult.ErrorNoSuchPartition || ioRet == AvbIOResult.ErrorNoSuchValue || (ioRet == AvbIOResult.Ok && read == 0))
        {
            outMode = AvbHashtreeErrorMode.Restart;
            return AvbIOResult.Ok;
        }
        else if (ioRet != AvbIOResult.Ok)
        {
            return ioRet;
        }

        if (read == 32 && currentDigest.AsSpan().SequenceEqual(storedDigest))
        {
            outMode = AvbHashtreeErrorMode.Eio;
        }
        else
        {
            _ops.WritePersistentValue(ManagedVerityModeKey, 0, []);
            outMode = AvbHashtreeErrorMode.Restart;
        }

        return AvbIOResult.Ok;
    }

    /// <summary>
    /// Determines whether a verification error is considered recoverable.
    /// Equivalent to 'is_recoverable()' in libavb.
    /// </summary>
    /// <param name="result">The verification result to check.</param>
    /// <returns>True if the error is recoverable, false otherwise.</returns>
    private bool IsRecoverable(AvbSlotVerifyResult result) => result switch
    {
        AvbSlotVerifyResult.Ok => true,
        AvbSlotVerifyResult.ErrorVerification => true,
        AvbSlotVerifyResult.ErrorRollbackIndex => true,
        AvbSlotVerifyResult.ErrorPublicKeyRejected => true,
        AvbSlotVerifyResult.ErrorOom or
        AvbSlotVerifyResult.ErrorIo or
        AvbSlotVerifyResult.ErrorInvalidMetadata or
        AvbSlotVerifyResult.ErrorUnsupportedVersion or
        AvbSlotVerifyResult.ErrorInvalidArgument => false,
        _ => false
    };

    /// <summary>
    /// Loads and verifies a VBMeta image from a partition.
    /// Equivalent to 'load_and_verify_vbmeta()' in libavb.
    /// </summary>
    /// <param name="partitionName">The name of the partition to load from.</param>
    /// <param name="abSuffix">The A/B suffix for the slot.</param>
    /// <param name="flags">Verification flags.</param>
    /// <param name="allowVerificationError">Whether to continue on recoverable errors.</param>
    /// <param name="toplevelVBMetaFlags">The flags from the top-level VBMeta image.</param>
    /// <param name="rollbackIndexLocation">The rollback index location for this metadata.</param>
    /// <param name="expectedPublicKey">The expected public key (for chained partitions).</param>
    /// <param name="requestedPartitions">List of partitions requested for loading.</param>
    /// <param name="slotData">The verification data object.</param>
    /// <param name="algorithmType">Outputs the algorithm type used by the VBMeta image.</param>
    /// <param name="useAbSuffix">Whether to append the A/B suffix to the partition name.</param>
    /// <returns>The result of the loader operation.</returns>
    private AvbSlotVerifyResult LoadAndVerifyVBMeta(
        string partitionName,
        string abSuffix,
        AvbSlotVerifyFlags flags,
        bool allowVerificationError,
        uint toplevelVBMetaFlags,
        uint rollbackIndexLocation,
        byte[]? expectedPublicKey,
        string[]? requestedPartitions,
        AvbSlotVerifyData slotData,
        out AvbAlgorithmType algorithmType,
        bool useAbSuffix = true)
    {
        var ret = AvbSlotVerifyResult.Ok;
        algorithmType = AvbAlgorithmType.None;
        var fullPartitionName = partitionName + (useAbSuffix ? abSuffix : "");

        var isMainVbmeta = false;
        if (rollbackIndexLocation == 0 && (flags & AvbSlotVerifyFlags.NoVbmetaPartition) == 0)
        {
            isMainVbmeta = true;
        }

        var lookForFooter = !partitionName.StartsWith("vbmeta");

        var ioRet = _ops.GetSizeOfPartition(fullPartitionName, out var size);
        if (ioRet != AvbIOResult.Ok)
        {
            return isMainVbmeta && ioRet == AvbIOResult.ErrorNoSuchPartition && !lookForFooter
                ? LoadAndVerifyVBMeta("boot", abSuffix, flags, allowVerificationError, toplevelVBMetaFlags, 0, null, requestedPartitions, slotData, out algorithmType, true)
                : AvbSlotVerifyResult.ErrorIo;
        }

        byte[] vbmetaBytes;
        long vbmetaOffset = 0;
        var vbmetaSize = 65536;

        if (lookForFooter)
        {
            var footerBytes = new byte[AvbFooter.Size];
            var ioRetFooter = _ops.ReadFromPartition(fullPartitionName, size - AvbFooter.Size, AvbFooter.Size, footerBytes, out _);
            if (ioRetFooter == AvbIOResult.Ok)
            {
                var footer = AvbFooter.FromBytes(footerBytes);
                if (footer.IsValid)
                {
                    vbmetaOffset = (long)footer.VBMetaOffset;
                    vbmetaSize = (int)footer.VBMetaSize;

                    if (vbmetaOffset < 0 || vbmetaSize < 0 || (vbmetaOffset + vbmetaSize) > size)
                    {
                        return AvbSlotVerifyResult.ErrorInvalidMetadata;
                    }
                }
            }
        }

        if (vbmetaSize > size)
        {
            vbmetaSize = (int)size;
        }

        if (vbmetaOffset == 0 && _ops.GetPreloadedPartition(fullPartitionName, vbmetaSize, out var preloaded) == AvbIOResult.Ok)
        {
            vbmetaBytes = preloaded.ToArray();
        }
        else
        {
            vbmetaBytes = new byte[vbmetaSize];
            if (_ops.ReadFromPartition(fullPartitionName, vbmetaOffset, vbmetaSize, vbmetaBytes, out var read) != AvbIOResult.Ok)
            {
                return AvbSlotVerifyResult.ErrorIo;
            }
        }

        var image = new AvbVBMetaImage(vbmetaBytes);
        var actualVbmetaSize = AvbVBMetaImageHeader.Size + (int)image.Header.AuthenticationDataBlockSize + (int)image.Header.AuxiliaryDataBlockSize;
        var verifyResult = image.VerifyIntegrity();

        if (verifyResult != AvbVBMetaVerifyResult.Ok)
        {
            if (verifyResult is AvbVBMetaVerifyResult.HashMismatch or AvbVBMetaVerifyResult.SignatureMismatch or AvbVBMetaVerifyResult.OkNotSigned)
            {
                ret = AvbSlotVerifyResult.ErrorVerification;
                if (!AllowErrorAndContinue(AvbSlotVerifyResult.ErrorVerification, allowVerificationError))
                {
                    return AvbSlotVerifyResult.ErrorVerification;
                }
            }
            else
            {
                return verifyResult == AvbVBMetaVerifyResult.UnsupportedVersion
                    ? AvbSlotVerifyResult.ErrorUnsupportedVersion
                    : AvbSlotVerifyResult.ErrorInvalidMetadata;
            }
        }

        if (slotData.VbmetaImages.Count == 0)
        {
            slotData.ToplevelVBMetaFlags = image.Header.Flags;
            slotData.ToplevelAlgorithmType = (AvbAlgorithmType)image.Header.AlgorithmType;
            slotData.ToplevelPublicKey = image.AuxiliaryData.Span.Slice((int)image.Header.PublicKeyOffset, (int)image.Header.PublicKeySize).ToArray();
            toplevelVBMetaFlags = image.Header.Flags;
        }
        else
        {
            if (image.Header.Flags != 0)
            {
                return AvbSlotVerifyResult.ErrorInvalidMetadata;
            }
        }

        if ((image.Header.Flags & (uint)AvbVBMetaImageFlags.VerificationDisabled) != 0)
        {
            slotData.VbmetaImages.Add(new AvbVBMetaData(partitionName, vbmetaBytes.AsSpan(0, (int)actualVbmetaSize).ToArray(), verifyResult));
            return LoadRequestedPartitions(requestedPartitions, abSuffix, slotData);
        }

        var isTrusted = false;
        var rollbackLocationToUse = rollbackIndexLocation;

        if (expectedPublicKey != null)
        {
            var pubkey = image.AuxiliaryData.Span.Slice((int)image.Header.PublicKeyOffset, (int)image.Header.PublicKeySize);
            if (!pubkey.SequenceEqual(expectedPublicKey))
            {
                return AvbSlotVerifyResult.ErrorPublicKeyRejected;
            }

            isTrusted = true;
        }
        else
        {
            var pubkey = image.AuxiliaryData.Span.Slice((int)image.Header.PublicKeyOffset, (int)image.Header.PublicKeySize);
            var metadata = image.AuxiliaryData.Span.Slice((int)image.Header.PublicKeyMetadataOffset, (int)image.Header.PublicKeyMetadataSize);

            if ((flags & AvbSlotVerifyFlags.NoVbmetaPartition) != 0)
            {
                _ops.ValidatePublicKeyForPartition(partitionName, pubkey, metadata, out isTrusted, out rollbackLocationToUse);
            }
            else
            {
                _ops.ValidateVBMetaPublicKey(pubkey, metadata, out isTrusted);
            }
        }

        if (!isTrusted)
        {
            ret = AvbSlotVerifyResult.ErrorPublicKeyRejected;
            if (!AllowErrorAndContinue(AvbSlotVerifyResult.ErrorPublicKeyRejected, allowVerificationError))
            {
                return AvbSlotVerifyResult.ErrorPublicKeyRejected;
            }
        }

        if (isMainVbmeta)
        {
            rollbackLocationToUse = image.Header.RollbackIndexLocation;
        }

        if (rollbackLocationToUse >= 32)
        {
            return AvbSlotVerifyResult.ErrorInvalidMetadata;
        }

        var rollbackIORet = _ops.ReadRollbackIndex((int)rollbackLocationToUse, out var storedRollback);
        if (rollbackIORet != AvbIOResult.Ok)
        {
            return rollbackIORet == AvbIOResult.ErrorOom ? AvbSlotVerifyResult.ErrorOom : AvbSlotVerifyResult.ErrorIo;
        }

        if (image.Header.RollbackIndex < storedRollback)
        {
            ret = AvbSlotVerifyResult.ErrorRollbackIndex;
            if (!AllowErrorAndContinue(AvbSlotVerifyResult.ErrorRollbackIndex, allowVerificationError))
            {
                return AvbSlotVerifyResult.ErrorRollbackIndex;
            }
        }

        if (image.Header.RollbackIndex > slotData.RollbackIndexes[rollbackLocationToUse])
        {
            slotData.RollbackIndexes[rollbackLocationToUse] = image.Header.RollbackIndex;
        }

        if (slotData.VbmetaImages.Count >= MaxVbmetaImages)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        if (actualVbmetaSize < (uint)vbmetaBytes.Length)
        {
            vbmetaBytes = vbmetaBytes.AsSpan(0, (int)actualVbmetaSize).ToArray();
        }

        if (slotData.VbmetaImages.Count >= MaxVbmetaImages)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        slotData.VbmetaImages.Add(new AvbVBMetaData(partitionName, vbmetaBytes, verifyResult));
        algorithmType = (AvbAlgorithmType)image.Header.AlgorithmType;

        foreach (var desc in image.GetDescriptors())
        {
            if (desc is AvbHashDescriptor hash)
            {
                var subRet = LoadAndVerifyHashPartition(abSuffix, allowVerificationError, requestedPartitions, hash, slotData, out var digest);
                if (subRet != AvbSlotVerifyResult.Ok)
                {
                    ret = subRet;
                    if (!AllowErrorAndContinue(subRet, allowVerificationError) || !IsRecoverable(subRet))
                    {
                        return subRet;
                    }
                }
                else
                {
                    if (hash.Digest.Length == 0)
                    {
                        var hex = AvbCompat.ToHexString(digest).ToLowerInvariant();
                        var token = $"$(AVB_{hash.PartitionName.ToUpperInvariant()}_ROOT_DIGEST)";
                        slotData.AdditionalSubstitutions[token] = hex;
                    }
                }
            }
            else if (desc is AvbChainPartitionDescriptor chain)
            {
                if (!isMainVbmeta)
                {
                    return AvbSlotVerifyResult.ErrorInvalidMetadata;
                }

                var chainedPart = chain.PartitionName;
                var chainKey = chain.PublicKey;
                var useAbSuffixForChain = (chain.Flags & AvbChainPartitionDescriptorFlags.DoNotUseAb) == 0;

                var subRet = LoadAndVerifyVBMeta(chainedPart, abSuffix, flags, allowVerificationError, toplevelVBMetaFlags, chain.RollbackIndexLocation, chainKey, requestedPartitions, slotData, out _, useAbSuffixForChain);
                if (subRet != AvbSlotVerifyResult.Ok)
                {
                    ret = subRet;
                    if (!AllowErrorAndContinue(subRet, allowVerificationError) || !IsRecoverable(subRet))
                    {
                        return subRet;
                    }
                }
            }
            else if (desc is AvbHashtreeDescriptor hashtree)
            {
                var rootDigest = hashtree.RootDigest;
                if (rootDigest.Length == 0)
                {
                    // AOSP: No ab_suffix for partitions without a digest in the descriptor
                    // because these partitions hold data unique to this device and are
                    // not updated using an A/B scheme.
                    if ((hashtree.Flags & AvbHashtreeDescriptorFlags.DoNotUseAb) == 0 && abSuffix.Length > 0)
                    {
                        return AvbSlotVerifyResult.ErrorInvalidMetadata;
                    }

                    var digestLen = AvbCrypto.GetDigestSize(hashtree.HashAlgorithm);
                    var subRet = LoadAndVerifyPersistentDigest(hashtree.PartitionName, abSuffix, (hashtree.Flags & AvbHashtreeDescriptorFlags.DoNotUseAb) == 0, digestLen, [], out rootDigest);
                    if (subRet != AvbSlotVerifyResult.Ok)
                    {
                        ret = subRet;
                        if (!AllowErrorAndContinue(subRet, allowVerificationError) || !IsRecoverable(subRet))
                        {
                            return subRet;
                        }
                    }
                }

                if (rootDigest.Length > 0)
                {
                    var hex = AvbCompat.ToHexString(rootDigest).ToLowerInvariant();
                    var token = hashtree.PartitionName == "system"
                        ? "$(ANDROID_SYSTEM_ROOT_DIGEST)"
                        : $"$(AVB_{hashtree.PartitionName.ToUpperInvariant()}_ROOT_DIGEST)";
                    slotData.AdditionalSubstitutions[token] = hex;
                }

                if (requestedPartitions == null || requestedPartitions.Any(p => p == hashtree.PartitionName))
                {
                    slotData.LoadedPartitions.Add(new AvbPartitionData(
                        hashtree.PartitionName,
                        [],
                        0,
                        false,
                        AvbSlotVerifyResult.Ok,
                        rootDigest,
                        hashtree.HashAlgorithm.ToLowerInvariant() == "sha512" ? AvbDigestType.Sha512 : AvbDigestType.Sha256));
                }
            }
        }

        return ret;
    }

    /// <summary>
    /// Loads and verifies a persistent digest for a partition.
    /// Equivalent to 'load_and_verify_persistent_digest()' in libavb.
    /// </summary>
    /// <param name="partitionName">The name of the partition.</param>
    /// <param name="abSuffix">The A/B suffix for the slot.</param>
    /// <param name="useAbSuffix">Whether to use the A/B suffix.</param>
    /// <param name="digestLen">The expected length of the digest.</param>
    /// <param name="initialDigest">Initial digest to write if not present.</param>
    /// <param name="digest">Outputs the loaded/initialized digest.</param>
    /// <returns>The result of the loader operation.</returns>
    private AvbSlotVerifyResult LoadAndVerifyPersistentDigest(
        string partitionName,
        string abSuffix,
        bool useAbSuffix,
        int digestLen,
        ReadOnlySpan<byte> initialDigest,
        out byte[] digest)
    {
        digest = new byte[digestLen];
        var fullPartitionName = partitionName + (useAbSuffix ? abSuffix : "");
        var persistentKey = PersistentDigestPrefix + fullPartitionName;

        var ioRet = _ops.ReadPersistentValue(persistentKey, digestLen, digest, out var read);
        if (ioRet == AvbIOResult.Ok && read == digestLen)
        {
            return AvbSlotVerifyResult.Ok;
        }

        if (ioRet == AvbIOResult.ErrorNoSuchPartition || ioRet == AvbIOResult.ErrorNoSuchValue || (ioRet == AvbIOResult.Ok && read == 0))
        {
            if (initialDigest.IsEmpty)
            {
                return AvbSlotVerifyResult.ErrorVerification;
            }

            if (_ops.ReadIsDeviceUnlocked(out var unlocked) != AvbIOResult.Ok)
            {
                return AvbSlotVerifyResult.ErrorIo;
            }

            if (unlocked)
            {
                return AvbSlotVerifyResult.ErrorVerification;
            }

            if (_ops.WritePersistentValue(persistentKey, initialDigest.Length, initialDigest) != AvbIOResult.Ok)
            {
                return AvbSlotVerifyResult.ErrorIo;
            }

            initialDigest.CopyTo(digest);
            return AvbSlotVerifyResult.Ok;
        }

        return ioRet is AvbIOResult.ErrorInvalidValueSize or AvbIOResult.ErrorInsufficientSpace
            ? AvbSlotVerifyResult.ErrorInvalidMetadata
            : ioRet == AvbIOResult.ErrorOom ? AvbSlotVerifyResult.ErrorOom : AvbSlotVerifyResult.ErrorIo;
    }

    /// <summary>
    /// Calculates the aggregate VBMeta digest across all loaded VBMeta images.
    /// Equivalent to 'calculate_vbmeta_digest()' in libavb.
    /// </summary>
    /// <param name="data">The verification data containing the loaded VBMeta images.</param>
    /// <param name="digestType">The type of digest to calculate (SHA256 or SHA512).</param>
    /// <returns>A byte array containing the calculated digest.</returns>
    public static byte[] CalculateVBMetaDigest(AvbSlotVerifyData data, AvbDigestType digestType)
    {
        using var hash = digestType == AvbDigestType.Sha256
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
            : IncrementalHash.CreateHash(HashAlgorithmName.SHA512);

        foreach (var img in data.VbmetaImages)
        {
            hash.AppendData(img.VbMetaBytes);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>
    /// Loads any partitions that were explicitly requested.
    /// Equivalent to 'load_requested_partitions()' in libavb.
    /// </summary>
    /// <param name="requestedPartitions">List of extra partitions requested for loading.</param>
    /// <param name="abSuffix">The A/B suffix for the slot.</param>
    /// <param name="slotData">The current verification data.</param>
    /// <returns>The result of the loader operation.</returns>
    private AvbSlotVerifyResult LoadRequestedPartitions(string[]? requestedPartitions, string abSuffix, AvbSlotVerifyData slotData)
    {
        if (requestedPartitions == null)
        {
            return AvbSlotVerifyResult.Ok;
        }

        foreach (var part in requestedPartitions)
        {
            if (slotData.LoadedPartitions.Any(p => p.PartitionName == part))
            {
                continue;
            }

            var ret = LoadFullPartition(part, abSuffix, slotData, out _);
            if (ret != AvbSlotVerifyResult.Ok)
            {
                return ret;
            }
        }

        return AvbSlotVerifyResult.Ok;
    }

    /// <summary>
    /// Loads the full content of a partition.
    /// Equivalent to 'load_full_partition()' in libavb.
    /// </summary>
    /// <param name="partitionName">The name of the partition.</param>
    /// <param name="abSuffix">The A/B suffix for the slot.</param>
    /// <param name="slotData">The current verification data.</param>
    /// <param name="data">Outputs the full partition content.</param>
    /// <returns>The result of the loader operation.</returns>
    private AvbSlotVerifyResult LoadFullPartition(string partitionName, string abSuffix, AvbSlotVerifyData slotData, out byte[] data)
    {
        data = [];
        var fullPartName = partitionName + abSuffix;

        if (slotData.LoadedPartitions.Any(p => p.PartitionName == partitionName))
        {
            data = slotData.LoadedPartitions.First(p => p.PartitionName == partitionName).Data;
            return AvbSlotVerifyResult.Ok;
        }

        if (slotData.LoadedPartitions.Count >= MaxLoadedPartitions)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        if (_ops.GetSizeOfPartition(fullPartName, out var size) != AvbIOResult.Ok)
        {
            return AvbSlotVerifyResult.ErrorIo;
        }

        var isPreloaded = false;
        if (_ops.GetPreloadedPartition(fullPartName, (int)size, out var preloaded) == AvbIOResult.Ok)
        {
            data = preloaded.ToArray();
            isPreloaded = true;
        }
        else
        {
            data = new byte[size];
            if (_ops.ReadFromPartition(fullPartName, 0, (int)size, data, out _) != AvbIOResult.Ok)
            {
                return AvbSlotVerifyResult.ErrorIo;
            }
        }

        slotData.LoadedPartitions.Add(new AvbPartitionData(
            partitionName,
            data,
            size,
            isPreloaded,
            AvbSlotVerifyResult.Ok,
            [],
            AvbDigestType.Sha256));

        return AvbSlotVerifyResult.Ok;
    }

    /// <summary>
    /// Loads and verifies a hash partition.
    /// Equivalent to 'load_and_verify_hash_partition()' in libavb.
    /// </summary>
    /// <param name="abSuffix">The A/B suffix for the slot.</param>
    /// <param name="allowVerificationError">Whether to continue on recoverable errors.</param>
    /// <param name="requestedPartitions">List of partitions requested for loading.</param>
    /// <param name="hash">The hash descriptor to follow.</param>
    /// <param name="slotData">The current verification data.</param>
    /// <param name="outDigest">The computed hash of the partition.</param>
    /// <returns>The result of the loader operation.</returns>
    private AvbSlotVerifyResult LoadAndVerifyHashPartition(
        string abSuffix,
        bool allowVerificationError,
        string[]? requestedPartitions,
        AvbHashDescriptor hash,
        AvbSlotVerifyData slotData,
        out byte[] outDigest)
    {
        outDigest = [];
        if (requestedPartitions != null && !requestedPartitions.Any(p => p == hash.PartitionName))
        {
            return AvbSlotVerifyResult.Ok;
        }

        var partName = hash.PartitionName + ((hash.Flags & AvbHashDescriptorFlags.DoNotUseAb) == 0 ? abSuffix : "");

        if (_ops.GetSizeOfPartition(partName, out var size) != AvbIOResult.Ok)
        {
            return AvbSlotVerifyResult.ErrorIo;
        }

        if (hash.ImageSize > (ulong)size)
        {
            return AvbSlotVerifyResult.ErrorInvalidMetadata;
        }

        var imageSizeToLoad = (long)hash.ImageSize;
        if (allowVerificationError)
        {
            imageSizeToLoad = size;
        }

        byte[] partData;
        var isPreloaded = false;
        if (_ops.GetPreloadedPartition(partName, (int)imageSizeToLoad, out var preloaded) == AvbIOResult.Ok)
        {
            partData = preloaded.ToArray();
            isPreloaded = true;
        }
        else
        {
            partData = new byte[imageSizeToLoad];
            if (_ops.ReadFromPartition(partName, 0, (int)imageSizeToLoad, partData, out _) != AvbIOResult.Ok)
            {
                return AvbSlotVerifyResult.ErrorIo;
            }
        }

        var lengthToHash = Math.Min((long)hash.ImageSize, imageSizeToLoad);
        var calculatedHash = AvbCrypto.CalculateHash(hash.HashAlgorithm, hash.Salt, partData.AsSpan(0, (int)lengthToHash));
        outDigest = calculatedHash;

        byte[]? expectedDigest = null;
        if (hash.Digest.Length == 0)
        {
            if (!string.IsNullOrEmpty(abSuffix))
            {
                return AvbSlotVerifyResult.ErrorInvalidMetadata;
            }

            var persistentRet = LoadAndVerifyPersistentDigest(hash.PartitionName, abSuffix, (hash.Flags & AvbHashDescriptorFlags.DoNotUseAb) == 0, calculatedHash.Length, calculatedHash, out var persisted);
            if (persistentRet != AvbSlotVerifyResult.Ok)
            {
                return persistentRet;
            }

            expectedDigest = persisted;
        }
        else
        {
            expectedDigest = hash.Digest;
        }

        var partitionVerifyResult = AvbSlotVerifyResult.Ok;
        if (!calculatedHash.AsSpan().SequenceEqual(expectedDigest))
        {
            partitionVerifyResult = AvbSlotVerifyResult.ErrorVerification;
            if (!AllowErrorAndContinue(AvbSlotVerifyResult.ErrorVerification, allowVerificationError))
            {
                return AvbSlotVerifyResult.ErrorVerification;
            }
        }

        if (slotData.LoadedPartitions.Count >= MaxLoadedPartitions)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        slotData.LoadedPartitions.Add(new AvbPartitionData(
            hash.PartitionName,
            partData,
            imageSizeToLoad,
            isPreloaded,
            partitionVerifyResult,
            calculatedHash,
            hash.HashAlgorithm.ToLowerInvariant() == "sha512" ? AvbDigestType.Sha512 : AvbDigestType.Sha256));

        return partitionVerifyResult;
    }

    /// <summary>
    /// Checks whether to allow an error and continue.
    /// Equivalent to 'allow_error_and_continue()' in libavb.
    /// </summary>
    /// <param name="res">The verification result to check.</param>
    /// <param name="allow">Whether the caller allows errors.</param>
    /// <returns>True if the error is recoverable and allowed, false otherwise.</returns>
    private bool AllowErrorAndContinue(AvbSlotVerifyResult res, bool allow) => allow && IsRecoverable(res);
}
