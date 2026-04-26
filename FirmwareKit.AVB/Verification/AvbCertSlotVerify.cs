using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Security;

namespace FirmwareKit.AVB.Verification;

/// <summary>
/// Certificate-based slot verification that integrates libavb_cert with avb_slot_verify.
/// Equivalent to 'avb_cert_slot_verify.c' in libavb_cert examples.
/// <para>基于证书的槽验证，集成了libavb_cert和avb_slot_verify。</para>
/// <para>等价于libavb_cert示例中的'avb_cert_slot_verify.c'。</para>
/// </summary>
public static class AvbCertSlotVerify
{
    private const int MaxRollbackIndexLocations = 32;
    private const ulong RollbackIndexIncreaseThreshold = 1000000000;
    private const ulong RollbackIndexNotUsed = 0;

    private static readonly string[] PartitionsWithoutOem = ["boot"];
    private static readonly string[] PartitionsWithOem = ["boot", "oem_bootloader"];

    /// <summary>
    /// Performs a full verification of the slot identified by <paramref name="abSuffix"/> using certificate-based trust.
    /// Equivalent to 'avb_cert_slot_verify()' in libavb_cert examples.
    /// <para>使用基于证书的信任对由<paramref name="abSuffix"/>标识的槽执行完整验证。</para>
    /// <para>等价于libavb_cert示例中的'avb_cert_slot_verify()'。</para>
    /// </summary>
    /// <param name="certOps">Certificate operations providing platform trust anchors and key version tracking.
    /// <para>提供平台信任锚和密钥版本跟踪的证书操作。</para></param>
    /// <param name="abSuffix">The A/B suffix for the slot to verify (e.g., "_a" or "_b").
    /// <para>要验证的槽的A/B后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="lockState">Whether the device is locked or unlocked.
    /// <para>设备是锁定还是解锁。</para></param>
    /// <param name="slotState">Whether the slot has been marked as successfully booted.
    /// <para>槽是否已被标记为成功启动。</para></param>
    /// <param name="oemDataState">Whether OEM-specific bootloader data is used.
    /// <para>是否使用OEM特定的引导加载程序数据。</para></param>
    /// <param name="verifyData">The result of the verification, containing loaded partition data and VBMeta information.
    /// <para>验证结果，包含已加载的分区数据和VBMeta信息。</para></param>
    /// <param name="vbmetaDigest">On success, the SHA-256 vbmeta digest for device attestation.
    /// <para>成功时，用于设备证明的SHA-256 vbmeta摘要。</para></param>
    /// <returns>A value from <see cref="AvbSlotVerifyResult"/> indicating overall verification success.
    /// <para>来自<see cref="AvbSlotVerifyResult"/>的值，指示整体验证是否成功。</para></returns>
    public static AvbSlotVerifyResult CertSlotVerify(
        IAvbCertOps certOps,
        string abSuffix,
        AvbCertLockState lockState,
        AvbCertSlotState slotState,
        AvbCertOemDataState oemDataState,
        out AvbSlotVerifyData? verifyData,
        out byte[] vbmetaDigest)
    {
        verifyData = null;
        vbmetaDigest = new byte[AvbCertConstants.Digest256Size];

        var context = new KeyVersionContext();
        var wrappedCertOps = new CertOpsWithContext(certOps, context);

        var partitions = oemDataState == AvbCertOemDataState.NotUsed
            ? PartitionsWithoutOem
            : PartitionsWithOem;

        var flags = lockState == AvbCertLockState.Unlocked
            ? AvbSlotVerifyFlags.AllowVerificationError
            : AvbSlotVerifyFlags.None;

        var verifier = new AvbSlotVerifier(certOps.Ops);
        var result = verifier.VerifySlot(partitions, abSuffix, flags, AvbHashtreeErrorMode.Eio, out verifyData);

        if (result != AvbSlotVerifyResult.Ok || lockState == AvbCertLockState.Unlocked)
        {
            return result;
        }

        vbmetaDigest = AvbSlotVerifier.CalculateVBMetaDigest(verifyData!, AvbDigestType.Sha256);

        if (slotState == AvbCertSlotState.MarkedSuccessful)
        {
            for (var i = 0; i < MaxRollbackIndexLocations; i++)
            {
                var rollbackIndexValue = verifyData!.RollbackIndexes[i];
                if (rollbackIndexValue != RollbackIndexNotUsed)
                {
                    result = UpdateRollbackIndex(certOps.Ops, i, rollbackIndexValue);
                    if (result != AvbSlotVerifyResult.Ok)
                    {
                        verifyData = null;
                        return result;
                    }
                }
            }

            for (var i = 0; i < MaxRollbackIndexLocations; i++)
            {
                var rollbackIndexLocation = context.Locations[i];
                var rollbackIndexValue = context.Values[i];
                if (rollbackIndexValue != RollbackIndexNotUsed)
                {
                    result = UpdateRollbackIndex(certOps.Ops, rollbackIndexLocation, rollbackIndexValue);
                    if (result != AvbSlotVerifyResult.Ok)
                    {
                        verifyData = null;
                        return result;
                    }
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Updates the stored rollback index value for <paramref name="location"/> to match <paramref name="value"/>.
    /// Equivalent to 'update_rollback_index()' in avb_cert_slot_verify.c.
    /// <para>更新<paramref name="location"/>的存储回滚索引值以匹配<paramref name="value"/>。</para>
    /// <para>等价于avb_cert_slot_verify.c中的'update_rollback_index()'。</para>
    /// </summary>
    /// <param name="ops">The AVB platform operations.
    /// <para>AVB平台操作。</para></param>
    /// <param name="location">The rollback index location.
    /// <para>回滚索引位置。</para></param>
    /// <param name="value">The desired rollback index value.
    /// <para>所需的回滚索引值。</para></param>
    /// <returns>A value from <see cref="AvbSlotVerifyResult"/> indicating success or failure.
    /// <para>来自<see cref="AvbSlotVerifyResult"/>的值，指示成功或失败。</para></returns>
    private static AvbSlotVerifyResult UpdateRollbackIndex(IAvbOps ops, int location, ulong value)
    {
        var ioResult = ops.ReadRollbackIndex(location, out var currentValue);
        if (ioResult == AvbIOResult.ErrorOom)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        if (ioResult != AvbIOResult.Ok)
        {
            return AvbSlotVerifyResult.ErrorIo;
        }

        if (currentValue == value)
        {
            return AvbSlotVerifyResult.Ok;
        }

        if (value - currentValue > RollbackIndexIncreaseThreshold)
        {
            return AvbSlotVerifyResult.ErrorRollbackIndex;
        }

        if (value < currentValue)
        {
            return AvbSlotVerifyResult.ErrorRollbackIndex;
        }

        ioResult = ops.WriteRollbackIndex(location, value);
        if (ioResult == AvbIOResult.ErrorOom)
        {
            return AvbSlotVerifyResult.ErrorOom;
        }

        if (ioResult != AvbIOResult.Ok)
        {
            return AvbSlotVerifyResult.ErrorIo;
        }

        return AvbSlotVerifyResult.Ok;
    }

    private sealed class KeyVersionContext
    {
        public readonly int[] Locations = new int[MaxRollbackIndexLocations];
        public readonly ulong[] Values = new ulong[MaxRollbackIndexLocations];
        public int NextSlot;

        public void Save(int rollbackIndexLocation, ulong keyVersion)
        {
            if (NextSlot < MaxRollbackIndexLocations)
            {
                Locations[NextSlot] = rollbackIndexLocation;
                Values[NextSlot] = keyVersion;
                NextSlot++;
            }
        }
    }

    private sealed class CertOpsWithContext : IAvbCertOps
    {
        private readonly IAvbCertOps _inner;
        private readonly KeyVersionContext _context;

        public CertOpsWithContext(IAvbCertOps inner, KeyVersionContext context)
        {
            _inner = inner;
            _context = context;
        }

        public IAvbOps Ops => _inner.Ops;

        public AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes attributes) =>
            _inner.ReadPermanentAttributes(out attributes);

        public AvbIOResult ReadPermanentAttributesHash(Span<byte> hash) =>
            _inner.ReadPermanentAttributesHash(hash);

        public void SetKeyVersion(int rollbackIndexLocation, ulong keyVersion) =>
            _context.Save(rollbackIndexLocation, keyVersion);

        public AvbIOResult GetRandomBytes(Span<byte> output) =>
            _inner.GetRandomBytes(output);
    }
}