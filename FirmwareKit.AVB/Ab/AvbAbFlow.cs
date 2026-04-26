using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using FirmwareKit.AVB.Verification;

namespace FirmwareKit.AVB.Ab;

/// <summary>
/// Implements the A/B boot flow logic for Android Verified Boot, equivalent to 'libavb_ab'.
/// This class handles slot selection and metadata management for devices with two bootable slots.
/// <para>实现Android Verified Boot的A/B启动流程逻辑，等价于'libavb_ab'。</para>
/// <para>此类处理具有两个可启动槽位设备的槽位选择和元数据管理。</para>
/// </summary>
public sealed class AvbAbFlow
{
    private readonly IAvbOps _ops;
    private static readonly string[] SlotSuffixes = new[] { "_a", "_b" };

    /// <summary>
    /// Initializes a new instance of the <see cref="AvbAbFlow"/> class.
    /// <para>初始化<see cref="AvbAbFlow"/>类的新实例。</para>
    /// </summary>
    public AvbAbFlow(IAvbOps ops)
    {
        _ops = ops;
    }

    /// <summary>
    /// Converts A/B flow result to a stable libavb-style string.
    /// Equivalent to 'avb_ab_flow_result_to_string()'.
    /// <para>将A/B流程结果转换为稳定的libavb风格字符串。</para>
    /// <para>等价于'avb_ab_flow_result_to_string()'。</para>
    /// </summary>
    public static string ResultToString(AvbAbFlowResult result) => AvbResultStrings.ToLibAvbString(result);

    /// <summary>
    /// Selects the best bootable slot based on the A/B metadata and verification results.
    /// <para>根据A/B元数据和验证结果选择最佳可启动槽位。</para>
    /// </summary>
    /// <param name="slotSuffix">Returns the suffix of the selected slot (e.g., "_a" or "_b").
    /// <para>返回所选槽位的后缀（例如"_a"或"_b"）。</para></param>
    /// <param name="verifyData">Returns the verification data for the selected slot.
    /// <para>返回所选槽位的验证数据。</para></param>
    /// <param name="flags">The verification flags.
    /// <para>验证标志。</para></param>
    /// <param name="hashtreeErrorMode">The hashtree error mode.
    /// <para>哈希树错误模式。</para></param>
    /// <returns>An <see cref="AvbAbFlowResult"/> indicating the result of the selection process.
    /// <para>指示选择过程结果的<see cref="AvbAbFlowResult"/>。</para></returns>
    public AvbAbFlowResult SelectSlot(out string slotSuffix, out AvbSlotVerifyData? verifyData, AvbSlotVerifyFlags flags = AvbSlotVerifyFlags.None, AvbHashtreeErrorMode hashtreeErrorMode = AvbHashtreeErrorMode.Restart)
    {
        slotSuffix = "";
        verifyData = null;

        var ioRet = _ops.ReadAbMetadata(out var abData);
        if (ioRet != AvbIOResult.Ok)
        {
            if (ioRet == AvbIOResult.ErrorOom)
            {
                return AvbAbFlowResult.ErrorOom;
            }
            abData = AvbAbData.CreateDefault();
            _ops.WriteAbMetadata(abData);
        }

        if (!abData.IsValid())
        {
            abData = AvbAbData.CreateDefault();
            _ops.WriteAbMetadata(abData);
        }

        var abDataOrig = abData;
        abData.SlotA = NormalizeSlot(abData.SlotA);
        abData.SlotB = NormalizeSlot(abData.SlotB);

        var slotVerifier = new AvbSlotVerifier(_ops);
        var slotVerifyData = new AvbSlotVerifyData?[2];
        var sawAndAllowedVerificationError = false;

        for (var n = 0; n < 2; n++)
        {
            var currentSlot = n == 0 ? abData.SlotA : abData.SlotB;
            if (IsBootable(currentSlot))
            {
                var result = slotVerifier.VerifySlot(null, SlotSuffixes[n], flags, hashtreeErrorMode, out var data);
                var setSlotUnbootable = false;

                switch (result)
                {
                    case AvbSlotVerifyResult.Ok:
                        slotVerifyData[n] = data;
                        break;
                    case AvbSlotVerifyResult.ErrorOom:
                        return AvbAbFlowResult.ErrorOom;
                    case AvbSlotVerifyResult.ErrorIo:
                        return AvbAbFlowResult.ErrorIo;
                    case AvbSlotVerifyResult.ErrorInvalidMetadata:
                    case AvbSlotVerifyResult.ErrorUnsupportedVersion:
                        setSlotUnbootable = true;
                        break;
                    case AvbSlotVerifyResult.ErrorVerification:
                    case AvbSlotVerifyResult.ErrorRollbackIndex:
                    case AvbSlotVerifyResult.ErrorPublicKeyRejected:
                        if ((flags & AvbSlotVerifyFlags.AllowVerificationError) != 0)
                        {
                            sawAndAllowedVerificationError = true;
                            slotVerifyData[n] = data;
                        }
                        else
                        {
                            setSlotUnbootable = true;
                        }
                        break;
                    case AvbSlotVerifyResult.ErrorInvalidArgument:
                        return AvbAbFlowResult.ErrorInvalidArgument;
                    default:
                        break;
                }

                if (setSlotUnbootable)
                {
                    if (n == 0)
                    {
                        abData.SlotA = SetUnbootable();
                    }
                    else
                    {
                        abData.SlotB = SetUnbootable();
                    }
                }
            }
        }

        var isA = IsBootable(abData.SlotA);
        var isB = IsBootable(abData.SlotB);

        int bestSlot;
        if (isA && isB)
        {
            bestSlot = abData.SlotB.Priority > abData.SlotA.Priority ? 1 : 0;
        }
        else if (isA)
        {
            bestSlot = 0;
        }
        else if (isB)
        {
            bestSlot = 1;
        }
        else
        {
            SaveMetadataIfChanged(abData, abDataOrig);
            return AvbAbFlowResult.ErrorNoBootableSlot;
        }

        if (UpdateGlobalRollbackIndices(slotVerifyData) != AvbIOResult.Ok)
        {
            return AvbAbFlowResult.ErrorIo;
        }

        slotSuffix = SlotSuffixes[bestSlot];
        verifyData = slotVerifyData[bestSlot];

        var ret = sawAndAllowedVerificationError ? AvbAbFlowResult.OkWithVerificationError : AvbAbFlowResult.Ok;

        var bestSlotMetadata = bestSlot == 0 ? abData.SlotA : abData.SlotB;
        if (bestSlotMetadata.SuccessfulBoot == 0 && bestSlotMetadata.TriesRemaining > 0)
        {
            bestSlotMetadata.TriesRemaining--;
            if (bestSlot == 0)
            {
                abData.SlotA = bestSlotMetadata;
            }
            else
            {
                abData.SlotB = bestSlotMetadata;
            }
        }

        return SaveMetadataIfChanged(abData, abDataOrig) != AvbIOResult.Ok ? AvbAbFlowResult.ErrorIo : ret;
    }

    private AvbIOResult SaveMetadataIfChanged(AvbAbData current, AvbAbData original) => current != original ? _ops.WriteAbMetadata(current) : AvbIOResult.Ok;

    /// <summary>
    /// Marks the specified slot as active.
    /// <para>将指定槽位标记为活动。</para>
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).
    /// <para>槽位索引（0表示_a，1表示_b）。</para></param>
    public AvbIOResult MarkSlotActive(int slotIndex)
    {
        if (slotIndex is not 0 and not 1)
        {
            return AvbIOResult.ErrorIo;
        }

        var ioRet = _ops.ReadAbMetadata(out var abData);
        if (ioRet != AvbIOResult.Ok)
        {
            return ioRet;
        }

        var abDataOrig = abData;

        if (slotIndex == 0)
        {
            abData.SlotA.Priority = AvbAbSlotData.MaxPriority;
            abData.SlotA.TriesRemaining = AvbAbSlotData.MaxTriesRemaining;
            abData.SlotA.SuccessfulBoot = 0;
            if (abData.SlotB.Priority == AvbAbSlotData.MaxPriority)
            {
                abData.SlotB.Priority = AvbAbSlotData.MaxPriority - 1;
            }
        }
        else
        {
            abData.SlotB.Priority = AvbAbSlotData.MaxPriority;
            abData.SlotB.TriesRemaining = AvbAbSlotData.MaxTriesRemaining;
            abData.SlotB.SuccessfulBoot = 0;
            if (abData.SlotA.Priority == AvbAbSlotData.MaxPriority)
            {
                abData.SlotA.Priority = AvbAbSlotData.MaxPriority - 1;
            }
        }

        return SaveMetadataIfChanged(abData, abDataOrig);
    }

    /// <summary>
    /// Marks the specified slot as unbootable.
    /// <para>将指定槽位标记为不可启动。</para>
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).
    /// <para>槽位索引（0表示_a，1表示_b）。</para></param>
    public AvbIOResult MarkSlotUnbootable(int slotIndex)
    {
        if (slotIndex is not 0 and not 1)
        {
            return AvbIOResult.ErrorIo;
        }

        var ioRet = _ops.ReadAbMetadata(out var abData);
        if (ioRet != AvbIOResult.Ok)
        {
            return ioRet;
        }

        var abDataOrig = abData;

        if (slotIndex == 0)
        {
            abData.SlotA = SetUnbootable();
        }
        else
        {
            abData.SlotB = SetUnbootable();
        }

        return SaveMetadataIfChanged(abData, abDataOrig);
    }

    /// <summary>
    /// Marks the specified slot as having booted successfully.
    /// <para>将指定槽位标记为已成功启动。</para>
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).
    /// <para>槽位索引（0表示_a，1表示_b）。</para></param>
    public AvbIOResult MarkSlotSuccessful(int slotIndex)
    {
        if (slotIndex is not 0 and not 1)
        {
            return AvbIOResult.ErrorIo;
        }

        var ioRet = _ops.ReadAbMetadata(out var abData);
        if (ioRet != AvbIOResult.Ok)
        {
            return ioRet;
        }

        var abDataOrig = abData;

        if (slotIndex == 0)
        {
            if (IsBootable(abData.SlotA))
            {
                abData.SlotA.TriesRemaining = 0;
                abData.SlotA.SuccessfulBoot = 1;
            }
        }
        else
        {
            if (IsBootable(abData.SlotB))
            {
                abData.SlotB.TriesRemaining = 0;
                abData.SlotB.SuccessfulBoot = 1;
            }
        }

        return SaveMetadataIfChanged(abData, abDataOrig);
    }

    /// <summary>
    /// Gets the slot index from a slot suffix.
    /// <para>从槽位后缀获取槽位索引。</para>
    /// </summary>
    /// <param name="suffix">The slot suffix ("_a" or "_b").
    /// <para>槽位后缀（"_a"或"_b"）。</para></param>
    /// <returns>The slot index (0 for _a, 1 for _b).
    /// <para>槽位索引（0表示_a，1表示_b）。</para></returns>
    public static int GetSlotIndex(string suffix)
    {
        for (var i = 0; i < SlotSuffixes.Length; i++)
        {
            if (SlotSuffixes[i] == suffix)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Gets the slot suffix for a slot index.
    /// <para>获取槽位索引对应的槽位后缀。</para>
    /// </summary>
    /// <param name="slotIndex">The slot index (0 for _a, 1 for _b).
    /// <para>槽位索引（0表示_a，1表示_b）。</para></param>
    /// <returns>The slot suffix.
    /// <para>槽位后缀。</para></returns>
    public static string GetSlotSuffix(int slotIndex) => slotIndex >= 0 && slotIndex < SlotSuffixes.Length ? SlotSuffixes[slotIndex] : string.Empty;

    /// <summary>
    /// Updates the global rollback indices based on the minimum values from all verified slots.
    /// Equivalent to 'update_global_rollback_indices()' in libavb_ab.
    /// <para>根据所有已验证槽位的最小值更新全局回滚索引。</para>
    /// <para>等价于libavb_ab中的'update_global_rollback_indices()'。</para>
    /// </summary>
    /// <param name="list">The list of verification data for each slot.
    /// <para>每个槽位的验证数据列表。</para></param>
    /// <returns>The result of the I/O operation.
    /// <para>I/O操作的结果。</para></returns>
    private AvbIOResult UpdateGlobalRollbackIndices(AvbSlotVerifyData?[] list)
    {
        for (var i = 0; i < 32; i++)
        {
            var rollbackIndexValue = 0UL;

            if (list[0] != null && list[1] != null)
            {
                rollbackIndexValue = Math.Min(list[0]!.RollbackIndexes[i], list[1]!.RollbackIndexes[i]);
            }
            else if (list[0] != null)
            {
                rollbackIndexValue = list[0]!.RollbackIndexes[i];
            }
            else if (list[1] != null)
            {
                rollbackIndexValue = list[1]!.RollbackIndexes[i];
            }

            if (rollbackIndexValue != 0)
            {
                var io = _ops.ReadRollbackIndex(i, out var currentBoardRollback);
                if (io != AvbIOResult.Ok)
                {
                    return io;
                }

                if (currentBoardRollback != rollbackIndexValue)
                {
                    io = _ops.WriteRollbackIndex(i, rollbackIndexValue);
                    if (io != AvbIOResult.Ok)
                    {
                        return io;
                    }
                }
            }
        }

        return AvbIOResult.Ok;
    }

    /// <summary>
    /// Determines whether a slot is considered bootable.
    /// <para>确定槽位是否被视为可启动。</para>
    /// </summary>
    /// <param name="slot">The slot metadata to check.
    /// <para>要检查的槽位元数据。</para></param>
    /// <returns>True if bootable, false otherwise.
    /// <para>如果可启动则返回true，否则返回false。</para></returns>
    private static bool IsBootable(AvbAbSlotData slot) =>
        slot.Priority > 0 && (slot.SuccessfulBoot != 0 || slot.TriesRemaining > 0);

    /// <summary>
    /// Normalizes the slot metadata to ensure a consistent state.
    /// <para>规范化槽位元数据以确保一致的状态。</para>
    /// </summary>
    /// <param name="slot">The slot metadata to normalize.
    /// <para>要规范化的槽位元数据。</para></param>
    /// <returns>The normalized slot metadata.
    /// <para>规范化后的槽位元数据。</para></returns>
    private static AvbAbSlotData NormalizeSlot(AvbAbSlotData slot)
    {
        if (slot.Priority > 0)
        {
            if (slot.TriesRemaining == 0 && slot.SuccessfulBoot == 0)
            {
                return SetUnbootable();
            }
            if (slot.TriesRemaining > 0 && slot.SuccessfulBoot != 0)
            {
                return SetUnbootable();
            }
        }
        else
        {
            return SetUnbootable();
        }
        return slot;
    }

    /// <summary>
    /// Resets a slot to an unbootable state.
    /// <para>将槽位重置为不可启动状态。</para>
    /// </summary>
    /// <returns>A new <see cref="AvbAbSlotData"/> instance representing an unbootable slot.
    /// <para>表示不可启动槽位的新<see cref="AvbAbSlotData"/>实例。</para></returns>
    private static AvbAbSlotData SetUnbootable() =>
        new()
        { Priority = 0, TriesRemaining = 0, SuccessfulBoot = 0 };
}