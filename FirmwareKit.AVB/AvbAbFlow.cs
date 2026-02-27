namespace FirmwareKit.AVB;

/// <summary>
/// Implements the A/B boot flow logic for Android Verified Boot, equivalent to 'libavb_ab'.
/// This class handles slot selection and metadata management for devices with two bootable slots.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="AvbAbFlow"/> class.
/// </remarks>
/// <param name="ops">The <see cref="IAvbOps"/> implementation to use for I/O operations.</param>
public class AvbAbFlow(IAvbOps ops)
{
    private readonly IAvbOps _ops = ops;
    private static readonly string[] SlotSuffixes = ["_a", "_b"];

    /// <summary>
    /// Selects the best bootable slot based on the A/B metadata and verification results.
    /// </summary>
    /// <param name="slotSuffix">Returns the suffix of the selected slot (e.g., "_a" or "_b").</param>
    /// <param name="verifyData">Returns the verification data for the selected slot.</param>
    /// <param name="flags">The verification flags.</param>
    /// <param name="hashtreeErrorMode">The hashtree error mode.</param>
    /// <returns>An <see cref="AvbAbFlowResult"/> indicating the result of the selection process.</returns>
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
            // If we can't read it, create a default one
            abData = AvbAbData.CreateDefault();
            _ops.WriteAbMetadata(abData);
        }

        if (!abData.IsValid())
        {
            abData = AvbAbData.CreateDefault();
            _ops.WriteAbMetadata(abData);
        }

        var abDataOrig = abData; // Keep track of changes
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

        // ... and decrement tries remaining, if applicable.
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
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).</param>
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
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).</param>
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
    /// </summary>
    /// <param name="slotIndex">Index of the slot (0 for _a, 1 for _b).</param>
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
    /// </summary>
    /// <param name="suffix">The slot suffix ("_a" or "_b").</param>
    /// <returns>The slot index (0 for _a, 1 for _b).</returns>
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
    /// </summary>
    /// <param name="slotIndex">The slot index (0 for _a, 1 for _b).</param>
    /// <returns>The slot suffix.</returns>
    public static string GetSlotSuffix(int slotIndex) => slotIndex >= 0 && slotIndex < SlotSuffixes.Length ? SlotSuffixes[slotIndex] : string.Empty;

    /// <summary>
    /// Updates the global rollback indices based on the minimum values from all verified slots.
    /// Equivalent to 'update_global_rollback_indices()' in libavb_ab.
    /// </summary>
    /// <param name="list">The list of verification data for each slot.</param>
    /// <returns>The result of the I/O operation.</returns>
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
    /// </summary>
    /// <param name="slot">The slot metadata to check.</param>
    /// <returns>True if bootable, false otherwise.</returns>
    private static bool IsBootable(AvbAbSlotData slot) =>
        slot.Priority > 0 && (slot.SuccessfulBoot != 0 || slot.TriesRemaining > 0);

    /// <summary>
    /// Normalizes the slot metadata to ensure a consistent state.
    /// </summary>
    /// <param name="slot">The slot metadata to normalize.</param>
    /// <returns>The normalized slot metadata.</returns>
    private static AvbAbSlotData NormalizeSlot(AvbAbSlotData slot)
    {
        if (slot.Priority > 0)
        {
            if (slot.TriesRemaining == 0 && slot.SuccessfulBoot == 0)
            {
                /* We've exhausted all tries -> unbootable. */
                return SetUnbootable();
            }
            if (slot.TriesRemaining > 0 && slot.SuccessfulBoot != 0)
            {
                /* Illegal state - tries_remaining should be 0 if successful_boot is set. */
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
    /// </summary>
    /// <returns>A new <see cref="AvbAbSlotData"/> instance representing an unbootable slot.</returns>
    private static AvbAbSlotData SetUnbootable() =>
        new()
        { Priority = 0, TriesRemaining = 0, SuccessfulBoot = 0 };
}
