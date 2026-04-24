namespace FirmwareKit.AVB;

/// <summary>
/// Managed boot-control facade built on top of AVB A/B metadata.
/// </summary>
public sealed class AvbBootControl
{
    private readonly IAvbOps _ops;
    private readonly AvbAbFlow _abFlow;
    private readonly Func<string> _currentSlotSuffixProvider;

    /// <summary>
    /// Creates a boot-control facade.
    /// </summary>
    /// <param name="ops">AVB platform operations.</param>
    /// <param name="currentSlotSuffixProvider">
    /// Optional provider for current slot suffix ("_a" or "_b").
    /// Defaults to always returning "_a".
    /// </param>
    public AvbBootControl(IAvbOps ops, Func<string>? currentSlotSuffixProvider = null)
    {
        _ops = ops;
        _abFlow = new AvbAbFlow(ops);
        _currentSlotSuffixProvider = currentSlotSuffixProvider ?? (() => "_a");
    }

    /// <summary>Gets number of supported slots.</summary>
    public int GetNumberSlots() => 2;

    /// <summary>Gets current slot index based on current slot suffix provider.</summary>
    public int GetCurrentSlot()
    {
        var suffix = _currentSlotSuffixProvider();
        return suffix switch
        {
            "_a" => 0,
            "_b" => 1,
            _ => 0
        };
    }

    /// <summary>Marks the current slot as boot-successful.</summary>
    public AvbIOResult MarkBootSuccessful() => _abFlow.MarkSlotSuccessful(GetCurrentSlot());

    /// <summary>Marks slot as active.</summary>
    public AvbIOResult SetActiveBootSlot(int slot) =>
        slot < 0 || slot >= GetNumberSlots() ? AvbIOResult.ErrorIo : _abFlow.MarkSlotActive(slot);

    /// <summary>Marks slot as unbootable.</summary>
    public AvbIOResult SetSlotAsUnbootable(int slot) =>
        slot < 0 || slot >= GetNumberSlots() ? AvbIOResult.ErrorIo : _abFlow.MarkSlotUnbootable(slot);

    /// <summary>Gets whether slot is bootable.</summary>
    public AvbIOResult IsSlotBootable(int slot, out bool isBootable)
    {
        isBootable = false;
        if (slot < 0 || slot >= GetNumberSlots())
        {
            return AvbIOResult.ErrorIo;
        }

        var io = _ops.ReadAbMetadata(out var abData);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        var slotData = slot == 0 ? abData.SlotA : abData.SlotB;
        isBootable = slotData.Priority > 0 && (slotData.SuccessfulBoot != 0 || slotData.TriesRemaining > 0);
        return AvbIOResult.Ok;
    }

    /// <summary>Gets whether slot was marked successful.</summary>
    public AvbIOResult IsSlotMarkedSuccessful(int slot, out bool isSuccessful)
    {
        isSuccessful = false;
        if (slot < 0 || slot >= GetNumberSlots())
        {
            return AvbIOResult.ErrorIo;
        }

        var io = _ops.ReadAbMetadata(out var abData);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        var slotData = slot == 0 ? abData.SlotA : abData.SlotB;
        isSuccessful = slotData.SuccessfulBoot != 0;
        return AvbIOResult.Ok;
    }

    /// <summary>Gets slot suffix.</summary>
    public string? GetSuffix(int slot) => slot switch
    {
        0 => "_a",
        1 => "_b",
        _ => null
    };
}
