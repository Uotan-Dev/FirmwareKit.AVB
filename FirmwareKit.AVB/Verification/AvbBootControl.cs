using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Verification;

/// <summary>
/// Managed boot-control facade built on top of AVB A/B metadata.
/// <para>基于AVB A/B元数据构建的托管启动控制外观。</para>
/// </summary>
public sealed class AvbBootControl
{
    private readonly IAvbOps _ops;
    private readonly AvbAbFlow _abFlow;
    private readonly Func<string> _currentSlotSuffixProvider;

    /// <summary>
    /// Creates a boot-control facade.
    /// <para>创建启动控制外观。</para>
    /// </summary>
    /// <param name="ops">AVB platform operations.
    /// <para>AVB平台操作。</para></param>
    /// <param name="currentSlotSuffixProvider">
    /// Optional provider for current slot suffix ("_a" or "_b").
    /// Defaults to always returning "_a".
    /// <para>当前槽后缀（"_a"或"_b"）的可选提供程序。</para>
    /// <para>默认始终返回"_a"。</para></param>
    public AvbBootControl(IAvbOps ops, Func<string>? currentSlotSuffixProvider = null)
    {
        _ops = ops;
        _abFlow = new AvbAbFlow(ops);
        _currentSlotSuffixProvider = currentSlotSuffixProvider ?? (() => "_a");
    }

    /// <summary>
    /// Gets number of supported slots.
    /// <para>获取支持的槽数量。</para>
    /// </summary>
    public int GetNumberSlots() => 2;

    /// <summary>
    /// Gets current slot index based on current slot suffix provider.
    /// <para>根据当前槽后缀提供程序获取当前槽索引。</para>
    /// </summary>
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

    /// <summary>
    /// Marks the current slot as boot-successful.
    /// <para>将当前槽标记为启动成功。</para>
    /// </summary>
    public AvbIOResult MarkBootSuccessful() => _abFlow.MarkSlotSuccessful(GetCurrentSlot());

    /// <summary>
    /// Marks slot as active.
    /// <para>将槽标记为活动。</para>
    /// </summary>
    public AvbIOResult SetActiveBootSlot(int slot) =>
        slot < 0 || slot >= GetNumberSlots() ? AvbIOResult.ErrorIo : _abFlow.MarkSlotActive(slot);

    /// <summary>
    /// Marks slot as unbootable.
    /// <para>将槽标记为不可启动。</para>
    /// </summary>
    public AvbIOResult SetSlotAsUnbootable(int slot) =>
        slot < 0 || slot >= GetNumberSlots() ? AvbIOResult.ErrorIo : _abFlow.MarkSlotUnbootable(slot);

    /// <summary>
    /// Gets whether slot is bootable.
    /// <para>获取槽是否可启动。</para>
    /// </summary>
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

    /// <summary>
    /// Gets whether slot was marked successful.
    /// <para>获取槽是否被标记为成功。</para>
    /// </summary>
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

    /// <summary>
    /// Gets slot suffix.
    /// <para>获取槽后缀。</para>
    /// </summary>
    public string? GetSuffix(int slot) => slot switch
    {
        0 => "_a",
        1 => "_b",
        _ => null
    };
}