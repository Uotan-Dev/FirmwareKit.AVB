using FirmwareKit.AVB.Utilities;

namespace FirmwareKit.AVB.Core;

/// <summary>
/// Managed substitution table for AVB command-line token replacement.
/// Mirrors the root-digest substitution helper from libavb in a C#-friendly form.
/// <para>AVB命令行令牌替换的托管替换表。</para>
/// <para>以C#友好的形式镜像libavb中的根摘要替换助手。</para>
/// </summary>
public sealed class AvbCmdlineSubstitutionList
{
    private const int DefaultCapacity = 10;
    private readonly List<KeyValuePair<string, string>> _items = new();

    /// <summary>
    /// Gets the number of substitutions currently stored.
    /// <para>获取当前存储的替换数量。</para>
    /// </summary>
    public int Count => _items.Count;

    /// <summary>
    /// Gets the substitutions as a read-only list.
    /// <para>获取替换列表的只读视图。</para>
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, string>> Items => _items;

    /// <summary>
    /// Adds an arbitrary token replacement.
    /// <para>添加任意令牌替换。</para>
    /// </summary>
    public bool TryAdd(string token, string value)
    {
        if (string.IsNullOrEmpty(token) || _items.Count >= DefaultCapacity)
        {
            return false;
        }

        _items.Add(new KeyValuePair<string, string>(token, value));
        return true;
    }

    /// <summary>
    /// Adds a root-digest substitution token of the form $(AVB_PARTITION_ROOT_DIGEST).
    /// <para>添加形式为 $(AVB_PARTITION_ROOT_DIGEST) 的根摘要替换令牌。</para>
    /// </summary>
    public bool TryAddRootDigestSubstitution(string partitionName, ReadOnlySpan<byte> digest)
    {
        if (string.IsNullOrWhiteSpace(partitionName) || digest.IsEmpty)
        {
            return false;
        }

        var token = $"$(AVB_{partitionName.ToUpperInvariant()}_ROOT_DIGEST)";
        var value = AvbCompat.ToHexString(digest).ToLowerInvariant();
        return TryAdd(token, value);
    }

    /// <summary>
    /// Applies all substitutions to a command-line string.
    /// <para>对命令行字符串应用所有替换。</para>
    /// </summary>
    public string Apply(string cmdline)
    {
        var result = cmdline;
        for (var i = 0; i < _items.Count; i++)
        {
            var item = _items[i];
            if (!string.IsNullOrEmpty(item.Key) && !string.IsNullOrEmpty(item.Value))
            {
                result = result.Replace(item.Key, item.Value);
            }
        }

        return result;
    }

    /// <summary>
    /// Clears the substitution table.
    /// <para>清除替换表。</para>
    /// </summary>
    public void Clear() => _items.Clear();
}