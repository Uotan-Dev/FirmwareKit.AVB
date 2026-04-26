using FirmwareKit.AVB.Enums;

namespace FirmwareKit.AVB.Abstractions;

/// <summary>
/// Fully managed file-backed <see cref="IAvbOps"/> implementation.
/// <para>完全托管的基于文件的<see cref="IAvbOps"/>实现。</para>
/// </summary>
/// <remarks>
/// Partitions are resolved from a directory by trying:
/// <para>分区通过尝试以下方式从目录中解析：</para>
/// 1) {partitionName}
/// 2) {partitionName}.img
/// <para>这提供了一个没有原生库的便携式用户空间AVB环境。</para>
/// </remarks>
public sealed class FileSystemAvbOps : AvbOpsBase
{
    private readonly string _partitionDirectory;
    private readonly Dictionary<string, string> _guidByPartition;
    private readonly Dictionary<string, byte[]> _preloadedByPartition;
    private readonly bool _isDeviceUnlocked;

    /// <summary>
    /// Initializes a new file-backed AVB ops instance.
    /// <para>初始化新的基于文件的AVB操作实例。</para>
    /// </summary>
    public FileSystemAvbOps(
        string partitionDirectory,
        bool isDeviceUnlocked = true,
        IDictionary<string, string>? partitionGuids = null)
    {
        if (string.IsNullOrWhiteSpace(partitionDirectory))
        {
            throw new ArgumentException("Partition directory is required.", nameof(partitionDirectory));
        }

        _partitionDirectory = Path.GetFullPath(partitionDirectory);
        _isDeviceUnlocked = isDeviceUnlocked;
        _guidByPartition = new Dictionary<string, string>(StringComparer.Ordinal);
        _preloadedByPartition = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        if (partitionGuids != null)
        {
            foreach (var pair in partitionGuids)
            {
                _guidByPartition[pair.Key] = pair.Value;
            }
        }
    }

    /// <summary>
    /// Registers or replaces a partition GUID used by cmdline substitution.
    /// <para>注册或替换命令行替换使用的分区GUID。</para>
    /// </summary>
    public void SetPartitionGuid(string partitionName, string guid) => _guidByPartition[partitionName] = guid;

    /// <summary>
    /// Registers preloaded partition bytes for <see cref="GetPreloadedPartition"/>.
    /// <para>为<see cref="GetPreloadedPartition"/>注册预加载的分区字节。</para>
    /// </summary>
    public void SetPreloadedPartition(string partitionName, byte[] data)
    {
        _preloadedByPartition[partitionName] = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <inheritdoc />
    public override AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead)
    {
        bytesRead = 0;
        if (numBytes < 0 || numBytes > buffer.Length)
        {
            return AvbIOResult.ErrorInvalidValueSize;
        }

        if (!TryResolvePartitionPath(partitionName, out var path))
        {
            return AvbIOResult.ErrorNoSuchPartition;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var position = ResolvePosition(stream.Length, offset);
            if (position < 0 || position > stream.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            stream.Position = position;
            var temp = new byte[numBytes];
            bytesRead = stream.Read(temp, 0, numBytes);
            temp.AsSpan(0, bytesRead).CopyTo(buffer);
            return AvbIOResult.Ok;
        }
        catch (IOException)
        {
            return AvbIOResult.ErrorIo;
        }
        catch (UnauthorizedAccessException)
        {
            return AvbIOResult.ErrorIo;
        }
    }

    /// <inheritdoc />
    public override AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer)
    {
        if (numBytes < 0 || numBytes > buffer.Length)
        {
            return AvbIOResult.ErrorInvalidValueSize;
        }

        if (!TryResolvePartitionPath(partitionName, out var path))
        {
            return AvbIOResult.ErrorNoSuchPartition;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
            var position = ResolvePosition(stream.Length, offset);
            if (position < 0 || position > stream.Length)
            {
                return AvbIOResult.ErrorRangeOutsidePartition;
            }

            stream.Position = position;
            var temp = buffer.Slice(0, numBytes).ToArray();
            stream.Write(temp, 0, temp.Length);
            return AvbIOResult.Ok;
        }
        catch (IOException)
        {
            return AvbIOResult.ErrorIo;
        }
        catch (UnauthorizedAccessException)
        {
            return AvbIOResult.ErrorIo;
        }
    }

    /// <inheritdoc />
    public override AvbIOResult GetSizeOfPartition(string partitionName, out long size)
    {
        size = 0;
        if (!TryResolvePartitionPath(partitionName, out var path))
        {
            return AvbIOResult.ErrorNoSuchPartition;
        }

        try
        {
            size = new FileInfo(path).Length;
            return AvbIOResult.Ok;
        }
        catch (IOException)
        {
            return AvbIOResult.ErrorIo;
        }
        catch (UnauthorizedAccessException)
        {
            return AvbIOResult.ErrorIo;
        }
    }

    /// <inheritdoc />
    public override AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked)
    {
        isUnlocked = _isDeviceUnlocked;
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public override AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid)
    {
        if (_guidByPartition.TryGetValue(partitionName, out guid!))
        {
            return AvbIOResult.Ok;
        }

        guid = string.Empty;
        return AvbIOResult.ErrorNoSuchPartition;
    }

    /// <inheritdoc />
    public override AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData)
    {
        preloadedData = ReadOnlySpan<byte>.Empty;

        if (!_preloadedByPartition.TryGetValue(partitionName, out var data))
        {
            return AvbIOResult.ErrorNoSuchPartition;
        }

        if (numBytes < 0 || numBytes > data.Length)
        {
            return AvbIOResult.ErrorRangeOutsidePartition;
        }

        preloadedData = data.AsSpan(0, numBytes);
        return AvbIOResult.Ok;
    }

    /// <inheritdoc />
    public override AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid)
    {
        isValid = true;
        return AvbIOResult.Ok;
    }

    private bool TryResolvePartitionPath(string partitionName, out string path)
    {
        var direct = Path.Combine(_partitionDirectory, partitionName);
        if (File.Exists(direct))
        {
            path = direct;
            return true;
        }

        var withImg = Path.Combine(_partitionDirectory, partitionName + ".img");
        if (File.Exists(withImg))
        {
            path = withImg;
            return true;
        }

        path = string.Empty;
        return false;
    }

    private static long ResolvePosition(long length, long offset)
    {
        if (offset >= 0)
        {
            return offset;
        }

        return length - (-offset);
    }
}