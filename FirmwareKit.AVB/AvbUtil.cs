using System.Text;

namespace FirmwareKit.AVB;

/// <summary>
/// Provides utility functions for AVB, matching libavb/avb_util.h.
/// </summary>
public static class AvbUtil
{
    /// <summary>
    /// Adds valueToAdd to value with overflow protection.
    /// </summary>
    public static bool SafeAddTo(ref ulong value, ulong valueToAdd)
    {
        if (ulong.MaxValue - value < valueToAdd)
        {
            value += valueToAdd; // Still add to match AOSP behavior of "always modified"
            return false;
        }
        value += valueToAdd;
        return true;
    }

    /// <summary>
    /// Adds a and b with overflow protection.
    /// </summary>
    public static bool SafeAdd(out ulong result, ulong a, ulong b)
    {
        if (ulong.MaxValue - a < b)
        {
            result = a + b;
            return false;
        }
        result = a + b;
        return true;
    }

    /// <summary>
    /// Checks if data is a valid UTF-8 string.
    /// </summary>
    public static bool ValidateUtf8(ReadOnlySpan<byte> data)
    {
        try
        {
#if NET8_0_OR_GREATER
            return System.Text.Unicode.Utf8.IsValid(data);
#else
            _ = Encoding.UTF8.GetString(data.ToArray());
            return true;
#endif
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Converts data to a hex string.
    /// </summary>
    public static string Bin2Hex(ReadOnlySpan<byte> data) => AvbCompat.ToHexString(data).ToLowerInvariant();

    /// <summary>
    /// Returns the basename of a path (POSIX style).
    /// </summary>
    public static string Basename(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return "";
        }

        var len = path.Length;
        if (len >= 2)
        {
            for (var i = len - 2; i >= 0; i--)
            {
                if (path[i] == '/')
                {
                    return path[(i + 1)..];
                }
            }
        }
        return path;
    }
}
