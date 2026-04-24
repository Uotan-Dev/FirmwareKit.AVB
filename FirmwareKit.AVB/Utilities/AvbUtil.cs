namespace FirmwareKit.AVB;

/// <summary>
/// Provides utility functions for AVB, matching libavb/avb_util.h.
/// </summary>
public static class AvbUtil
{
    /// <summary>
    /// Constant-time comparison of two byte sequences.
    /// Returns 0 when equal, 1 when different.
    /// </summary>
    public static int SafeMemCmp(ReadOnlySpan<byte> s1, ReadOnlySpan<byte> s2)
    {
        var n = s1.Length;
        if (n != s2.Length)
        {
            return 1;
        }

        var result = 0;
        for (var i = 0; i < n; i++)
        {
            result |= s1[i] ^ s2[i];
        }

        return result != 0 ? 1 : 0;
    }

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
        var numContinuation = 0;
        for (var i = 0; i < data.Length; i++)
        {
            var c = data[i];

            if (numContinuation > 0)
            {
                if ((c & 0xC0) != 0x80)
                {
                    return false;
                }

                numContinuation--;
                continue;
            }

            if (c < 0x80)
            {
                continue;
            }

            if ((c & 0xE0) == 0xC0)
            {
                numContinuation = 1;
            }
            else if ((c & 0xF0) == 0xE0)
            {
                numContinuation = 2;
            }
            else if ((c & 0xF8) == 0xF0)
            {
                numContinuation = 3;
            }
            else
            {
                return false;
            }
        }

        return numContinuation == 0;
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
