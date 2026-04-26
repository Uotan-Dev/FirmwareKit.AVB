namespace FirmwareKit.AVB.Utilities;

/// <summary>
/// Provides utility functions for AVB, matching libavb/avb_util.h.
/// <para>为AVB提供实用函数，与libavb/avb_util.h匹配。</para>
/// </summary>
public static class AvbUtil
{
    /// <summary>
    /// Converts a 16-bit unsigned integer from big-endian to host order.
    /// <para>将16位无符号整数从大端序转换为主机序。</para>
    /// </summary>
    public static ushort Be16ToHost(ushort value) => BitConverter.IsLittleEndian
            ? (ushort)((value << 8) | (value >> 8))
            : value;

    /// <summary>
    /// Converts a 32-bit unsigned integer from big-endian to host order.
    /// <para>将32位无符号整数从大端序转换为主机序。</para>
    /// </summary>
    public static uint Be32ToHost(uint value) => BitConverter.IsLittleEndian
            ? ((value & 0x000000FFu) << 24) |
                ((value & 0x0000FF00u) << 8) |
                ((value & 0x00FF0000u) >> 8) |
                ((value & 0xFF000000u) >> 24)
            : value;

    /// <summary>
    /// Converts a 64-bit unsigned integer from big-endian to host order.
    /// <para>将64位无符号整数从大端序转换为主机序。</para>
    /// </summary>
    public static ulong Be64ToHost(ulong value) => BitConverter.IsLittleEndian
            ? ((value & 0x00000000000000FFUL) << 56) |
                ((value & 0x000000000000FF00UL) << 40) |
                ((value & 0x0000000000FF0000UL) << 24) |
                ((value & 0x00000000FF000000UL) << 8) |
                ((value & 0x000000FF00000000UL) >> 8) |
                ((value & 0x0000FF0000000000UL) >> 24) |
                ((value & 0x00FF000000000000UL) >> 40) |
                ((value & 0xFF00000000000000UL) >> 56)
            : value;

    /// <summary>
    /// Converts a 16-bit unsigned integer from host to big-endian order.
    /// <para>将16位无符号整数从主机序转换为大端序。</para>
    /// </summary>
    public static ushort HostToBe16(ushort value) => Be16ToHost(value);

    /// <summary>
    /// Converts a 32-bit unsigned integer from host to big-endian order.
    /// <para>将32位无符号整数从主机序转换为大端序。</para>
    /// </summary>
    public static uint HostToBe32(uint value) => Be32ToHost(value);

    /// <summary>
    /// Converts a 64-bit unsigned integer from host to big-endian order.
    /// <para>将64位无符号整数从主机序转换为大端序。</para>
    /// </summary>
    public static ulong HostToBe64(ulong value) => Be64ToHost(value);

    /// <summary>
    /// Constant-time comparison of two byte sequences.
    /// Returns 0 when equal, 1 when different.
    /// <para>两个字节序列的常量时间比较。</para>
    /// <para>相等时返回0，不同时返回1。</para>
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
    /// <para>在有溢出保护的情况下将valueToAdd添加到value。</para>
    /// </summary>
    public static bool SafeAddTo(ref ulong value, ulong valueToAdd)
    {
        if (ulong.MaxValue - value < valueToAdd)
        {
            value += valueToAdd;
            return false;
        }
        value += valueToAdd;
        return true;
    }

    /// <summary>
    /// Adds a and b with overflow protection.
    /// <para>在有溢出保护的情况下添加a和b。</para>
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
    /// <para>检查数据是否为有效的UTF-8字符串。</para>
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
    /// <para>将数据转换为十六进制字符串。</para>
    /// </summary>
    public static string Bin2Hex(ReadOnlySpan<byte> data) => AvbCompat.ToHexString(data).ToLowerInvariant();

    /// <summary>
    /// Duplicates a string.
    /// <para>复制一个字符串。</para>
    /// </summary>
    public static string StrDup(string value) => string.Concat(value);

    /// <summary>
    /// Concatenates multiple strings into a single string.
    /// <para>将多个字符串连接成一个字符串。</para>
    /// </summary>
    public static string StrDupV(params string[] values) => string.Concat(values);

    /// <summary>
    /// Concatenates two string slices and guarantees a NUL-terminated result in the C sense.
    /// In managed code this is represented as a normal string without embedded terminators.
    /// <para>连接两个字符串切片，并在C意义上保证结果以NUL结尾。</para>
    /// <para>在托管代码中，这表示为没有嵌入终止符的普通字符串。</para>
    /// </summary>
    public static bool StrConcat(
        Span<char> buffer,
        string str1,
        int str1Length,
        string str2,
        int str2Length,
        out int written)
    {
        written = 0;

        if (str1Length < 0 || str2Length < 0)
        {
            return false;
        }

        if (str1Length > str1.Length || str2Length > str2.Length)
        {
            return false;
        }

        var totalLength = str1Length + str2Length;
        if (buffer.Length < totalLength + 1)
        {
            return false;
        }

        str1.AsSpan(0, str1Length).CopyTo(buffer);
        str2.AsSpan(0, str2Length).CopyTo(buffer.Slice(str1Length));
        buffer[totalLength] = '\0';
        written = totalLength;
        return true;
    }

    /// <summary>
    /// Returns the first occurrence of a substring using POSIX-style semantics.
    /// <para>使用POSIX风格的语义返回子字符串的第一次出现。</para>
    /// </summary>
    public static string? StrStr(string haystack, string needle)
    {
        if (needle.Length == 0)
        {
            return haystack;
        }

        var index = haystack.IndexOf(needle, StringComparison.Ordinal);
        return index >= 0 ? haystack[index..] : null;
    }

    /// <summary>
    /// Finds a string in a list of strings using ordinal comparison.
    /// <para>使用序数比较在字符串列表中查找字符串。</para>
    /// </summary>
    public static string? StrvFindStr(IReadOnlyList<string> strings, string value)
    {
        for (var i = 0; i < strings.Count; i++)
        {
            if (string.Equals(strings[i], value, StringComparison.Ordinal))
            {
                return strings[i];
            }
        }

        return null;
    }

    /// <summary>
    /// Finds a byte-slice key in a string list using ordinal comparison.
    /// <para>使用序数比较在字符串列表中查找字节切片键。</para>
    /// </summary>
    public static string? StrvFindStr(IReadOnlyList<string> strings, ReadOnlySpan<char> value)
    {
        for (var i = 0; i < strings.Count; i++)
        {
            if (strings[i].AsSpan().SequenceEqual(value))
            {
                return strings[i];
            }
        }

        return null;
    }

    /// <summary>
    /// Replaces all occurrences of <paramref name="search"/> with <paramref name="replace"/>.
    /// <para>将所有出现的<paramref name="search"/>替换为<paramref name="replace"/>。</para>
    /// </summary>
    public static string Replace(string text, string search, string replace)
    {
        if (string.IsNullOrEmpty(search))
        {
            return text;
        }

        return text.Replace(search, replace);
    }

    /// <summary>
    /// Returns the basename of a path (POSIX style).
    /// <para>返回路径的基名（POSIX风格）。</para>
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

    /// <summary>
    /// Converts ASCII lowercase characters in a string to uppercase.
    /// <para>将字符串中的ASCII小写字符转换为大写。</para>
    /// </summary>
    public static string Uppercase(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (chars[i] >= 'a' && chars[i] <= 'z')
            {
                chars[i] = (char)(chars[i] - ('a' - 'A'));
            }
        }

        return new string(chars);
    }

    /// <summary>
    /// Converts a 64-bit unsigned integer to base-10 text.
    /// <para>将64位无符号整数转换为基10文本。</para>
    /// </summary>
    public static int UInt64ToBase10(ulong value, Span<char> digits)
    {
        if (value == 0)
        {
            if (digits.Length < 1)
            {
                throw new ArgumentException("Buffer is too small for the value.", nameof(digits));
            }
            digits[0] = '0';
            return 1;
        }

        int pos = 0;
        ulong temp = value;
        while (temp > 0)
        {
            if (pos >= digits.Length)
            {
                throw new ArgumentException("Buffer is too small for the value.", nameof(digits));
            }
            digits[pos++] = (char)('0' + (temp % 10));
            temp /= 10;
        }

        for (int i = 0; i < pos / 2; i++)
        {
            char tmp = digits[i];
            digits[i] = digits[pos - 1 - i];
            digits[pos - 1 - i] = tmp;
        }

        return pos;
    }

    /// <summary>
    /// Converts a 64-bit unsigned integer to base-10 text.
    /// <para>将64位无符号整数转换为基10文本。</para>
    /// </summary>
    public static string UInt64ToBase10(ulong value)
    {
        if (value == 0)
        {
            return "0";
        }

        char[] buffer = new char[32];
        int len = 0;
        ulong temp = value;
        while (temp > 0)
        {
            buffer[len++] = (char)('0' + (temp % 10));
            temp /= 10;
        }

        Array.Reverse(buffer, 0, len);
        return new string(buffer, 0, len);
    }
}