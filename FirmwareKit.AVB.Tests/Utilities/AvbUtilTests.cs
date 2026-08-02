using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Utilities;

namespace FirmwareKit.AVB.Tests;

public class AvbUtilTests
{
    [Fact]
    public void SafeAdd()
    {
        Assert.True(AvbUtil.SafeAdd(out var result, 10, 20));
        Assert.Equal(30uL, result);

        Assert.True(AvbUtil.SafeAdd(out result, ulong.MaxValue - 10, 10));
        Assert.Equal(ulong.MaxValue, result);

        Assert.False(AvbUtil.SafeAdd(out result, ulong.MaxValue - 10, 11));
        Assert.Equal(0uL, result);
    }

    [Fact]
    public void SafeAddTo()
    {
        ulong value = 10;
        Assert.True(AvbUtil.SafeAddTo(ref value, 20));
        Assert.Equal(30uL, value);

        value = ulong.MaxValue - 10;
        Assert.True(AvbUtil.SafeAddTo(ref value, 10));
        Assert.Equal(ulong.MaxValue, value);

        value = ulong.MaxValue - 10;
        Assert.False(AvbUtil.SafeAddTo(ref value, 11));
        Assert.Equal(0uL, value);
    }

    [Fact]
    public void SafeAddition_WithPow2_60()
    {
        var pow2_60 = 1UL << 60;

        var value = 1 * pow2_60;
        Assert.True(AvbUtil.SafeAddTo(ref value, 2 * pow2_60));
        Assert.Equal(3 * pow2_60, value);

        value = 7 * pow2_60;
        Assert.True(AvbUtil.SafeAddTo(ref value, 8 * pow2_60));
        Assert.Equal(15 * pow2_60, value);

        value = 9 * pow2_60;
        Assert.True(AvbUtil.SafeAddTo(ref value, 3 * pow2_60));
        Assert.Equal(12 * pow2_60, value);

        value = 0xfffffffffffffffcUL;
        Assert.True(AvbUtil.SafeAddTo(ref value, 2));
        Assert.Equal(0xfffffffffffffffeUL, value);

        value = 8 * pow2_60;
        Assert.False(AvbUtil.SafeAddTo(ref value, 8 * pow2_60));

        value = 0xfffffffffffffffcUL;
        Assert.False(AvbUtil.SafeAddTo(ref value, 4));
    }

    [Fact]
    public void ValidateUtf8_Valid()
    {
        var valid = "foobar"u8;
        Assert.True(AvbUtil.ValidateUtf8(valid));

        var chinese = "你好"u8;
        Assert.True(AvbUtil.ValidateUtf8(chinese));

        var latinAe = "foo \xC3\xA6 bar"u8;
        Assert.True(AvbUtil.ValidateUtf8(latinAe));

        var euroSign = "foo \xE2\x82\xAC bar"u8;
        Assert.True(AvbUtil.ValidateUtf8(euroSign));

        var emoji = "foo \xF0\x9F\x91\xA6 bar"u8;
        Assert.True(AvbUtil.ValidateUtf8(emoji));

        var allRunes = "\xC3\xA6\xE2\x82\xAC\xF0\x9F\x91\xA6"u8;
        Assert.True(AvbUtil.ValidateUtf8(allRunes));
    }

    [Fact]
    public void ValidateUtf8_Invalid()
    {
        ReadOnlySpan<byte> invalid = [0xFF, 0xFE, 0xFD];
        Assert.False(AvbUtil.ValidateUtf8(invalid));

        ReadOnlySpan<byte> truncated = [0xE4, 0xBD];
        Assert.False(AvbUtil.ValidateUtf8(truncated));

        ReadOnlySpan<byte> badLeading = [0xF8];
        Assert.False(AvbUtil.ValidateUtf8(badLeading));

        ReadOnlySpan<byte> truncatedMidRune = [0xC3];
        Assert.False(AvbUtil.ValidateUtf8(truncatedMidRune));
    }

    [Fact]
    public void SafeMemCmp()
    {
        ReadOnlySpan<byte> a = [1, 2, 3, 4];
        ReadOnlySpan<byte> b = [1, 2, 3, 4];
        ReadOnlySpan<byte> c = [1, 2, 3, 5];
        ReadOnlySpan<byte> d = [1, 2, 3];

        Assert.Equal(0, AvbUtil.SafeMemCmp(a, b));
        Assert.Equal(1, AvbUtil.SafeMemCmp(a, c));
        Assert.Equal(1, AvbUtil.SafeMemCmp(a, d));
    }

    [Fact]
    public void Bin2Hex()
    {
        ReadOnlySpan<byte> data = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0xff];
        Assert.Equal("deadbeef010203ff", AvbUtil.Bin2Hex(data));
    }

    [Fact]
    public void Crc32()
    {
        var data = "foobar"u8;
        Assert.Equal(0x9ef61f95u, AvbCrc32.Compute(data));
    }

    [Fact]
    public void Crc32_StandardCheckVector()
    {
        // Standard CRC-32 (IEEE 802.3) check value: CRC32("123456789") == 0xCBF43926.
        Assert.Equal(0xCBF43926u, AvbCrc32.Compute("123456789"u8));
    }

    [Fact]
    public void Basename()
    {
        Assert.Equal("foobar.c", AvbUtil.Basename("foobar.c"));
        Assert.Equal("foobar.c", AvbUtil.Basename("/path/to/foobar.c"));
        Assert.Equal("foobar.c", AvbUtil.Basename("a/foobar.c"));
        Assert.Equal("baz.c", AvbUtil.Basename("/baz.c"));
        Assert.Equal("some_dir/", AvbUtil.Basename("some_dir/"));
        Assert.Equal("some_dir/", AvbUtil.Basename("/path/to/some_dir/"));
        Assert.Equal("some_dir/", AvbUtil.Basename("a/some_dir/"));
        Assert.Equal("some_dir/", AvbUtil.Basename("/some_dir/"));
        Assert.Equal("/", AvbUtil.Basename("/"));
    }

    [Fact]
    public void EndianConversionHelpers()
    {
        Assert.Equal(0x1234, AvbUtil.Be16ToHost(AvbUtil.HostToBe16(0x1234)));
        Assert.Equal(0x12345678u, AvbUtil.Be32ToHost(AvbUtil.HostToBe32(0x12345678u)));
        Assert.Equal(0x1122334455667788ul, AvbUtil.Be64ToHost(AvbUtil.HostToBe64(0x1122334455667788ul)));
    }

    [Fact]
    public void StrvFindStr_WithSpanOverload()
    {
        var values = new[] { "foo", "bar", "baz" };
        Assert.Equal("bar", AvbUtil.StrvFindStr(values, "bar".AsSpan()));
        Assert.Null(AvbUtil.StrvFindStr(values, "qux".AsSpan()));
    }

    [Fact]
    public void StrvFindStr_WithDetailedCases()
    {
        var strings = new[] { "abcabc", "abc", "def" };
        Assert.Null(AvbUtil.StrvFindStr(strings, "not there"));
        Assert.Equal("abc", AvbUtil.StrvFindStr(strings, "abc"));
        Assert.Equal("def", AvbUtil.StrvFindStr(strings, "def"));
        Assert.Equal("abcabc", AvbUtil.StrvFindStr(strings, "abcabc"));
    }

    [Fact]
    public void StrConcat_Success()
    {
        Span<char> buf = stackalloc char[8];
        Assert.True(AvbUtil.StrConcat(buf, "foo", 3, "bar1", 4, out var written));
        Assert.Equal(7, written);
    }

    [Fact]
    public void StrConcat_InsufficientSpace()
    {
        Span<char> buf = stackalloc char[8];
        Assert.False(AvbUtil.StrConcat(buf, "foo0", 4, "bar1", 4, out var written));
    }

    [Fact]
    public void StrStr_DetailedCases()
    {
        var haystack = "abc def abcabc";
        Assert.Null(AvbUtil.StrStr(haystack, "needle"));
        Assert.Equal(haystack, AvbUtil.StrStr(haystack, "abc"));
        Assert.Equal("def abcabc", AvbUtil.StrStr(haystack, "def"));
        Assert.Equal(haystack, AvbUtil.StrStr(haystack, haystack));
    }

    [Fact]
    public void StrReplace_DetailedCases()
    {
        Assert.Equal("OK blah bah $(FOO OK blah", AvbUtil.Replace("$(FOO) blah bah $(FOO $(FOO) blah", "$(FOO)", "OK"));
        Assert.Equal("OK", AvbUtil.Replace("$(FOO)", "$(FOO)", "OK"));
        Assert.Equal(" OK", AvbUtil.Replace(" $(FOO)", "$(FOO)", "OK"));
        Assert.Equal("OK ", AvbUtil.Replace("$(FOO) ", "$(FOO)", "OK"));
        Assert.Equal("LONGSTRINGLONGSTRING", AvbUtil.Replace("$(FOO)$(FOO)", "$(FOO)", "LONGSTRING"));
    }

    [Fact]
    public void StrDupV_DetailedCases()
    {
        Assert.Equal("xyz", AvbUtil.StrDupV("x", "y", "z"));
        Assert.Equal("HelloWorld XYZ", AvbUtil.StrDupV("Hello", "World", " XYZ"));
    }

    [Fact]
    public void StrDup_ShouldReturnSameString()
    {
        Assert.Equal("foobar", AvbUtil.StrDup("foobar"));
        Assert.Equal("", AvbUtil.StrDup(""));
    }
}