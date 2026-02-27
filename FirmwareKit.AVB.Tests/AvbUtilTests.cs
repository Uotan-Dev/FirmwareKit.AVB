namespace LibAVBSharp.Tests;

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
    public void ValidateUtf8_Valid()
    {
        var valid = "foobar"u8;
        Assert.True(AvbUtil.ValidateUtf8(valid));

        // UTF-8 Chinese characters
        var chinese = "你好"u8;
        Assert.True(AvbUtil.ValidateUtf8(chinese));
    }

    [Fact]
    public void ValidateUtf8_Invalid()
    {
        // Invalid sequence (0xFF, 0xFE, 0xFD)
        ReadOnlySpan<byte> invalid = [0xFF, 0xFE, 0xFD];
        Assert.False(AvbUtil.ValidateUtf8(invalid));
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
        // $ (echo -n foobar > /tmp/crc32_input); crc32 /tmp/crc32_input
        // 9ef61f95
        var data = "foobar"u8;
        Assert.Equal(0x9ef61f95u, AvbCrc32.Compute(data));
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
}