using FirmwareKit.AVB.Fec;
using System.Security.Cryptography;

namespace FirmwareKit.AVB.Tests;

/// <summary>
/// Tests for <see cref="AvbFec"/> - the Reed-Solomon FEC parity generator.
/// The golden vectors were captured from the AOSP 'fec' tool (built from
/// system/extras/verity/fec + libfec) and cross-validated byte-for-byte.
/// <para><see cref="AvbFec"/>的测试 - Reed-Solomon FEC奇偶校验生成器。
/// 黄金向量取自AOSP 'fec'工具（由system/extras/verity/fec + libfec构建）
/// 并经逐字节交叉验证。</para>
/// </summary>
public class AvbFecTests
{
    private static byte[] Pattern(int size)
    {
        var data = new byte[size];
        for (var i = 0; i < size; i++)
        {
            data[i] = (byte)(i % 251);
        }

        return data;
    }

    private static string HashHex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    [Fact]
    public void ComputeParity_ZeroImageRoots2_MatchesReferenceVector()
    {
        var parity = AvbFec.ComputeParity(new byte[4096], 2);
        Assert.Equal(8192, parity.Length);
        Assert.Equal("9f1dcbc35c350d6027f98be0f5c8b43b42ca52b7604459c0c42be3aa88913d47", HashHex(parity));
    }

    [Fact]
    public void ComputeParity_PatternImageRoots2_MatchesReferenceVector()
    {
        var parity = AvbFec.ComputeParity(Pattern(4096), 2);
        Assert.Equal(8192, parity.Length);
        Assert.Equal("90fbe5529d7bd3fca798b9ee9b1d29b3277781f4e82e17a710d4c8c08ed394d6", HashHex(parity));
    }

    [Fact]
    public void ComputeParity_PatternImageRoots4_MatchesReferenceVector()
    {
        var parity = AvbFec.ComputeParity(Pattern(8192), 4);
        Assert.Equal(16384, parity.Length);
        Assert.Equal("5aebc03b2ed6dc252f6d3a4a1f2b245bd42eedbe834ee67c53778c0b4e297cb5", HashHex(parity));
    }

    [Fact]
    public void ComputeParity_ThreeBlockImageRoots2_MatchesReferenceVector()
    {
        var parity = AvbFec.ComputeParity(Pattern(12288), 2);
        Assert.Equal(8192, parity.Length);
        Assert.Equal("54e45a0716072250bdba057d82a07c6068e131965b6a7c138aaf7b2a03631b97", HashHex(parity));
    }

    [Fact]
    public void CalculateEccSize_MatchesReferenceFormula()
    {
        // fec_ecc_get_size() values as produced by the AOSP 'fec --print-fec-size'.
        Assert.Equal(20480UL, AvbFec.CalculateEccSize(1048576, 2));
        Assert.Equal(36864UL, AvbFec.CalculateEccSize(1048576, 4));
        Assert.Equal(77824UL, AvbFec.CalculateEccSize(8388608, 2));
        Assert.Equal(167936UL, AvbFec.CalculateEccSize(4194304, 8));
    }

    [Fact]
    public void ComputeParity_InvalidRoots_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AvbFec.ComputeParity(new byte[4096], 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => AvbFec.ComputeParity(new byte[4096], 255));
        Assert.Throws<ArgumentOutOfRangeException>(() => AvbFec.CalculateEccSize(4096, 0));
    }

    [Fact]
    public void ComputeParity_NonBlockAlignedOrEmpty_Throws()
    {
        Assert.Throws<ArgumentException>(() => AvbFec.ComputeParity(new byte[100], 2));
        Assert.Throws<ArgumentException>(() => AvbFec.ComputeParity(Array.Empty<byte>(), 2));
    }

    [Fact]
    public void Interleave_MapsCodewordPositionsPerEccHeader()
    {
        // fec_ecc_interleave(offset, rsn, rounds) = (offset / rsn) + (offset % rsn) * rounds * FEC_BLOCKSIZE
        Assert.Equal(0UL, AvbFec.Interleave(0, 253, 2));
        Assert.Equal(1UL, AvbFec.Interleave(253, 253, 2));
        Assert.Equal(8192UL, AvbFec.Interleave(1, 253, 2));
        Assert.Equal(8193UL, AvbFec.Interleave(254, 253, 2));
    }
}
