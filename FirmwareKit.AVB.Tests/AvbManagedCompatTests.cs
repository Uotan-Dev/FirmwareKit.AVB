using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Core;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Security;
using FirmwareKit.AVB.Utilities;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FirmwareKit.AVB.Tests;

public class AvbManagedCompatTests
{
    [Fact]
    public void AvbUtil_StringHelpers_WorkAsExpected()
    {
        Span<char> buffer = stackalloc char[16];
        Assert.True(AvbUtil.StrConcat(buffer, "ab", 2, "cd", 2, out var written));
        Assert.Equal(4, written);
        Assert.Equal('a', buffer[0]);
        Assert.Equal('d', buffer[3]);
        Assert.Equal('\0', buffer[4]);

        Assert.Equal("abcdef", AvbUtil.StrDupV("ab", "cd", "ef"));
        Assert.Equal("foobar", AvbUtil.StrDup("foobar"));
        Assert.Equal("barbaz", AvbUtil.StrStr("foobarbaz", "bar"));
        Assert.Null(AvbUtil.StrStr("foobarbaz", "xxx"));
        Assert.Equal("b", AvbUtil.StrvFindStr(new[] { "a", "b", "c" }, "b"));
        Assert.Null(AvbUtil.StrvFindStr(new[] { "a", "b", "c" }, "d"));
        Assert.Equal("x b x", AvbUtil.Replace("a b a", "a", "x"));
    }

    [Fact]
    public void AvbCrypto_TryApis_WorkAsExpected()
    {
        using var rsa = RSA.Create(2048);
        var encoded = AvbCrypto.EncodeRSAPublicKey(rsa.ExportParameters(includePrivateParameters: false));

        Assert.True(AvbCrypto.TryParseRSAPublicKey(encoded, out var parsed));
        Assert.NotNull(parsed.Modulus);
        Assert.Equal(new byte[] { 1, 0, 1 }, parsed.Exponent);

        Assert.True(AvbCrypto.TryGetAlgorithmInfo(AvbAlgorithmType.Sha256Rsa4096, out var hashName, out var hashSize));
        Assert.Equal(HashAlgorithmName.SHA256, hashName);
        Assert.Equal(32, hashSize);

        Assert.False(AvbCrypto.TryGetAlgorithmInfo(AvbAlgorithmType.None, out _, out _));
    }

    [Fact]
    public void AvbFooter_TryFromBytes_ValidatesFooter()
    {
        var footer = new AvbFooter
        {
            MagicValue = AvbFooter.MagicValueLiteral,
            VersionMajor = AvbFooter.ExpectedVersionMajor,
            VersionMinor = AvbFooter.ExpectedVersionMinor,
            OriginalImageSize = 4096,
            VBMetaOffset = 4096,
            VBMetaSize = 1024
        };

        var bytes = new byte[AvbFooter.Size];
        footer.ToBytes(bytes);

        Assert.True(AvbFooter.TryFromBytes(bytes, out var parsed));
        Assert.True(parsed.IsFullyValid);

        bytes[0] = 0;
        Assert.False(AvbFooter.TryFromBytes(bytes, out _));
    }

    [Fact]
    public void AvbDescriptor_Enumerate_ParsesMultipleDescriptors()
    {
        var kernelBody = new byte[8 + 8];
        BinaryPrimitives.WriteUInt32BigEndian(kernelBody.AsSpan(0, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(kernelBody.AsSpan(4, 4), 8);
        System.Text.Encoding.UTF8.GetBytes("console=").CopyTo(kernelBody.AsSpan(8));

        var kernelDescriptor = new byte[16 + kernelBody.Length];
        BinaryPrimitives.WriteUInt64BigEndian(kernelDescriptor.AsSpan(0, 8), (ulong)AvbDescriptorTag.KernelCmdline);
        BinaryPrimitives.WriteUInt64BigEndian(kernelDescriptor.AsSpan(8, 8), (ulong)kernelBody.Length);
        kernelBody.CopyTo(kernelDescriptor.AsSpan(16));

        var unknownBody = new byte[8];
        var unknownDescriptor = new byte[16 + unknownBody.Length];
        BinaryPrimitives.WriteUInt64BigEndian(unknownDescriptor.AsSpan(0, 8), 999UL);
        BinaryPrimitives.WriteUInt64BigEndian(unknownDescriptor.AsSpan(8, 8), (ulong)unknownBody.Length);
        unknownBody.CopyTo(unknownDescriptor.AsSpan(16));

        var blob = kernelDescriptor.Concat(unknownDescriptor).ToArray();
        var descriptors = AvbDescriptor.Enumerate(blob);

        Assert.Equal(2, descriptors.Count);
        Assert.IsType<AvbKernelCmdlineDescriptor>(descriptors[0]);
        Assert.IsType<UnknownAvbDescriptor>(descriptors[1]);
    }

    [Fact]
    public void FileSystemAvbOps_ReadWriteAndMetadata_WorkAsExpected()
    {
        var root = Path.Combine(Path.GetTempPath(), "avb-ops-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var bootPath = Path.Combine(root, "boot_a.img");
            File.WriteAllBytes(bootPath, Enumerable.Range(0, 128).Select(i => (byte)i).ToArray());

            var ops = new FileSystemAvbOps(root, isDeviceUnlocked: true);
            ops.SetPartitionGuid("boot_a", "guid-boot-a");
            ops.SetPreloadedPartition("boot_a", File.ReadAllBytes(bootPath));

            Assert.Equal(AvbIOResult.Ok, ops.GetSizeOfPartition("boot_a", out var size));
            Assert.Equal(128, size);

            var buffer = new byte[16];
            Assert.Equal(AvbIOResult.Ok, ops.ReadFromPartition("boot_a", 0, 16, buffer, out var bytesRead));
            Assert.Equal(16, bytesRead);
            Assert.Equal((byte)0, buffer[0]);
            Assert.Equal((byte)15, buffer[15]);

            var tail = new byte[4];
            Assert.Equal(AvbIOResult.Ok, ops.ReadFromPartition("boot_a", -4, 4, tail, out bytesRead));
            Assert.Equal(4, bytesRead);
            Assert.Equal((byte)124, tail[0]);
            Assert.Equal((byte)127, tail[3]);

            Assert.Equal(AvbIOResult.Ok, ops.WriteToPartition("boot_a", 4, 4, new byte[] { 9, 8, 7, 6 }));
            var verify = File.ReadAllBytes(bootPath);
            Assert.Equal(new byte[] { 9, 8, 7, 6 }, verify.Skip(4).Take(4).ToArray());

            Assert.Equal(AvbIOResult.Ok, ops.GetUniqueGuidForPartition("boot_a", out var guid));
            Assert.Equal("guid-boot-a", guid);

            Assert.Equal(AvbIOResult.Ok, ops.ReadIsDeviceUnlocked(out var unlocked));
            Assert.True(unlocked);

            Assert.Equal(AvbIOResult.Ok, ops.GetPreloadedPartition("boot_a", 8, out var preloaded));
            Assert.Equal(8, preloaded.Length);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
