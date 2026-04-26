using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Core;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Security;
using FirmwareKit.AVB.VBMeta;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace FirmwareKit.AVB.Tests;

public class AvbCliTests
{
    [Fact]
    public async Task PrintPartitionDigests_OnMinimalVbmeta_ShouldPrintHashDigest()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var imagePath = Path.Combine(tempDir, "vbmeta.img");
            File.WriteAllBytes(imagePath, BuildMinimalVbmetaWithHashDescriptor());

            var cliDll = Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "..",
                "..",
                "..",
                "FirmwareKit.AVB.Cli",
                "bin",
                "Debug",
                "net8.0",
                "FirmwareKit.AVB.Cli.dll"));

            Assert.True(File.Exists(cliDll));

            var (exitCode, output, error) = await RunCliAsync(cliDll, $"vbmeta print-partition-digests \"{imagePath}\"");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("boot: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", output);
        }
        finally
        {
            try
            {
                Directory.Delete(tempDir, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task CalculateVBMetaDigest_Command_ShouldReturnDigest()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var imagePath = Path.Combine(tempDir, "vbmeta.img");
            File.WriteAllBytes(imagePath, BuildMinimalVbmetaWithHashDescriptor());

            var cliDll = GetCliDllPath();
            var (exitCode, output, error) = await RunCliAsync(
                cliDll,
                $"calculate_vbmeta_digest --image \"{imagePath}\" --hash_algorithm sha256");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("digest_alg: sha256", output);
            Assert.Contains("digest:", output);
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task SetAbMetadata_Command_ShouldWriteValidMetadataToOffset()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var miscPath = Path.Combine(tempDir, "misc.img");
            File.WriteAllBytes(miscPath, new byte[4096]);

            var cliDll = GetCliDllPath();
            var (exitCode, output, error) = await RunCliAsync(
                cliDll,
                $"set_ab_metadata --misc_image \"{miscPath}\" --slot_data 15:7:1:14:3:0");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("A/B metadata written", output);

            var allBytes = File.ReadAllBytes(miscPath);
            var metadata = AvbAbData.FromBytes(allBytes.AsSpan(2048, AvbAbData.Size));
            Assert.True(metadata.IsValid());
            Assert.Equal((byte)15, metadata.SlotA.Priority);
            Assert.Equal((byte)7, metadata.SlotA.TriesRemaining);
            Assert.Equal((byte)1, metadata.SlotA.SuccessfulBoot);
            Assert.Equal((byte)14, metadata.SlotB.Priority);
            Assert.Equal((byte)3, metadata.SlotB.TriesRemaining);
            Assert.Equal((byte)0, metadata.SlotB.SuccessfulBoot);
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task ExtractVBMetaImage_Command_ShouldExtractAndPad()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var vbmeta = BuildMinimalVbmetaWithHashDescriptor();
            var imagePath = Path.Combine(tempDir, "boot.img");
            var outputPath = Path.Combine(tempDir, "vbmeta_extracted.img");
            File.WriteAllBytes(imagePath, BuildImageWithFooter(vbmeta));

            var cliDll = GetCliDllPath();
            var (exitCode, output, error) = await RunCliAsync(
                cliDll,
                $"extract_vbmeta_image --image \"{imagePath}\" --output \"{outputPath}\" --padding_size 64");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("vbmeta extracted", output);

            var extracted = File.ReadAllBytes(outputPath);
            Assert.True((extracted.Length % 64) == 0);
            Assert.True(extracted.AsSpan(0, vbmeta.Length).SequenceEqual(vbmeta));
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task AvbtoolAliasCommands_ShouldWorkWithImageOption()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var imagePath = Path.Combine(tempDir, "vbmeta.img");
            File.WriteAllBytes(imagePath, BuildMinimalVbmetaWithHashDescriptor());

            var cliDll = GetCliDllPath();

            var (verifyCode, verifyOut, verifyErr) = await RunCliAsync(
                cliDll,
                $"verify_image --image \"{imagePath}\"");
            Assert.Equal(0, verifyCode);
            Assert.True(string.IsNullOrWhiteSpace(verifyErr), verifyErr);
            Assert.Contains("verify_result", verifyOut);

            var (infoCode, infoOut, infoErr) = await RunCliAsync(
                cliDll,
                $"info_image --image \"{imagePath}\"");
            Assert.Equal(0, infoCode);
            Assert.True(string.IsNullOrWhiteSpace(infoErr), infoErr);
            Assert.Contains("descriptor_count", infoOut);

            var (digestCode, digestOut, digestErr) = await RunCliAsync(
                cliDll,
                $"print_partition_digests --image \"{imagePath}\"");
            Assert.Equal(0, digestCode);
            Assert.True(string.IsNullOrWhiteSpace(digestErr), digestErr);
            Assert.Contains("boot:", digestOut);
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task GenerateTestImage_Command_ShouldCreatePattern()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var outPath = Path.Combine(tempDir, "pattern.img");
            var cliDll = GetCliDllPath();

            var (exitCode, _, error) = await RunCliAsync(
                cliDll,
                $"generate_test_image --image_size 32 --start_byte 250 --output \"{outPath}\"");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);

            var data = File.ReadAllBytes(outPath);
            Assert.Equal(32, data.Length);
            Assert.Equal(250, data[0]);
            Assert.Equal(255, data[5]);
            Assert.Equal(0, data[6]);
            Assert.Equal(25, data[31]);
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task ExtractPublicKey_AndDigest_Commands_ShouldProduceValidOutputs()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var keyPath = Path.Combine(tempDir, "key.pem");
            var pubPath = Path.Combine(tempDir, "pubkey.bin");
            var digestPath = Path.Combine(tempDir, "pubkey.sha256");

            using (var rsa = System.Security.Cryptography.RSA.Create(2048))
            {
                var privatePem = rsa.ExportRSAPrivateKeyPem();
                File.WriteAllText(keyPath, privatePem);
            }

            var cliDll = GetCliDllPath();

            var (extractCode, _, extractErr) = await RunCliAsync(
                cliDll,
                $"extract_public_key --key \"{keyPath}\" --output \"{pubPath}\"");
            Assert.Equal(0, extractCode);
            Assert.True(string.IsNullOrWhiteSpace(extractErr), extractErr);

            var encoded = File.ReadAllBytes(pubPath);
            var parsed = AvbCrypto.ParseRSAPublicKey(encoded);
            Assert.Equal(256, parsed.Modulus!.Length);

            var (digestCode, _, digestErr) = await RunCliAsync(
                cliDll,
                $"extract_public_key_digest --key \"{keyPath}\" --output \"{digestPath}\"");
            Assert.Equal(0, digestCode);
            Assert.True(string.IsNullOrWhiteSpace(digestErr), digestErr);

            var digestText = File.ReadAllText(digestPath).Trim();
            Assert.Equal(64, digestText.Length);
            Assert.Matches("^[0-9a-f]+$", digestText);
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task MakeVBMetaImage_Command_ShouldCreateUnsignedVbmeta()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var outPath = Path.Combine(tempDir, "vbmeta.img");
            var cliDll = GetCliDllPath();

            var (exitCode, output, error) = await RunCliAsync(
                cliDll,
                $"make_vbmeta_image --output \"{outPath}\" --algorithm NONE --padding_size 64");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("vbmeta image written", output);

            var vbmeta = File.ReadAllBytes(outPath);
            Assert.True((vbmeta.Length % 64) == 0);

            var image = new AvbVBMetaImage(vbmeta);
            Assert.Equal(AvbVBMetaVerifyResult.OkNotSigned, image.VerifyIntegrity());
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    [Fact]
    public async Task AddHashFooter_Command_ShouldAppendFooterAndHashDescriptor()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var imagePath = Path.Combine(tempDir, "boot.img");
            var outVbmeta = Path.Combine(tempDir, "boot.vbmeta.img");

            var payload = Enumerable.Range(0, 5000).Select(i => (byte)(i & 0xFF)).ToArray();
            File.WriteAllBytes(imagePath, payload);

            var cliDll = GetCliDllPath();
            var (exitCode, output, error) = await RunCliAsync(
                cliDll,
                $"add_hash_footer --image \"{imagePath}\" --partition_size 16384 --partition_name boot --hash_algorithm sha256 --salt aabbcc --output_vbmeta_image \"{outVbmeta}\"");

            Assert.Equal(0, exitCode);
            Assert.True(string.IsNullOrWhiteSpace(error), error);
            Assert.Contains("hash footer added", output);

            var finalImage = File.ReadAllBytes(imagePath);
            Assert.Equal(16384, finalImage.Length);

            var footer = AvbFooter.FromBytes(finalImage.AsSpan(finalImage.Length - AvbFooter.Size, AvbFooter.Size));
            Assert.True(footer.IsValid);
            Assert.Equal((ulong)payload.Length, footer.OriginalImageSize);

            var vbmeta = finalImage.AsSpan((int)footer.VBMetaOffset, (int)footer.VBMetaSize).ToArray();
            var vbmetaImage = new AvbVBMetaImage(vbmeta);
            var hashDescriptor = Assert.Single(vbmetaImage.GetDescriptors().OfType<AvbHashDescriptor>());
            Assert.Equal("boot", hashDescriptor.PartitionName);
            Assert.Equal("sha256", hashDescriptor.HashAlgorithm);
            Assert.Equal((ulong)payload.Length, hashDescriptor.ImageSize);
            Assert.Equal(new byte[] { 0xaa, 0xbb, 0xcc }, hashDescriptor.Salt);
            Assert.Equal(32, hashDescriptor.Digest.Length);

            Assert.True(File.Exists(outVbmeta));
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"FirmwareKit.AVB.Tests.{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private static string GetCliDllPath()
    {
        var cliDll = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
            "FirmwareKit.AVB.Cli",
            "bin",
            "Debug",
            "net8.0",
            "FirmwareKit.AVB.Cli.dll"));

        Assert.True(File.Exists(cliDll));
        return cliDll;
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunCliAsync(string cliDll, string command)
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"\"{cliDll}\" {command}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        Assert.NotNull(process);

        var output = await process!.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, output, error);
    }

    private static byte[] BuildImageWithFooter(byte[] vbmeta)
    {
        const int prefixSize = 1536;
        var vbmetaOffset = (ulong)prefixSize;

        var footer = new AvbFooter
        {
            MagicValue = AvbFooter.MagicValueLiteral,
            VersionMajor = AvbFooter.ExpectedVersionMajor,
            VersionMinor = AvbFooter.ExpectedVersionMinor,
            OriginalImageSize = (ulong)prefixSize,
            VBMetaOffset = vbmetaOffset,
            VBMetaSize = (ulong)vbmeta.Length
        };

        var footerBytes = new byte[AvbFooter.Size];
        footer.ToBytes(footerBytes);

        var image = new byte[prefixSize + vbmeta.Length + AvbFooter.Size];
        vbmeta.CopyTo(image.AsSpan(prefixSize));
        footerBytes.CopyTo(image.AsSpan(image.Length - AvbFooter.Size));
        return image;
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch
        {
        }
    }

    private static byte[] BuildMinimalVbmetaWithHashDescriptor()
    {
        var descriptorBody = new byte[152];
        BinaryPrimitives.WriteUInt64BigEndian(descriptorBody.AsSpan(0, 8), 123UL);
        Encoding.ASCII.GetBytes("sha256").CopyTo(descriptorBody.AsSpan(8, 6));
        BinaryPrimitives.WriteUInt32BigEndian(descriptorBody.AsSpan(40, 4), 4U);
        BinaryPrimitives.WriteUInt32BigEndian(descriptorBody.AsSpan(44, 4), 0U);
        BinaryPrimitives.WriteUInt32BigEndian(descriptorBody.AsSpan(48, 4), 32U);
        BinaryPrimitives.WriteUInt32BigEndian(descriptorBody.AsSpan(52, 4), 0U);
        Encoding.ASCII.GetBytes("boot").CopyTo(descriptorBody.AsSpan(116, 4));
        for (var i = 0; i < 32; i++)
        {
            descriptorBody[120 + i] = (byte)i;
        }

        var descriptor = new byte[16 + descriptorBody.Length];
        BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
        BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(8, 8), (ulong)descriptorBody.Length);
        descriptorBody.CopyTo(descriptor.AsSpan(16));

        var header = new byte[AvbVBMetaImageHeader.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), 0x30425641);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), AvbVBMetaImageHeader.ExpectedVersionMajor);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), 0U);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(12, 8), 64UL);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(20, 8), 192UL);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(28, 4), (uint)AvbAlgorithmType.None);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(96, 8), 0UL);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(104, 8), (ulong)descriptor.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(112, 8), 0UL);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(120, 4), 0U);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(124, 4), 0U);
        var release = Encoding.ASCII.GetBytes("avbtool test");
        release.CopyTo(header.AsSpan(128));
        header[128 + release.Length] = 0;

        var result = new byte[header.Length + 64 + 192];
        header.CopyTo(result.AsSpan(0));
        descriptor.CopyTo(result.AsSpan(header.Length + 64));
        return result;
    }
}
