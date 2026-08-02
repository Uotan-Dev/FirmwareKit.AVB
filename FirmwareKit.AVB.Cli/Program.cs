using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Core;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Fec;
using FirmwareKit.AVB.Hashtree;
using FirmwareKit.AVB.Security;
using FirmwareKit.AVB.VBMeta;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

return Run(args);

static int Run(string[] args)
{
    if (args.Length == 0)
    {
        PrintHelp();
        return 1;
    }

    try
    {
        if (args.Length >= 1 && args[0] == "version")
        {
            Console.WriteLine(GetVersionString());
            return 0;
        }

        if (args.Length >= 1 && args[0] == "generate_test_image")
        {
            return GenerateTestImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "extract_public_key")
        {
            return ExtractPublicKeyCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "extract_public_key_digest")
        {
            return ExtractPublicKeyDigestCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "make_vbmeta_image")
        {
            return MakeVBMetaImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "add_hash_footer")
        {
            return AddHashFooterCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "add_hashtree_footer")
        {
            return AddHashtreeFooterCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "make_hashtree_image")
        {
            return MakeHashtreeImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "verify_hashtree")
        {
            return VerifyHashtreeCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "calc_footer_size")
        {
            return CalcFooterSizeCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 2 && args[0] == "fec" && args[1] == "encode")
        {
            return FecEncodeCommand(args.Skip(2).ToArray());
        }

        if (args.Length >= 2 && args[0] == "fec" && args[1] == "calc-size")
        {
            return FecCalcSizeCommand(args.Skip(2).ToArray());
        }

        if (args.Length >= 3 && args[0] == "vbmeta" && args[1] == "verify")
        {
            return VerifyVbmeta(args[2]);
        }

        if (args.Length >= 3 && args[0] == "vbmeta" && args[1] == "info")
        {
            return InfoVbmeta(args[2]);
        }

        if (args.Length >= 3 && args[0] == "vbmeta" && args[1] == "digest")
        {
            var useSha512 = args.Skip(3).Any(a => a == "--sha512");
            return DigestVbmeta(args[2], useSha512);
        }

        if (args.Length >= 3 && args[0] == "vbmeta" && args[1] == "print-partition-digests")
        {
            var useJson = args.Skip(3).Any(a => a == "--json");
            return PrintPartitionDigests(args[2], useJson);
        }

        if (args.Length >= 1 && args[0] == "calculate_vbmeta_digest")
        {
            return CalculateVBMetaDigestCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "print_partition_digests")
        {
            return PrintPartitionDigestsCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "info_image")
        {
            return InfoImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "verify_image")
        {
            return VerifyImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "extract_vbmeta_image")
        {
            return ExtractVBMetaImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "erase_footer")
        {
            return EraseFooterCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "resize_image")
        {
            return ResizeImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "set_ab_metadata")
        {
            return SetAbMetadataCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "append_vbmeta_image")
        {
            return AppendVBMetaImageCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 1 && args[0] == "zero_hashtree")
        {
            return ZeroHashtreeCommand(args.Skip(1).ToArray());
        }

        if (args.Length >= 3 && args[0] == "ab" && args[1] == "inspect")
        {
            return InspectAb(args[2]);
        }

        if (args.Length >= 2 && args[0] == "cert" && args[1] == "make-unlock-credential")
        {
            return MakeUnlockCredential(args.Skip(2).ToArray());
        }

        if (args.Length >= 2 && args[0] == "cert" && args[1] == "make-unlock-credential-from-archive")
        {
            return MakeUnlockCredentialFromArchive(args.Skip(2).ToArray());
        }

        if (args.Length >= 2 && args[0] == "cert" && args[1] == "make-unlock-credential-auto")
        {
            return MakeUnlockCredentialAuto(args.Skip(2).ToArray());
        }

        if (args.Length >= 3 && args[0] == "cert" && args[1] == "inspect-challenge")
        {
            return InspectChallenge(args[2]);
        }

        if (args.Length >= 3 && args[0] == "cert" && args[1] == "inspect-archive")
        {
            return InspectCredentialArchive(args[2]);
        }

        if (args.Length >= 2 && args[0] == "persistent-digest" && args[1] == "build")
        {
            return BuildPersistentDigestInput(args.Skip(2).ToArray());
        }

        if (args.Length >= 2 && args[0] == "persistent-digest" && args[1] == "build-clear-factory")
        {
            return BuildClearFactoryPersistentDigestInput(args.Skip(2).ToArray());
        }

        if (args.Length >= 3 && args[0] == "persistent-digest" && args[1] == "inspect")
        {
            return InspectPersistentDigestInput(args[2]);
        }

        if (args.Length >= 2 && args[0] == "auth-unlock" && args[1] == "run")
        {
            return RunAuthenticatedUnlock(args.Skip(2).ToArray());
        }

        PrintHelp();
        return 1;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 2;
    }
}

static int VerifyVbmeta(string path)
{
    var bytes = File.ReadAllBytes(path);
    var image = new AvbVBMetaImage(bytes);
    var result = image.VerifyIntegrity();

    Console.WriteLine($"file: {path}");
    Console.WriteLine($"verify_result: {result}");
    Console.WriteLine($"algorithm_type: {(AvbAlgorithmType)image.Header.AlgorithmType}");
    Console.WriteLine($"flags: 0x{image.Header.Flags:x8}");
    Console.WriteLine($"rollback_index: {image.Header.RollbackIndex}");

    return result == AvbVBMetaVerifyResult.Ok || result == AvbVBMetaVerifyResult.OkNotSigned ? 0 : 3;
}

static int InfoVbmeta(string path)
{
    var bytes = File.ReadAllBytes(path);
    var image = new AvbVBMetaImage(bytes);
    var descriptors = image.GetDescriptors();

    Console.WriteLine($"file: {path}");
    Console.WriteLine($"required_libavb_version: {image.Header.RequiredLibavbVersionMajor}.{image.Header.RequiredLibavbVersionMinor}");
    Console.WriteLine($"algorithm_type: {(AvbAlgorithmType)image.Header.AlgorithmType}");
    Console.WriteLine($"rollback_index: {image.Header.RollbackIndex}");
    Console.WriteLine($"flags: 0x{image.Header.Flags:x8}");
    Console.WriteLine($"release_string: {image.Header.ReleaseString}");
    Console.WriteLine($"descriptor_count: {descriptors.Count}");

    for (var i = 0; i < descriptors.Count; i++)
    {
        var d = descriptors[i];
        Console.WriteLine($"descriptor[{i}].tag: {d.Tag}");

        switch (d)
        {
            case AvbHashDescriptor hash:
                Console.WriteLine($"descriptor[{i}].partition: {hash.PartitionName}");
                Console.WriteLine($"descriptor[{i}].hash_algorithm: {hash.HashAlgorithm}");
                Console.WriteLine($"descriptor[{i}].image_size: {hash.ImageSize}");
                Console.WriteLine($"descriptor[{i}].digest: {ToHexLower(hash.Digest)}");
                break;
            case AvbHashtreeDescriptor tree:
                Console.WriteLine($"descriptor[{i}].partition: {tree.PartitionName}");
                Console.WriteLine($"descriptor[{i}].hash_algorithm: {tree.HashAlgorithm}");
                Console.WriteLine($"descriptor[{i}].image_size: {tree.ImageSize}");
                Console.WriteLine($"descriptor[{i}].root_digest: {ToHexLower(tree.RootDigest)}");
                break;
            case AvbChainPartitionDescriptor chain:
                Console.WriteLine($"descriptor[{i}].partition: {chain.PartitionName}");
                Console.WriteLine($"descriptor[{i}].rollback_index_location: {chain.RollbackIndexLocation}");
                break;
            case AvbPropertyDescriptor prop:
                Console.WriteLine($"descriptor[{i}].key: {prop.Key}");
                Console.WriteLine($"descriptor[{i}].value_hex: {ToHexLower(prop.Value)}");
                break;
            case AvbKernelCmdlineDescriptor cmd:
                Console.WriteLine($"descriptor[{i}].flags: {cmd.Flags}");
                Console.WriteLine($"descriptor[{i}].cmdline: {cmd.KernelCmdline}");
                break;
            case UnknownAvbDescriptor unknown:
                Console.WriteLine($"descriptor[{i}].bytes: {unknown.Data.Length}");
                break;
        }
    }

    return 0;
}

static int DigestVbmeta(string path, bool useSha512)
{
    var bytes = File.ReadAllBytes(path);
    var image = new AvbVBMetaImage(bytes);

    var headerSize = AvbVBMetaImageHeader.Size;
    var authSize = (int)image.Header.AuthenticationDataBlockSize;
    var auxSize = (int)image.Header.AuxiliaryDataBlockSize;

    // libavb hash/sign flow digests header + auxiliary block.
    var headerBlock = bytes.AsSpan(0, headerSize).ToArray();
    var auxiliaryBlock = bytes.AsSpan(headerSize + authSize, auxSize).ToArray();

    byte[] digest;
    if (useSha512)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(headerBlock);
        hash.AppendData(auxiliaryBlock);
        digest = hash.GetHashAndReset();
    }
    else
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(headerBlock);
        hash.AppendData(auxiliaryBlock);
        digest = hash.GetHashAndReset();
    }

    Console.WriteLine($"file: {path}");
    Console.WriteLine($"digest_alg: {(useSha512 ? "sha512" : "sha256")}");
    Console.WriteLine($"digest: {ToHexLower(digest)}");

    return 0;
}

static string GetVersionString() => "avbtool 1.4.3";

static int GenerateTestImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image_size", out var imageSizeText) ||
        !long.TryParse(imageSizeText, out var imageSize) || imageSize < 0)
    {
        Console.Error.WriteLine("error: missing or invalid --image_size for generate_test_image");
        return 9;
    }

    var startByte = 0;
    if (options.TryGetValue("--start_byte", out var startByteText) &&
        !int.TryParse(startByteText, out startByte))
    {
        Console.Error.WriteLine("error: invalid --start_byte value");
        return 9;
    }

    options.TryGetValue("--output", out var outputPath);

    var output = new byte[imageSize];
    for (long i = 0; i < imageSize; i++)
    {
        output[i] = (byte)((startByte + i) & 0xFF);
    }

    if (string.IsNullOrWhiteSpace(outputPath))
    {
        Console.OpenStandardOutput().Write(output, 0, output.Length);
    }
    else
    {
        File.WriteAllBytes(outputPath, output);
        Console.WriteLine($"test image generated: {outputPath}");
    }

    return 0;
}

static int ExtractPublicKeyCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--key", out var keyPath) ||
        !options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required options for extract_public_key");
        Console.Error.WriteLine("required: --key <pem> --output <file>");
        return 9;
    }

    using var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText(keyPath));
    var encoded = AvbCrypto.EncodeRSAPublicKey(rsa.ExportParameters(includePrivateParameters: false));
    File.WriteAllBytes(outputPath, encoded);
    Console.WriteLine($"public key extracted: {outputPath}");
    return 0;
}

static int ExtractPublicKeyDigestCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--key", out var keyPath) ||
        !options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required options for extract_public_key_digest");
        Console.Error.WriteLine("required: --key <pem> --output <file>");
        return 9;
    }

    using var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText(keyPath));
    var encoded = AvbCrypto.EncodeRSAPublicKey(rsa.ExportParameters(includePrivateParameters: false));
    var digest = SHA256.HashData(encoded);
    var digestHex = ToHexLower(digest);
    File.WriteAllText(outputPath, digestHex);
    Console.WriteLine($"public key digest extracted: {outputPath}");
    return 0;
}

static int MakeVBMetaImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required option --output for make_vbmeta_image");
        return 9;
    }

    var algorithmName = options.TryGetValue("--algorithm", out var alg) ? alg : "NONE";
    var algorithmType = algorithmName switch
    {
        "NONE" => AvbAlgorithmType.None,
        "sha256-rsa2048" => AvbAlgorithmType.Sha256Rsa2048,
        "sha256-rsa4096" => AvbAlgorithmType.Sha256Rsa4096,
        "sha256-rsa8192" => AvbAlgorithmType.Sha256Rsa8192,
        "sha512-rsa2048" => AvbAlgorithmType.Sha512Rsa2048,
        "sha512-rsa4096" => AvbAlgorithmType.Sha512Rsa4096,
        "sha512-rsa8192" => AvbAlgorithmType.Sha512Rsa8192,
        _ => throw new ArgumentException($"Unsupported algorithm: {algorithmName}")
    };

    string? keyPath = null;
    string? signingHelper = null;
    string? signingHelperWithFiles = null;

    if (algorithmType != AvbAlgorithmType.None)
    {
        if (!options.TryGetValue("--key", out keyPath))
        {
            Console.Error.WriteLine("error: --key is required when --algorithm is not NONE");
            return 9;
        }

        options.TryGetValue("--signing_helper", out signingHelper);
        options.TryGetValue("--signing_helper_with_files", out signingHelperWithFiles);
    }

    var rollbackIndex = options.TryGetValue("--rollback_index", out var rollbackIndexText) && ulong.TryParse(rollbackIndexText, out var ri)
        ? ri
        : 0UL;
    var flags = options.TryGetValue("--flags", out var flagsText) && uint.TryParse(flagsText, out var fl)
        ? fl
        : 0U;
    var rollbackIndexLocation = options.TryGetValue("--rollback_index_location", out var rilText) && uint.TryParse(rilText, out var ril)
        ? ril
        : 0U;
    var releaseString = options.TryGetValue("--release_string", out var rs)
        ? rs
        : GetVersionString();

    var blob = BuildVBMetaBlob(
        descriptors: ReadOnlySpan<byte>.Empty,
        algorithmType: (uint)algorithmType,
        rollbackIndex: rollbackIndex,
        flags: flags,
        rollbackIndexLocation: rollbackIndexLocation,
        releaseString: releaseString,
        keyPath: keyPath,
        signingHelper: signingHelper,
        signingHelperWithFiles: signingHelperWithFiles);

    if (options.TryGetValue("--padding_size", out var paddingText) &&
        int.TryParse(paddingText, out var paddingSize) &&
        paddingSize > 0)
    {
        blob = PadToMultiple(blob, paddingSize);
    }

    File.WriteAllBytes(outputPath, blob);
    Console.WriteLine($"vbmeta image written: {outputPath}");
    return 0;
}

static int AddHashFooterCommand(string[] args)
{
    var options = ParseOptions(args);
    var flags = ParseFlags(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for add_hash_footer");
        return 9;
    }

    var algorithmName = options.TryGetValue("--algorithm", out var alg) ? alg : "NONE";
    var algorithmType = algorithmName switch
    {
        "NONE" => AvbAlgorithmType.None,
        "sha256-rsa2048" => AvbAlgorithmType.Sha256Rsa2048,
        "sha256-rsa4096" => AvbAlgorithmType.Sha256Rsa4096,
        "sha256-rsa8192" => AvbAlgorithmType.Sha256Rsa8192,
        "sha512-rsa2048" => AvbAlgorithmType.Sha512Rsa2048,
        "sha512-rsa4096" => AvbAlgorithmType.Sha512Rsa4096,
        "sha512-rsa8192" => AvbAlgorithmType.Sha512Rsa8192,
        _ => throw new ArgumentException($"Unsupported algorithm: {algorithmName}")
    };

    string? keyPath = null;
    string? signingHelper = null;
    string? signingHelperWithFiles = null;

    if (algorithmType != AvbAlgorithmType.None)
    {
        if (!options.TryGetValue("--key", out keyPath))
        {
            Console.Error.WriteLine("error: --key is required when --algorithm is not NONE");
            return 9;
        }

        options.TryGetValue("--signing_helper", out signingHelper);
        options.TryGetValue("--signing_helper_with_files", out signingHelperWithFiles);
    }

    var partitionName = options.TryGetValue("--partition_name", out var pn)
        ? pn
        : Path.GetFileNameWithoutExtension(imagePath);
    var hashAlgorithm = options.TryGetValue("--hash_algorithm", out var ha)
        ? ha.ToLowerInvariant()
        : "sha256";

    byte[] salt;
    if (options.TryGetValue("--salt", out var saltHex))
    {
        try
        {
            salt = Convert.FromHexString(saltHex);
        }
        catch
        {
            Console.Error.WriteLine("error: --salt must be valid hex");
            return 9;
        }
    }
    else
    {
        salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
    }

    var image = File.ReadAllBytes(imagePath);
    var originalImageSize = (ulong)image.Length;
    if (TryGetFooter(image, out var existingFooter) && existingFooter.OriginalImageSize <= (ulong)image.Length)
    {
        originalImageSize = existingFooter.OriginalImageSize;
        image = image.AsSpan(0, (int)existingFooter.OriginalImageSize).ToArray();
    }

    var digest = AvbCrypto.CalculateHash(hashAlgorithm, salt, image);
    var hashDescriptor = BuildHashDescriptorBlob(
        imageSize: (ulong)image.Length,
        hashAlgorithm: hashAlgorithm,
        partitionName: partitionName,
        salt: salt,
        digest: digest,
        descriptorFlags: flags.Contains("--do_not_use_ab") ? (uint)AvbHashDescriptorFlags.DoNotUseAb : 0U);

    var rollbackIndex = options.TryGetValue("--rollback_index", out var rollbackIndexText) && ulong.TryParse(rollbackIndexText, out var ri)
        ? ri
        : 0UL;
    var vbmetaFlags = options.TryGetValue("--flags", out var vbmetaFlagsText) && uint.TryParse(vbmetaFlagsText, out var vf)
        ? vf
        : 0U;
    var rollbackIndexLocation = options.TryGetValue("--rollback_index_location", out var rilText) && uint.TryParse(rilText, out var ril)
        ? ril
        : 0U;

    var vbmetaBlob = BuildVBMetaBlob(
        descriptors: hashDescriptor,
        algorithmType: (uint)algorithmType,
        rollbackIndex: rollbackIndex,
        flags: vbmetaFlags,
        rollbackIndexLocation: rollbackIndexLocation,
        releaseString: GetVersionString(),
        keyPath: keyPath,
        signingHelper: signingHelper,
        signingHelperWithFiles: signingHelperWithFiles);

    if (options.TryGetValue("--output_vbmeta_image", out var outVbmetaPath))
    {
        File.WriteAllBytes(outVbmetaPath, vbmetaBlob);
    }

    if (flags.Contains("--do_not_append_vbmeta_image"))
    {
        Console.WriteLine("hash footer metadata generated without appending to image");
        return 0;
    }

    ulong partitionSize;
    if (flags.Contains("--dynamic_partition_size"))
    {
        const ulong blockSize = 4096;
        var alignedImage = AlignUp((ulong)image.Length, blockSize);
        var alignedVbmeta = AlignUp((ulong)vbmetaBlob.Length, blockSize);
        partitionSize = alignedImage + alignedVbmeta + blockSize;
    }
    else if (!options.TryGetValue("--partition_size", out var partitionSizeText) || !ulong.TryParse(partitionSizeText, out partitionSize))
    {
        Console.Error.WriteLine("error: missing required --partition_size (or set --dynamic_partition_size)");
        return 9;
    }

    if (flags.Contains("--calc_max_image_size"))
    {
        const ulong blockSize = 4096;
        var maxImage = partitionSize - AlignUp((ulong)vbmetaBlob.Length, blockSize) - blockSize;
        Console.WriteLine(maxImage);
        return 0;
    }

    var appendResult = AppendVBMetaImageInternal(imagePath, image, originalImageSize, vbmetaBlob, partitionSize);
    if (appendResult != 0)
    {
        return appendResult;
    }

    Console.WriteLine("hash footer added");
    return 0;
}

static int AddHashtreeFooterCommand(string[] args)
{
    var options = ParseOptions(args);
    var flags = ParseFlags(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for add_hashtree_footer");
        return 9;
    }

    var algorithmName = options.TryGetValue("--algorithm", out var alg) ? alg : "NONE";
    var algorithmType = algorithmName switch
    {
        "NONE" => AvbAlgorithmType.None,
        "sha256-rsa2048" => AvbAlgorithmType.Sha256Rsa2048,
        "sha256-rsa4096" => AvbAlgorithmType.Sha256Rsa4096,
        "sha256-rsa8192" => AvbAlgorithmType.Sha256Rsa8192,
        "sha512-rsa2048" => AvbAlgorithmType.Sha512Rsa2048,
        "sha512-rsa4096" => AvbAlgorithmType.Sha512Rsa4096,
        "sha512-rsa8192" => AvbAlgorithmType.Sha512Rsa8192,
        _ => throw new ArgumentException($"Unsupported algorithm: {algorithmName}")
    };

    string? keyPath = null;
    string? signingHelper = null;
    string? signingHelperWithFiles = null;

    if (algorithmType != AvbAlgorithmType.None)
    {
        if (!options.TryGetValue("--key", out keyPath))
        {
            Console.Error.WriteLine("error: --key is required when --algorithm is not NONE");
            return 9;
        }

        options.TryGetValue("--signing_helper", out signingHelper);
        options.TryGetValue("--signing_helper_with_files", out signingHelperWithFiles);
    }

    var partitionName = options.TryGetValue("--partition_name", out var pn)
        ? pn
        : Path.GetFileNameWithoutExtension(imagePath);
    var hashAlgorithm = options.TryGetValue("--hash_algorithm", out var ha)
        ? ha.ToLowerInvariant()
        : "sha256";

    byte[] salt;
    if (options.TryGetValue("--salt", out var saltHex))
    {
        try
        {
            salt = Convert.FromHexString(saltHex);
        }
        catch
        {
            Console.Error.WriteLine("error: --salt must be valid hex");
            return 9;
        }
    }
    else
    {
        salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
    }

    var blockSize = options.TryGetValue("--block_size", out var blockSizeText) && int.TryParse(blockSizeText, out var bs)
        ? bs
        : 4096;

    var image = File.ReadAllBytes(imagePath);
    var originalImageSize = (ulong)image.Length;
    if (TryGetFooter(image, out var existingFooter) && existingFooter.OriginalImageSize <= (ulong)image.Length)
    {
        originalImageSize = existingFooter.OriginalImageSize;
        image = image.AsSpan(0, (int)existingFooter.OriginalImageSize).ToArray();
    }

    if (image.Length % blockSize != 0)
    {
        Console.Error.WriteLine($"error: image size {image.Length} is not a multiple of block size {blockSize}");
        return 9;
    }

    var hashtree = GenerateHashTree(image, blockSize, hashAlgorithm, salt, out var rootDigest);

    // FEC (Forward Error Correction) parity data over data + hashtree,
    // mirroring avbtool add_hashtree_footer with --generate_fec (default on).
    var generateFec = !flags.Contains("--do_not_generate_fec");
    var fecNumRoots = options.TryGetValue("--fec_num_roots", out var fecRootsText) && int.TryParse(fecRootsText, out var fecRoots)
        ? fecRoots
        : AvbFec.DefaultRoots;
    byte[] fecData = Array.Empty<byte>();
    ulong fecOffset = 0;
    if (generateFec)
    {
        var dataPlusTree = new byte[image.Length + hashtree.Length];
        image.CopyTo(dataPlusTree, 0);
        hashtree.CopyTo(dataPlusTree, image.Length);
        fecData = AvbFec.ComputeParity(dataPlusTree, fecNumRoots);
        fecOffset = (ulong)(image.Length + hashtree.Length);
    }

    var hashtreeDescriptor = BuildHashtreeDescriptorBlob(
        imageSize: (ulong)image.Length,
        hashAlgorithm: hashAlgorithm,
        partitionName: partitionName,
        salt: salt,
        rootDigest: rootDigest,
        blockSize: blockSize,
        treeOffset: (ulong)image.Length,
        treeSize: (ulong)hashtree.Length,
        fecNumRoots: generateFec ? (uint)fecNumRoots : 0U,
        fecOffset: generateFec ? fecOffset : 0UL,
        fecSize: generateFec ? (ulong)fecData.Length : 0UL,
        descriptorFlags: flags.Contains("--do_not_use_ab") ? (uint)AvbHashDescriptorFlags.DoNotUseAb : 0U);

    var rollbackIndex = options.TryGetValue("--rollback_index", out var rollbackIndexText) && ulong.TryParse(rollbackIndexText, out var ri)
        ? ri
        : 0UL;
    var vbmetaFlags = options.TryGetValue("--flags", out var vbmetaFlagsText) && uint.TryParse(vbmetaFlagsText, out var vf)
        ? vf
        : 0U;
    var rollbackIndexLocation = options.TryGetValue("--rollback_index_location", out var rilText) && uint.TryParse(rilText, out var ril)
        ? ril
        : 0U;

    var vbmetaBlob = BuildVBMetaBlob(
        descriptors: hashtreeDescriptor,
        algorithmType: (uint)algorithmType,
        rollbackIndex: rollbackIndex,
        flags: vbmetaFlags,
        rollbackIndexLocation: rollbackIndexLocation,
        releaseString: GetVersionString(),
        keyPath: keyPath,
        signingHelper: signingHelper,
        signingHelperWithFiles: signingHelperWithFiles);

    if (options.TryGetValue("--output_vbmeta_image", out var outVbmetaPath))
    {
        File.WriteAllBytes(outVbmetaPath, vbmetaBlob);
    }

    if (flags.Contains("--do_not_append_vbmeta_image"))
    {
        Console.WriteLine("hashtree footer metadata generated without appending to image");
        return 0;
    }

    ulong partitionSize;
    if (flags.Contains("--dynamic_partition_size"))
    {
        const ulong blockSizeUL = 4096;
        var alignedImage = AlignUp((ulong)image.Length, blockSizeUL);
        var alignedHashtree = AlignUp((ulong)hashtree.Length, blockSizeUL);
        var alignedFec = AlignUp((ulong)fecData.Length, blockSizeUL);
        var alignedVbmeta = AlignUp((ulong)vbmetaBlob.Length, blockSizeUL);
        partitionSize = alignedImage + alignedHashtree + alignedFec + alignedVbmeta + blockSizeUL;
    }
    else if (!options.TryGetValue("--partition_size", out var partitionSizeText) || !ulong.TryParse(partitionSizeText, out partitionSize))
    {
        Console.Error.WriteLine("error: missing required --partition_size (or set --dynamic_partition_size)");
        return 9;
    }

    if (flags.Contains("--calc_max_image_size"))
    {
        const ulong blockSizeUL = 4096;
        var maxImage = partitionSize - AlignUp((ulong)hashtree.Length, blockSizeUL) - AlignUp((ulong)fecData.Length, blockSizeUL) - AlignUp((ulong)vbmetaBlob.Length, blockSizeUL) - blockSizeUL;
        Console.WriteLine(maxImage);
        return 0;
    }

    var appendResult = AppendHashtreeAndVBMetaInternal(imagePath, image, hashtree, fecData, originalImageSize, vbmetaBlob, partitionSize);
    if (appendResult != 0)
    {
        return appendResult;
    }

    Console.WriteLine("hashtree footer added");
    return 0;
}

static int PrintPartitionDigests(string path, bool useJson)
{
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var entries = new List<(string PartitionName, string Digest)>();

    CollectPartitionDigests(path, seen, entries);

    if (useJson)
    {
        Console.WriteLine("[");
        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var suffix = i + 1 == entries.Count ? string.Empty : ",";
            Console.WriteLine($"  {{ \"partition\": \"{EscapeJson(entry.PartitionName)}\", \"digest\": \"{entry.Digest}\" }}{suffix}");
        }
        Console.WriteLine("]");
        return 0;
    }

    foreach (var entry in entries)
    {
        Console.WriteLine($"{entry.PartitionName}: {entry.Digest}");
    }

    return 0;
}

static int CalculateVBMetaDigestCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for calculate_vbmeta_digest");
        return 9;
    }

    var useSha512 = options.TryGetValue("--hash_algorithm", out var alg) &&
                    string.Equals(alg, "sha512", StringComparison.OrdinalIgnoreCase);
    return DigestVbmeta(imagePath, useSha512);
}

static int PrintPartitionDigestsCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for print_partition_digests");
        return 9;
    }

    var useJson = options.TryGetValue("--output", out var outputFormat) &&
                  string.Equals(outputFormat, "json", StringComparison.OrdinalIgnoreCase);
    return PrintPartitionDigests(imagePath, useJson);
}

static int InfoImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for info_image");
        return 9;
    }

    using var capture = new StringWriter();
    var originalOut = Console.Out;
    try
    {
        Console.SetOut(capture);
        var code = InfoVbmeta(imagePath);
        Console.Out.Flush();

        var text = capture.ToString();
        if (options.TryGetValue("--output", out var outputPath))
        {
            File.WriteAllText(outputPath, text);
        }

        originalOut.Write(text);
        return code;
    }
    finally
    {
        Console.SetOut(originalOut);
    }
}

static int VerifyImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for verify_image");
        return 9;
    }

    return VerifyVbmeta(imagePath);
}

static int ExtractVBMetaImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath) ||
        !options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required options for extract_vbmeta_image");
        Console.Error.WriteLine("required: --image <file> --output <file> [--padding_size <n>]");
        return 9;
    }

    var imageBytes = File.ReadAllBytes(imagePath);
    if (!TryGetFooter(imageBytes, out var footer))
    {
        Console.Error.WriteLine("error: given image does not have a valid footer");
        return 9;
    }

    if (footer.VBMetaOffset + footer.VBMetaSize > (ulong)imageBytes.Length)
    {
        Console.Error.WriteLine("error: footer points outside image bounds");
        return 9;
    }

    var vbmetaBlob = imageBytes.AsSpan((int)footer.VBMetaOffset, (int)footer.VBMetaSize).ToArray();
    var output = new List<byte>(vbmetaBlob);

    if (options.TryGetValue("--padding_size", out var paddingSizeText) &&
        int.TryParse(paddingSizeText, out var paddingSize) &&
        paddingSize > 0)
    {
        var paddingNeeded = (paddingSize - (output.Count % paddingSize)) % paddingSize;
        if (paddingNeeded > 0)
        {
            output.AddRange(new byte[paddingNeeded]);
        }
    }

    File.WriteAllBytes(outputPath, output.ToArray());
    Console.WriteLine($"vbmeta extracted: {outputPath}");
    return 0;
}

static int EraseFooterCommand(string[] args)
{
    var options = ParseOptions(args);
    var flags = ParseFlags(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for erase_footer");
        return 9;
    }

    var keepHashtree = flags.Contains("--keep_hashtree") || flags.Contains("--keep_hashtree=true");
    var imageBytes = File.ReadAllBytes(imagePath);
    if (!TryGetFooter(imageBytes, out var footer))
    {
        Console.Error.WriteLine("error: given image does not have a valid footer");
        return 9;
    }

    ulong newSize;
    if (!keepHashtree)
    {
        newSize = footer.OriginalImageSize;
    }
    else
    {
        if (footer.VBMetaOffset + footer.VBMetaSize > (ulong)imageBytes.Length)
        {
            Console.Error.WriteLine("error: footer points outside image bounds");
            return 9;
        }

        var vbmetaImage = new AvbVBMetaImage(imageBytes.AsMemory((int)footer.VBMetaOffset, (int)footer.VBMetaSize));
        var tree = vbmetaImage.GetDescriptors().OfType<AvbHashtreeDescriptor>().FirstOrDefault();
        if (tree is null)
        {
            Console.Error.WriteLine("error: requested keep_hashtree but no hashtree descriptor found");
            return 9;
        }

        newSize = tree.TreeOffset + tree.TreeSize;
        if (tree.FecOffset > 0)
        {
            var fecEnd = tree.FecOffset + tree.FecSize;
            if (fecEnd > newSize)
            {
                newSize = fecEnd;
            }
        }
    }

    if (newSize > (ulong)imageBytes.Length)
    {
        Console.Error.WriteLine("error: computed new size exceeds image bounds");
        return 9;
    }

    using var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Write, FileShare.None);
    stream.SetLength((long)newSize);
    Console.WriteLine($"footer erased, new image size: {newSize}");
    return 0;
}

static int ResizeImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath) ||
        !options.TryGetValue("--partition_size", out var partitionSizeText) ||
        !ulong.TryParse(partitionSizeText, out var partitionSize))
    {
        Console.Error.WriteLine("error: missing required options for resize_image");
        Console.Error.WriteLine("required: --image <file> --partition_size <bytes>");
        return 9;
    }

    const ulong blockSize = 4096;
    if ((partitionSize % blockSize) != 0)
    {
        Console.Error.WriteLine($"error: partition size must be multiple of {blockSize}");
        return 9;
    }

    var imageBytes = File.ReadAllBytes(imagePath);
    if (!TryGetFooter(imageBytes, out var footer))
    {
        Console.Error.WriteLine("error: given image does not have a valid footer");
        return 9;
    }

    var vbmetaEnd = footer.VBMetaOffset + footer.VBMetaSize;
    if ((vbmetaEnd % blockSize) != 0)
    {
        vbmetaEnd += blockSize - (vbmetaEnd % blockSize);
    }

    if (partitionSize < vbmetaEnd + blockSize)
    {
        Console.Error.WriteLine($"error: requested size too small, need at least {vbmetaEnd + blockSize}");
        return 9;
    }

    if (vbmetaEnd > (ulong)imageBytes.Length)
    {
        Console.Error.WriteLine("error: footer points outside image bounds");
        return 9;
    }

    var footerStart = imageBytes.Length - AvbFooter.Size;
    var footerBytes = imageBytes.AsSpan(footerStart, AvbFooter.Size).ToArray();

    using var stream = new FileStream(imagePath, FileMode.Create, FileAccess.Write, FileShare.None);
    stream.Write(imageBytes, 0, (int)vbmetaEnd);

    var dontCareLength = (long)(partitionSize - vbmetaEnd - blockSize);
    if (dontCareLength > 0)
    {
        stream.Write(new byte[dontCareLength]);
    }

    var footerBlockPadding = new byte[blockSize - AvbFooter.Size];
    stream.Write(footerBlockPadding);
    stream.Write(footerBytes);

    Console.WriteLine($"image resized: {partitionSize} bytes");
    return 0;
}

static int SetAbMetadataCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--misc_image", out var miscImage) ||
        !options.TryGetValue("--slot_data", out var slotDataText))
    {
        Console.Error.WriteLine("error: missing required options for set_ab_metadata");
        Console.Error.WriteLine("required: --misc_image <file> --slot_data A_pri:A_try:A_succ:B_pri:B_try:B_succ");
        return 9;
    }

    var tokens = slotDataText.Split(':');
    if (tokens.Length != 6 || !tokens.All(t => byte.TryParse(t, out _)))
    {
        Console.Error.WriteLine("error: malformed slot_data");
        return 9;
    }

    var aPriority = byte.Parse(tokens[0]);
    var aTries = byte.Parse(tokens[1]);
    var aSuccess = byte.Parse(tokens[2]);
    var bPriority = byte.Parse(tokens[3]);
    var bTries = byte.Parse(tokens[4]);
    var bSuccess = byte.Parse(tokens[5]);

    var abData = new AvbAbData
    {
        MagicBytes = System.Text.Encoding.ASCII.GetBytes(AvbAbData.Magic),
        VersionMajor = AvbAbData.MajorVersion,
        VersionMinor = AvbAbData.MinorVersion,
        SlotA = new AvbAbSlotData
        {
            Priority = aPriority,
            TriesRemaining = aTries,
            SuccessfulBoot = aSuccess
        },
        SlotB = new AvbAbSlotData
        {
            Priority = bPriority,
            TriesRemaining = bTries,
            SuccessfulBoot = bSuccess
        }
    };

    var payload = abData.ToBytes();
    const int metadataOffset = 2048;
    using var fs = new FileStream(miscImage, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    if (fs.Length < metadataOffset + payload.Length)
    {
        fs.SetLength(metadataOffset + payload.Length);
    }
    fs.Position = metadataOffset;
    fs.Write(payload, 0, payload.Length);

    Console.WriteLine($"A/B metadata written at offset {metadataOffset}");
    return 0;
}

static int AppendVBMetaImageCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath) ||
        !options.TryGetValue("--vbmeta_image", out var vbmetaPath) ||
        !options.TryGetValue("--partition_size", out var partitionSizeText) ||
        !ulong.TryParse(partitionSizeText, out var partitionSize))
    {
        Console.Error.WriteLine("error: missing required options for append_vbmeta_image");
        Console.Error.WriteLine("required: --image <file> --vbmeta_image <file> --partition_size <bytes>");
        return 9;
    }

    const ulong blockSize = 4096;
    if ((partitionSize % blockSize) != 0)
    {
        Console.Error.WriteLine($"error: partition size must be multiple of {blockSize}");
        return 9;
    }

    var image = File.ReadAllBytes(imagePath);
    var originalImageSize = (ulong)image.Length;
    if (TryGetFooter(image, out var existingFooter) && existingFooter.OriginalImageSize <= (ulong)image.Length)
    {
        originalImageSize = existingFooter.OriginalImageSize;
        image = image.AsSpan(0, (int)existingFooter.OriginalImageSize).ToArray();
    }

    var vbmetaBlob = LoadVbmetaBlob(vbmetaPath);
    var appendResult = AppendVBMetaImageInternal(imagePath, image, originalImageSize, vbmetaBlob, partitionSize);
    if (appendResult != 0)
    {
        return appendResult;
    }

    Console.WriteLine("vbmeta image appended");
    return 0;
}

static int ZeroHashtreeCommand(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for zero_hashtree");
        return 9;
    }

    var imageBytes = File.ReadAllBytes(imagePath);
    if (!TryGetFooter(imageBytes, out var footer))
    {
        Console.Error.WriteLine("error: given image does not have a valid footer");
        return 9;
    }

    if (footer.VBMetaOffset + footer.VBMetaSize > (ulong)imageBytes.Length)
    {
        Console.Error.WriteLine("error: footer points outside image bounds");
        return 9;
    }

    var vbmetaImage = new AvbVBMetaImage(imageBytes.AsMemory((int)footer.VBMetaOffset, (int)footer.VBMetaSize));
    var tree = vbmetaImage.GetDescriptors().OfType<AvbHashtreeDescriptor>().FirstOrDefault();
    if (tree is null)
    {
        Console.Error.WriteLine("error: no hashtree descriptor found");
        return 9;
    }

    var treeStart = (long)tree.TreeOffset;
    var treeLength = (long)tree.TreeSize;
    var fecStart = tree.FecOffset > 0 ? (long)tree.FecOffset : -1;
    var fecLength = tree.FecOffset > 0 ? (long)tree.FecSize : 0;

    if (treeStart < 0 || treeStart + treeLength > imageBytes.Length ||
        (fecStart >= 0 && fecStart + fecLength > imageBytes.Length))
    {
        Console.Error.WriteLine("error: hashtree/FEC range out of image bounds");
        return 9;
    }

    var marker = System.Text.Encoding.ASCII.GetBytes("ZeRoHaSH");

    Array.Clear(imageBytes, (int)treeStart, (int)treeLength);
    marker.CopyTo(imageBytes, (int)treeStart);

    if (fecStart >= 0)
    {
        Array.Clear(imageBytes, (int)fecStart, (int)fecLength);
        marker.CopyTo(imageBytes, (int)fecStart);
    }

    File.WriteAllBytes(imagePath, imageBytes);
    Console.WriteLine("hashtree and FEC data zeroed");
    return 0;
}

static bool TryGetFooter(ReadOnlySpan<byte> imageBytes, out AvbFooter footer)
{
    footer = default;
    if (imageBytes.Length < AvbFooter.Size)
    {
        return false;
    }

    try
    {
        footer = AvbFooter.FromBytes(imageBytes.Slice(imageBytes.Length - AvbFooter.Size, AvbFooter.Size));
        return footer.IsValid;
    }
    catch
    {
        return false;
    }
}

static int AppendVBMetaImageInternal(
    string imagePath,
    byte[] imageData,
    ulong originalImageSize,
    byte[] vbmetaBlob,
    ulong partitionSize)
{
    const ulong blockSize = 4096;
    if ((partitionSize % blockSize) != 0)
    {
        Console.Error.WriteLine($"error: partition size must be multiple of {blockSize}");
        return 9;
    }

    if (((ulong)imageData.Length % blockSize) != 0)
    {
        var padded = (int)AlignUp((ulong)imageData.Length, blockSize);
        Array.Resize(ref imageData, padded);
    }

    var vbmetaOffset = (ulong)imageData.Length;
    var vbmetaPaddedLength = (int)AlignUp((ulong)vbmetaBlob.Length, blockSize);
    var vbmetaPadded = new byte[vbmetaPaddedLength];
    vbmetaBlob.CopyTo(vbmetaPadded, 0);

    var vbmetaEndOffset = vbmetaOffset + (ulong)vbmetaPadded.Length;
    if (partitionSize < vbmetaEndOffset + blockSize)
    {
        Console.Error.WriteLine($"error: partition size too small, need at least {vbmetaEndOffset + blockSize}");
        return 9;
    }

    var footer = new AvbFooter
    {
        MagicValue = AvbFooter.MagicValueLiteral,
        VersionMajor = AvbFooter.ExpectedVersionMajor,
        VersionMinor = AvbFooter.ExpectedVersionMinor,
        OriginalImageSize = originalImageSize,
        VBMetaOffset = vbmetaOffset,
        VBMetaSize = (ulong)vbmetaBlob.Length
    };
    var footerBytes = new byte[AvbFooter.Size];
    footer.ToBytes(footerBytes);

    using var stream = new FileStream(imagePath, FileMode.Create, FileAccess.Write, FileShare.None);
    stream.Write(imageData, 0, imageData.Length);
    stream.Write(vbmetaPadded, 0, vbmetaPadded.Length);

    var dontCareLength = (long)(partitionSize - vbmetaEndOffset - blockSize);
    if (dontCareLength > 0)
    {
        stream.Write(new byte[dontCareLength]);
    }

    stream.Write(new byte[blockSize - AvbFooter.Size], 0, (int)(blockSize - AvbFooter.Size));
    stream.Write(footerBytes, 0, footerBytes.Length);
    return 0;
}

static byte[] BuildHashDescriptorBlob(
    ulong imageSize,
    string hashAlgorithm,
    string partitionName,
    ReadOnlySpan<byte> salt,
    ReadOnlySpan<byte> digest,
    uint descriptorFlags)
{
    var partitionBytes = System.Text.Encoding.UTF8.GetBytes(partitionName);
    var bodyLength = 116 + partitionBytes.Length + salt.Length + digest.Length;
    var bodyPaddedLength = (int)AlignUp((ulong)bodyLength, 8);

    var body = new byte[bodyPaddedLength];
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(0, 8), imageSize);

    var hashAlgorithmBytes = System.Text.Encoding.ASCII.GetBytes(hashAlgorithm);
    hashAlgorithmBytes.AsSpan(0, Math.Min(hashAlgorithmBytes.Length, 32)).CopyTo(body.AsSpan(8, 32));
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(40, 4), (uint)partitionBytes.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(44, 4), (uint)salt.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(48, 4), (uint)digest.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(52, 4), descriptorFlags);

    var offset = 116;
    partitionBytes.CopyTo(body.AsSpan(offset));
    offset += partitionBytes.Length;
    salt.CopyTo(body.AsSpan(offset));
    offset += salt.Length;
    digest.CopyTo(body.AsSpan(offset));

    var descriptor = new byte[16 + body.Length];
    BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hash);
    BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(8, 8), (ulong)body.Length);
    body.CopyTo(descriptor.AsSpan(16));
    return descriptor;
}

static int MakeHashtreeImageCommand(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for make_hashtree_image");
        return 9;
    }

    if (!options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required option --output for make_hashtree_image");
        return 9;
    }

    var hashAlgorithm = options.TryGetValue("--hash_algorithm", out var ha) ? ha.ToLowerInvariant() : "sha256";
    var blockSize = options.TryGetValue("--block_size", out var blockSizeText) && int.TryParse(blockSizeText, out var bs) ? bs : 4096;

    byte[] salt;
    if (options.TryGetValue("--salt", out var saltHex))
    {
        try
        {
            salt = Convert.FromHexString(saltHex);
        }
        catch
        {
            Console.Error.WriteLine("error: --salt must be valid hex");
            return 9;
        }
    }
    else
    {
        salt = new byte[32];
        RandomNumberGenerator.Fill(salt);
    }

    var image = File.ReadAllBytes(imagePath);
    byte[] rootDigest;
    var tree = AvbHashtree.Build(image, blockSize, hashAlgorithm, salt, out rootDigest);

    File.WriteAllBytes(outputPath, tree);
    Console.WriteLine(ToHexLower(rootDigest));
    return 0;
}

static int VerifyHashtreeCommand(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for verify_hashtree");
        return 9;
    }

    if (!options.TryGetValue("--hashtree", out var hashtreePath))
    {
        Console.Error.WriteLine("error: missing required option --hashtree for verify_hashtree");
        return 9;
    }

    var hashAlgorithm = options.TryGetValue("--hash_algorithm", out var ha) ? ha.ToLowerInvariant() : "sha256";
    var blockSize = options.TryGetValue("--block_size", out var blockSizeText) && int.TryParse(blockSizeText, out var bs) ? bs : 4096;

    byte[] salt;
    if (options.TryGetValue("--salt", out var saltHex))
    {
        try
        {
            salt = Convert.FromHexString(saltHex);
        }
        catch
        {
            Console.Error.WriteLine("error: --salt must be valid hex");
            return 9;
        }
    }
    else
    {
        salt = Array.Empty<byte>();
    }

    byte[] rootDigest = Array.Empty<byte>();
    if (options.TryGetValue("--root_digest", out var rootHex))
    {
        try
        {
            rootDigest = Convert.FromHexString(rootHex);
        }
        catch
        {
            Console.Error.WriteLine("error: --root_digest must be valid hex");
            return 9;
        }
    }

    var image = File.ReadAllBytes(imagePath);
    var tree = File.ReadAllBytes(hashtreePath);

    if (!AvbHashtree.Verify(image, blockSize, hashAlgorithm, salt, tree, rootDigest))
    {
        Console.Error.WriteLine("error: hashtree verification failed");
        return 9;
    }

    Console.WriteLine("hashtree verified");
    return 0;
}

static int CalcFooterSizeCommand(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--partition_size", out var partitionSizeText) || !ulong.TryParse(partitionSizeText, out var partitionSize))
    {
        Console.Error.WriteLine("error: missing or invalid --partition_size for calc_footer_size");
        return 9;
    }

    var vbmetaSize = options.TryGetValue("--vbmeta_size", out var vbmetaSizeText) && ulong.TryParse(vbmetaSizeText, out var vs)
        ? vs
        : AvbVBMetaImageHeader.Size;

    // Footer region reserved by add_hashtree_footer: the vbmeta block padded
    // to the block size plus one block holding the 64-byte AVB footer.
    const ulong blockSize = 4096;
    var footerSize = AlignUp(vbmetaSize, blockSize) + blockSize;
    Console.WriteLine(footerSize);
    return 0;
}

static int FecEncodeCommand(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--image", out var imagePath))
    {
        Console.Error.WriteLine("error: missing required option --image for fec encode");
        return 9;
    }

    if (!options.TryGetValue("--output", out var outputPath))
    {
        Console.Error.WriteLine("error: missing required option --output for fec encode");
        return 9;
    }

    var roots = options.TryGetValue("--roots", out var rootsText) && int.TryParse(rootsText, out var r) ? r : AvbFec.DefaultRoots;
    var image = File.ReadAllBytes(imagePath);
    var parity = AvbFec.ComputeParity(image, roots);
    File.WriteAllBytes(outputPath, parity);
    Console.WriteLine(parity.Length);
    return 0;
}

static int FecCalcSizeCommand(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--data_size", out var sizeText) || !ulong.TryParse(sizeText, out var dataSize))
    {
        Console.Error.WriteLine("error: missing or invalid --data_size for fec calc-size");
        return 9;
    }

    var roots = options.TryGetValue("--roots", out var rootsText) && int.TryParse(rootsText, out var r) ? r : AvbFec.DefaultRoots;
    Console.WriteLine(AvbFec.CalculateEccSize(dataSize, roots));
    return 0;
}

static byte[] BuildHashtreeDescriptorBlob(
    ulong imageSize,
    string hashAlgorithm,
    string partitionName,
    ReadOnlySpan<byte> salt,
    ReadOnlySpan<byte> rootDigest,
    int blockSize,
    ulong treeOffset,
    ulong treeSize,
    uint fecNumRoots,
    ulong fecOffset,
    ulong fecSize,
    uint descriptorFlags)
{
    var partitionBytes = System.Text.Encoding.UTF8.GetBytes(partitionName);
    var bodyLength = 164 + partitionBytes.Length + salt.Length + rootDigest.Length;
    var bodyPaddedLength = (int)AlignUp((ulong)bodyLength, 8);

    var body = new byte[bodyPaddedLength];
    // Matches the on-disk AvbHashtreeDescriptor layout (avb_hashtree_descriptor.h):
    // dm_verity_version, image_size, tree_offset, tree_size, data/hash block
    // sizes, fec fields, hash_algorithm[32], lengths, flags, reserved[60].
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(0, 4), 1); // dm_verity_version
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(4, 8), imageSize);
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(12, 8), treeOffset);
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(20, 8), treeSize);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(28, 4), (uint)blockSize); // data_block_size
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(32, 4), (uint)blockSize); // hash_block_size
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(36, 4), fecNumRoots);
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(40, 8), fecOffset);
    BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(48, 8), fecSize);

    var hashAlgorithmBytes = System.Text.Encoding.ASCII.GetBytes(hashAlgorithm);
    hashAlgorithmBytes.AsSpan(0, Math.Min(hashAlgorithmBytes.Length, 32)).CopyTo(body.AsSpan(56, 32));
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(88, 4), (uint)partitionBytes.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(92, 4), (uint)salt.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(96, 4), (uint)rootDigest.Length);
    BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(100, 4), descriptorFlags);
    // body[104..164) is reserved[60], left as zero.

    var offset = 164;
    partitionBytes.CopyTo(body.AsSpan(offset));
    offset += partitionBytes.Length;
    salt.CopyTo(body.AsSpan(offset));
    offset += salt.Length;
    rootDigest.CopyTo(body.AsSpan(offset));

    var descriptor = new byte[16 + body.Length];
    BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(0, 8), (ulong)AvbDescriptorTag.Hashtree);
    BinaryPrimitives.WriteUInt64BigEndian(descriptor.AsSpan(8, 8), (ulong)body.Length);
    body.CopyTo(descriptor.AsSpan(16));
    return descriptor;
}

static byte[] GenerateHashTree(byte[] image, int blockSize, string hashAlgorithm, ReadOnlySpan<byte> salt, out byte[] rootDigest)
{
    // Real dm-verity Merkle tree generation (avbtool generate_hash_tree port).
    return AvbHashtree.Build(image, blockSize, hashAlgorithm, salt, out rootDigest);
}

static int AppendHashtreeAndVBMetaInternal(
    string imagePath,
    byte[] imageData,
    byte[] hashtree,
    byte[] fecData,
    ulong originalImageSize,
    byte[] vbmetaBlob,
    ulong partitionSize)
{
    const ulong blockSize = 4096;
    if ((partitionSize % blockSize) != 0)
    {
        Console.Error.WriteLine($"error: partition size must be multiple of {blockSize}");
        return 9;
    }

    if (((ulong)imageData.Length % blockSize) != 0)
    {
        var padded = (int)AlignUp((ulong)imageData.Length, blockSize);
        Array.Resize(ref imageData, padded);
    }

    if (((ulong)hashtree.Length % blockSize) != 0)
    {
        var padded = (int)AlignUp((ulong)hashtree.Length, blockSize);
        Array.Resize(ref hashtree, padded);
    }

    var vbmetaOffset = (ulong)(imageData.Length + hashtree.Length + fecData.Length);
    var vbmetaPaddedLength = (int)AlignUp((ulong)vbmetaBlob.Length, blockSize);
    var vbmetaPadded = new byte[vbmetaPaddedLength];
    vbmetaBlob.CopyTo(vbmetaPadded, 0);

    var vbmetaEndOffset = vbmetaOffset + (ulong)vbmetaPadded.Length;
    if (partitionSize < vbmetaEndOffset + blockSize)
    {
        Console.Error.WriteLine($"error: partition size too small, need at least {vbmetaEndOffset + blockSize}");
        return 9;
    }

    var footer = new AvbFooter
    {
        MagicValue = AvbFooter.MagicValueLiteral,
        VersionMajor = AvbFooter.ExpectedVersionMajor,
        VersionMinor = AvbFooter.ExpectedVersionMinor,
        OriginalImageSize = originalImageSize,
        VBMetaOffset = vbmetaOffset,
        VBMetaSize = (ulong)vbmetaBlob.Length
    };
    var footerBytes = new byte[AvbFooter.Size];
    footer.ToBytes(footerBytes);

    using var stream = new FileStream(imagePath, FileMode.Create, FileAccess.Write, FileShare.None);
    stream.Write(imageData, 0, imageData.Length);
    stream.Write(hashtree, 0, hashtree.Length);
    if (fecData.Length > 0)
    {
        stream.Write(fecData, 0, fecData.Length);
    }

    stream.Write(vbmetaPadded, 0, vbmetaPadded.Length);

    var dontCareLength = (long)(partitionSize - vbmetaEndOffset - blockSize);
    if (dontCareLength > 0)
    {
        stream.Write(new byte[dontCareLength]);
    }

    stream.Write(new byte[blockSize - AvbFooter.Size], 0, (int)(blockSize - AvbFooter.Size));
    stream.Write(footerBytes, 0, footerBytes.Length);
    return 0;
}

static byte[] BuildVBMetaBlob(
    ReadOnlySpan<byte> descriptors,
    uint algorithmType,
    ulong rollbackIndex,
    uint flags,
    uint rollbackIndexLocation,
    string releaseString,
    string? keyPath = null,
    string? signingHelper = null,
    string? signingHelperWithFiles = null)
{
    var authBlock = Array.Empty<byte>();
    var auxSize = (int)AlignUp((ulong)descriptors.Length, 64);
    var auxBlock = new byte[auxSize];
    descriptors.CopyTo(auxBlock);

    var header = new byte[AvbVBMetaImageHeader.Size];
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), 0x30425641);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), AvbVersion.Major);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), AvbVersion.Minor);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(12, 8), (ulong)authBlock.Length);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(20, 8), (ulong)auxBlock.Length);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(28, 4), algorithmType);

    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(32, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(40, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(48, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(56, 8), 0UL);

    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(64, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(72, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(80, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(88, 8), 0UL);

    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(96, 8), 0UL);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(104, 8), (ulong)descriptors.Length);
    BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(112, 8), rollbackIndex);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(120, 4), flags);
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(124, 4), rollbackIndexLocation);

    var releaseBytes = System.Text.Encoding.ASCII.GetBytes(releaseString);
    var releaseLength = Math.Min(releaseBytes.Length, AvbVBMetaImageHeader.ReleaseStringSize - 1);
    releaseBytes.AsSpan(0, releaseLength).CopyTo(header.AsSpan(128, releaseLength));
    header[128 + releaseLength] = 0;

    if (algorithmType != (uint)AvbAlgorithmType.None && keyPath != null)
    {
        var algorithm = (AvbAlgorithmType)algorithmType;
        var dataToSign = header.Concat(auxBlock).ToArray();
        var signature = AvbCrypto.SignData(keyPath, algorithm, dataToSign, signingHelper, signingHelperWithFiles);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(keyPath));
        var publicKey = rsa.ExportParameters(false);
        var encodedPublicKey = AvbCrypto.EncodeRSAPublicKey(publicKey);

        var hash = AvbCrypto.CalculateHash(algorithm, dataToSign);
        authBlock = new byte[hash.Length + signature.Length + encodedPublicKey.Length];
        hash.CopyTo(authBlock, 0);
        signature.CopyTo(authBlock, hash.Length);
        encodedPublicKey.CopyTo(authBlock, hash.Length + signature.Length);

        // Update header with auth block size and offsets
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(12, 8), (ulong)authBlock.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(32, 8), (ulong)hash.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(40, 8), (ulong)hash.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(48, 8), (ulong)signature.Length);
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(56, 8), (ulong)(hash.Length + signature.Length));
        BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(64, 8), (ulong)encodedPublicKey.Length);
    }

    var output = new byte[header.Length + authBlock.Length + auxBlock.Length];
    header.CopyTo(output.AsSpan(0));
    authBlock.CopyTo(output.AsSpan(header.Length));
    auxBlock.CopyTo(output.AsSpan(header.Length + authBlock.Length));
    return output;
}

static ulong AlignUp(ulong value, ulong alignment)
{
    if (alignment == 0)
    {
        return value;
    }

    var remainder = value % alignment;
    return remainder == 0 ? value : value + alignment - remainder;
}

static byte[] PadToMultiple(byte[] data, int multiple)
{
    if (multiple <= 0)
    {
        return data;
    }

    var paddedSize = (int)AlignUp((ulong)data.Length, (ulong)multiple);
    if (paddedSize == data.Length)
    {
        return data;
    }

    var output = new byte[paddedSize];
    data.CopyTo(output, 0);
    return output;
}

static void CollectPartitionDigests(string path, HashSet<string> seen, List<(string PartitionName, string Digest)> entries)
{
    var normalizedPath = Path.GetFullPath(path);
    if (!seen.Add(normalizedPath))
    {
        return;
    }

    var image = LoadVbmetaImage(normalizedPath, out var resolvedPath);
    var imageDir = Path.GetDirectoryName(resolvedPath) ?? string.Empty;
    var imageExt = Path.GetExtension(resolvedPath);

    foreach (var descriptor in image.GetDescriptors())
    {
        switch (descriptor)
        {
            case AvbHashDescriptor hash:
                entries.Add((hash.PartitionName, ToHexLower(hash.Digest)));
                break;
            case AvbHashtreeDescriptor tree:
                entries.Add((tree.PartitionName, ToHexLower(tree.RootDigest)));
                break;
            case AvbChainPartitionDescriptor chain:
                {
                    var childPath = ResolveChainedPartitionPath(imageDir, imageExt, chain.PartitionName);
                    if (File.Exists(childPath))
                    {
                        CollectPartitionDigests(childPath, seen, entries);
                    }
                    break;
                }
        }
    }
}

static AvbVBMetaImage LoadVbmetaImage(string path, out string resolvedPath)
{
    var bytes = File.ReadAllBytes(path);
    resolvedPath = path;

    if (bytes.Length >= AvbFooter.Size)
    {
        try
        {
            var footer = AvbFooter.FromBytes(bytes.AsSpan(bytes.Length - AvbFooter.Size, AvbFooter.Size));
            if (footer.IsValid && footer.VBMetaOffset <= (ulong)bytes.Length && footer.VBMetaSize > 0 && footer.VBMetaOffset + footer.VBMetaSize <= (ulong)bytes.Length)
            {
                return new AvbVBMetaImage(bytes.AsMemory((int)footer.VBMetaOffset, (int)footer.VBMetaSize));
            }
        }
        catch
        {
            // Treat as a plain vbmeta image if footer parsing fails.
        }
    }

    return new AvbVBMetaImage(bytes);
}

static byte[] LoadVbmetaBlob(string path)
{
    var bytes = File.ReadAllBytes(path);
    if (bytes.Length >= AvbFooter.Size && TryGetFooter(bytes, out var footer))
    {
        if (footer.VBMetaOffset + footer.VBMetaSize <= (ulong)bytes.Length)
        {
            return bytes.AsSpan((int)footer.VBMetaOffset, (int)footer.VBMetaSize).ToArray();
        }
    }

    return bytes;
}

static string ResolveChainedPartitionPath(string directory, string extension, string partitionName)
{
    var childName = string.IsNullOrEmpty(extension) ? partitionName : partitionName + extension;
    return string.IsNullOrEmpty(directory) ? childName : Path.Combine(directory, childName);
}

static int InspectAb(string path)
{
    var bytes = File.ReadAllBytes(path);
    if (bytes.Length < AvbAbData.Size)
    {
        Console.Error.WriteLine($"error: file must be at least {AvbAbData.Size} bytes");
        return 4;
    }

    var data = AvbAbData.FromBytes(bytes.AsSpan(0, AvbAbData.Size));

    Console.WriteLine($"file: {path}");
    Console.WriteLine($"magic: {System.Text.Encoding.ASCII.GetString(data.MagicBytes ?? [])}");
    Console.WriteLine($"version: {data.VersionMajor}.{data.VersionMinor}");
    Console.WriteLine($"slot_a: priority={data.SlotA.Priority}, tries={data.SlotA.TriesRemaining}, successful={data.SlotA.SuccessfulBoot}");
    Console.WriteLine($"slot_b: priority={data.SlotB.Priority}, tries={data.SlotB.TriesRemaining}, successful={data.SlotB.SuccessfulBoot}");
    Console.WriteLine($"crc32_be: 0x{data.Crc32:x8}");

    var first28 = bytes.AsSpan(0, 28);
    var computed = AvbCrc32.Compute(first28);
    var stored = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(28, 4));
    Console.WriteLine($"crc32_ok: {computed == stored}");

    return 0;
}

static int MakeUnlockCredential(string[] args)
{
    var options = ParseOptions(args);

    if (!options.TryGetValue("--pik-cert", out var pikPath) ||
        !options.TryGetValue("--puk-cert", out var pukCertPath) ||
        !options.TryGetValue("--puk-key", out var pukKeyPath) ||
        !options.TryGetValue("--challenge", out var challengePath) ||
        !options.TryGetValue("--out", out var outPath))
    {
        Console.Error.WriteLine("error: missing required options for cert make-unlock-credential");
        Console.Error.WriteLine("required: --pik-cert <file> --puk-cert <file> --puk-key <pem> --challenge <file> --out <file>");
        return 5;
    }

    var pikCert = File.ReadAllBytes(pikPath);
    var pukCert = File.ReadAllBytes(pukCertPath);
    var challenge = AvbCertUnlockChallenge.FromBytes(File.ReadAllBytes(challengePath));
    var pukPem = File.ReadAllText(pukKeyPath);

    var output = BuildUnlockCredentialBinary(pikCert, pukCert, pukPem, challenge);
    File.WriteAllBytes(outPath, output);
    Console.WriteLine($"unlock credential written: {outPath}");
    return 0;
}

static int MakeUnlockCredentialFromArchive(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--archive", out var archivePath) ||
        !options.TryGetValue("--challenge", out var challengePath) ||
        !options.TryGetValue("--out", out var outPath))
    {
        Console.Error.WriteLine("error: missing required options for cert make-unlock-credential-from-archive");
        Console.Error.WriteLine("required: --archive <zip> --challenge <file> --out <file>");
        return 5;
    }

    var challenge = AvbCertUnlockChallenge.FromBytes(File.ReadAllBytes(challengePath));
    ValidateChallenge(challenge);
    var challengeProductIdHash = challenge.ProductIdHash;

    if (!TryReadCredentialArchive(archivePath, out var pikCert, out var pukCert, out var pukPem, out var parseError))
    {
        Console.Error.WriteLine($"error: invalid credential archive: {parseError}");
        return 6;
    }

    var pukSubjectProductHash = GetPukSubjectHash(pukCert);
    if (!CryptographicOperations.FixedTimeEquals(pukSubjectProductHash, challengeProductIdHash))
    {
        Console.Error.WriteLine("error: archive PUK certificate does not match challenge product_id_hash");
        return 6;
    }

    var output = BuildUnlockCredentialBinary(pikCert, pukCert, pukPem, challenge);
    File.WriteAllBytes(outPath, output);
    Console.WriteLine($"unlock credential written from archive: {outPath}");
    return 0;
}

static int MakeUnlockCredentialAuto(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--challenge", out var challengePath) ||
        !options.TryGetValue("--out", out var outPath))
    {
        Console.Error.WriteLine("error: missing required options for cert make-unlock-credential-auto");
        Console.Error.WriteLine("required: --challenge <file> --out <file> <archive_or_directory> [more_paths...]");
        return 5;
    }

    var searchPaths = ExtractNonOptionArgs(args);
    if (searchPaths.Count == 0)
    {
        Console.Error.WriteLine("error: at least one archive or directory path must be provided");
        return 5;
    }

    var challenge = AvbCertUnlockChallenge.FromBytes(File.ReadAllBytes(challengePath));
    ValidateChallenge(challenge);

    if (!TryBuildUnlockCredentialFromSearchPaths(challenge, searchPaths, out var credential, out var matchedArchive))
    {
        Console.Error.WriteLine("error: no matching unlock credential archive found for challenge product_id_hash");
        return 6;
    }

    File.WriteAllBytes(outPath, credential);
    Console.WriteLine($"unlock credential written from matching archive: {outPath}");
    Console.WriteLine($"matched_archive: {matchedArchive}");
    return 0;
}

static int RunAuthenticatedUnlock(string[] args)
{
    var options = ParseOptions(args);
    var flags = ParseFlags(args);
    var searchPaths = ExtractNonOptionArgs(args);
    if (searchPaths.Count == 0)
    {
        Console.Error.WriteLine("error: at least one archive or directory path must be provided");
        return 5;
    }

    options.TryGetValue("--serial", out var serial);
    var clearFactoryDigest = !flags.Contains("--no-clear-factory-digest");

    using var tempDir = new TempDirectory();
    var challengePath = Path.Combine(tempDir.Path, "challenge.bin");
    var credentialPath = Path.Combine(tempDir.Path, "unlock_credential.bin");
    var clearDigestPath = Path.Combine(tempDir.Path, "factory_clear_digest.bin");

    RunFastboot(serial, "oem", "at-get-vboot-unlock-challenge");
    RunFastboot(serial, "get_staged", challengePath);

    var challenge = AvbCertUnlockChallenge.FromBytes(File.ReadAllBytes(challengePath));
    ValidateChallenge(challenge);
    Console.WriteLine($"product_id_hash: {ToHexLower(challenge.ProductIdHash)}");

    if (!TryBuildUnlockCredentialFromSearchPaths(challenge, searchPaths, out var credential, out var matchedArchive))
    {
        Console.Error.WriteLine("error: no matching unlock credential archive found for challenge product_id_hash");
        return 6;
    }

    File.WriteAllBytes(credentialPath, credential);
    Console.WriteLine($"matched_archive: {matchedArchive}");

    RunFastboot(serial, "stage", credentialPath);
    RunFastboot(serial, "oem", "at-unlock-vboot");

    var stateOutput = RunFastboot(serial, "getvar", "at-vboot-state");
    if (!stateOutput.Contains("avb-locked: 0", StringComparison.OrdinalIgnoreCase) &&
        !stateOutput.Contains("avb-locked=0", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("error: unlock command succeeded but device still appears locked");
        return 8;
    }

    if (clearFactoryDigest)
    {
        var clearDigestPayload = BuildPersistentDigestBinary("avb.persistent_digest.factory", []);
        File.WriteAllBytes(clearDigestPath, clearDigestPayload);
        RunFastboot(serial, "stage", clearDigestPath);
        RunFastboot(serial, "oem", "at-write-persistent-digest");
        Console.WriteLine("factory persistent digest cleared");
    }

    Console.WriteLine("authenticated unlock flow completed");
    return 0;
}

static bool TryBuildUnlockCredentialFromSearchPaths(
    AvbCertUnlockChallenge challenge,
    List<string> searchPaths,
    out byte[] credential,
    out string matchedArchive)
{
    credential = [];
    matchedArchive = string.Empty;

    var archiveCandidates = new List<string>();
    foreach (var input in searchPaths)
    {
        if (File.Exists(input))
        {
            archiveCandidates.Add(input);
            continue;
        }

        if (Directory.Exists(input))
        {
            archiveCandidates.AddRange(Directory.GetFiles(input));
            continue;
        }

        Console.Error.WriteLine($"warning: path not found, skipped: {input}");
    }

    foreach (var archivePath in archiveCandidates)
    {
        if (!TryReadCredentialArchive(archivePath, out var pikCert, out var pukCert, out var pukPem, out _))
        {
            continue;
        }

        if (!CryptographicOperations.FixedTimeEquals(GetPukSubjectHash(pukCert), challenge.ProductIdHash))
        {
            continue;
        }

        credential = BuildUnlockCredentialBinary(pikCert, pukCert, pukPem, challenge);
        matchedArchive = archivePath;
        return true;
    }

    return false;
}

static string RunFastboot(string? serial, params string[] commandArgs)
{
    var args = new List<string>();
    if (!string.IsNullOrWhiteSpace(serial))
    {
        args.Add("-s");
        args.Add(serial);
    }

    args.AddRange(commandArgs);

    var psi = new ProcessStartInfo
    {
        FileName = "fastboot",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    foreach (var arg in args)
    {
        psi.ArgumentList.Add(arg);
    }

    using var process = Process.Start(psi) ?? throw new InvalidOperationException("failed to start fastboot process");
    var stdOut = process.StandardOutput.ReadToEnd();
    var stdErr = process.StandardError.ReadToEnd();
    process.WaitForExit();

    var combined = string.Concat(stdOut, stdErr);
    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException($"fastboot failed ({string.Join(' ', args)}): {combined.Trim()}");
    }

    return combined;
}

static int InspectChallenge(string path)
{
    var challenge = AvbCertUnlockChallenge.FromBytes(File.ReadAllBytes(path));

    Console.WriteLine($"file: {path}");
    Console.WriteLine($"version: {challenge.Version}");
    Console.WriteLine($"product_id_hash: {ToHexLower(challenge.ProductIdHash)}");
    Console.WriteLine($"challenge_data: {ToHexLower(challenge.Challenge)}");
    return 0;
}

static int BuildPersistentDigestInput(string[] args)
{
    const string prefix = "avb.persistent_digest.";

    var options = ParseOptions(args);
    var flags = ParseFlags(args);

    if (!options.TryGetValue("--name", out var name) ||
        !options.TryGetValue("--out", out var outPath))
    {
        Console.Error.WriteLine("error: missing required options for persistent-digest build");
        Console.Error.WriteLine("required: --name <name> --out <file>");
        Console.Error.WriteLine("and one of: --digest-hex <hex> or --clear-digest");
        return 7;
    }

    var hasDigestHex = options.TryGetValue("--digest-hex", out var digestHex);
    var clearDigest = flags.Contains("--clear-digest") || flags.Contains("--clear_digest");

    if (hasDigestHex == clearDigest)
    {
        Console.Error.WriteLine("error: specify exactly one of --digest-hex or --clear-digest");
        return 7;
    }

    if (!name.StartsWith(prefix, StringComparison.Ordinal))
    {
        name = prefix + name;
        Console.WriteLine($"name normalized: {name}");
    }

    var nameBytes = System.Text.Encoding.UTF8.GetBytes(name);
    byte[] digestBytes;

    if (clearDigest)
    {
        digestBytes = [];
    }
    else
    {
        if (string.IsNullOrWhiteSpace(digestHex))
        {
            Console.Error.WriteLine("error: --digest-hex must not be empty");
            return 7;
        }

        try
        {
            digestBytes = Convert.FromHexString(digestHex);
        }
        catch (FormatException)
        {
            Console.Error.WriteLine("error: --digest-hex must be valid hex");
            return 7;
        }
    }

    var output = new byte[4 + nameBytes.Length + 4 + digestBytes.Length];
    var offset = 0;

    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(offset, 4), (uint)nameBytes.Length);
    offset += 4;
    nameBytes.CopyTo(output.AsSpan(offset, nameBytes.Length));
    offset += nameBytes.Length;
    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(offset, 4), (uint)digestBytes.Length);
    offset += 4;
    digestBytes.CopyTo(output.AsSpan(offset, digestBytes.Length));

    File.WriteAllBytes(outPath, output);
    Console.WriteLine($"persistent digest input written: {outPath}");
    Console.WriteLine($"name: {name}");
    Console.WriteLine($"digest_size: {digestBytes.Length}");

    return 0;
}

static int BuildClearFactoryPersistentDigestInput(string[] args)
{
    var options = ParseOptions(args);
    if (!options.TryGetValue("--out", out var outPath))
    {
        Console.Error.WriteLine("error: missing required option for persistent-digest build-clear-factory");
        Console.Error.WriteLine("required: --out <file>");
        return 7;
    }

    var output = BuildPersistentDigestBinary("avb.persistent_digest.factory", []);
    File.WriteAllBytes(outPath, output);
    Console.WriteLine($"factory clear digest input written: {outPath}");
    return 0;
}

static int InspectPersistentDigestInput(string path)
{
    var bytes = File.ReadAllBytes(path);
    if (bytes.Length < 8)
    {
        Console.Error.WriteLine("error: persistent digest payload too short");
        return 7;
    }

    var offset = 0;
    var nameLen = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    offset += 4;

    if (nameLen > int.MaxValue || bytes.Length < offset + (int)nameLen + 4)
    {
        Console.Error.WriteLine("error: invalid name length in payload");
        return 7;
    }

    var name = System.Text.Encoding.UTF8.GetString(bytes, offset, (int)nameLen);
    offset += (int)nameLen;

    var digestLen = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    offset += 4;

    if (digestLen > int.MaxValue || bytes.Length != offset + (int)digestLen)
    {
        Console.Error.WriteLine("error: invalid digest length in payload");
        return 7;
    }

    var digest = bytes.AsSpan(offset, (int)digestLen);
    Console.WriteLine($"file: {path}");
    Console.WriteLine($"name: {name}");
    Console.WriteLine($"digest_size: {digestLen}");
    Console.WriteLine($"digest_hex: {ToHexLower(digest)}");
    return 0;
}

static byte[] BuildPersistentDigestBinary(string name, byte[] digestBytes)
{
    var nameBytes = System.Text.Encoding.UTF8.GetBytes(name);
    var output = new byte[4 + nameBytes.Length + 4 + digestBytes.Length];
    var offset = 0;

    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(offset, 4), (uint)nameBytes.Length);
    offset += 4;
    nameBytes.CopyTo(output.AsSpan(offset, nameBytes.Length));
    offset += nameBytes.Length;
    BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(offset, 4), (uint)digestBytes.Length);
    offset += 4;
    digestBytes.CopyTo(output.AsSpan(offset, digestBytes.Length));

    return output;
}

static int InspectCredentialArchive(string path)
{
    if (!TryReadCredentialArchive(path, out var pikCert, out var pukCert, out var _, out var error))
    {
        Console.Error.WriteLine($"error: invalid credential archive: {error}");
        return 6;
    }

    var productHash = GetPukSubjectHash(pukCert);
    Console.WriteLine($"archive: {path}");
    Console.WriteLine($"pik_cert_size: {pikCert.Length}");
    Console.WriteLine($"puk_cert_size: {pukCert.Length}");
    Console.WriteLine($"product_id_hash_from_puk_subject: {ToHexLower(productHash)}");
    return 0;
}

static void PrintHelp()
{
    Console.WriteLine("FirmwareKit.AVB CLI");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  version");
    Console.WriteLine("  generate_test_image --image_size <bytes> [--start_byte <n>] [--output <file>]");
    Console.WriteLine("  extract_public_key --key <pem> --output <pubkey.bin>");
    Console.WriteLine("  extract_public_key_digest --key <pem> --output <digest.txt>");
    Console.WriteLine("  make_vbmeta_image --output <vbmeta.img> [--algorithm NONE] [--padding_size <n>]");
    Console.WriteLine("  add_hash_footer --image <image> --partition_size <bytes> --partition_name <name> [--hash_algorithm sha256|sha512]");
    Console.WriteLine("  add_hashtree_footer --image <image> --partition_size <bytes> --partition_name <name> [--hash_algorithm sha1|sha256|sha512] [--block_size <n>] [--salt <hex>] [--algorithm NONE|sha256-rsa2048|...] [--key <pem>] [--do_not_generate_fec] [--fec_num_roots <n>]");
    Console.WriteLine("  make_hashtree_image --image <image> --output <tree_file> [--hash_algorithm sha1|sha256|sha512] [--block_size <n>] [--salt <hex>]");
    Console.WriteLine("  verify_hashtree --image <image> --hashtree <tree_file> [--hash_algorithm sha1|sha256|sha512] [--block_size <n>] [--salt <hex>] [--root_digest <hex>]");
    Console.WriteLine("  calc_footer_size --partition_size <bytes> [--vbmeta_size <bytes>]");
    Console.WriteLine("  fec encode --image <file> --output <ecc> [--roots <n>]");
    Console.WriteLine("  fec calc-size --data_size <bytes> [--roots <n>]");
    Console.WriteLine("  vbmeta verify <image_path>");
    Console.WriteLine("  vbmeta info <image_path>");
    Console.WriteLine("  vbmeta digest <image_path> [--sha512]");
    Console.WriteLine("  calculate_vbmeta_digest --image <image_path> [--hash_algorithm sha256|sha512]");
    Console.WriteLine("  print_partition_digests --image <image_path> [--output json]");
    Console.WriteLine("  info_image --image <image_path> [--output <txt_file>]");
    Console.WriteLine("  verify_image --image <image_path>");
    Console.WriteLine("  extract_vbmeta_image --image <image_with_footer> --output <vbmeta_out> [--padding_size <n>]");
    Console.WriteLine("  erase_footer --image <image_with_footer> [--keep_hashtree]");
    Console.WriteLine("  resize_image --image <image_with_footer> --partition_size <bytes>");
    Console.WriteLine("  set_ab_metadata --misc_image <misc.img> --slot_data A_pri:A_try:A_succ:B_pri:B_try:B_succ");
    Console.WriteLine("  append_vbmeta_image --image <image> --vbmeta_image <vbmeta.img> --partition_size <bytes>");
    Console.WriteLine("  zero_hashtree --image <image_with_footer>");
    Console.WriteLine("  ab inspect <ab_metadata_file>");
    Console.WriteLine("  cert inspect-challenge <challenge_file>");
    Console.WriteLine("  cert inspect-archive <zip>");
    Console.WriteLine("  cert make-unlock-credential --pik-cert <file> --puk-cert <file> --puk-key <pem> --challenge <file> --out <file>");
    Console.WriteLine("  cert make-unlock-credential-from-archive --archive <zip> --challenge <file> --out <file>");
    Console.WriteLine("  cert make-unlock-credential-auto --challenge <file> --out <file> <archive_or_directory> [more_paths...]");
    Console.WriteLine("  persistent-digest build --name <name> --digest-hex <hex> --out <file>");
    Console.WriteLine("  persistent-digest build --name <name> --clear-digest --out <file>");
    Console.WriteLine("  persistent-digest build-clear-factory --out <file>");
    Console.WriteLine("  persistent-digest inspect <payload_file>");
    Console.WriteLine("  auth-unlock run [--serial <id>] [--no-clear-factory-digest] <archive_or_directory> [more_paths...]");
}

static byte[] BuildUnlockCredentialBinary(byte[] pikCert, byte[] pukCert, string pukPem, AvbCertUnlockChallenge challenge)
{
    if (pikCert.Length != AvbCertCertificate.Size)
    {
        throw new InvalidOperationException($"invalid PIK cert length, expected {AvbCertCertificate.Size}");
    }

    if (pukCert.Length != AvbCertCertificate.Size)
    {
        throw new InvalidOperationException($"invalid PUK cert length, expected {AvbCertCertificate.Size}");
    }

    ValidateChallenge(challenge);

    var challengeHash = SHA512.HashData(challenge.Challenge);

    using var rsa = RSA.Create();
    rsa.ImportFromPem(pukPem);

    var signature = rsa.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
    if (signature.Length != AvbCertConstants.Rsa4096SignatureSize)
    {
        throw new InvalidOperationException("unlock key must be RSA-4096 private key");
    }

    var credential = new AvbCertUnlockCredential
    {
        Version = 1,
        ProductIntermediateKeyCertificate = AvbCertCertificate.FromBytes(pikCert),
        ProductUnlockKeyCertificate = AvbCertCertificate.FromBytes(pukCert),
        ChallengeSignature = signature
    };

    return credential.ToBytes();
}

static void ValidateChallenge(AvbCertUnlockChallenge challenge)
{
    if (challenge.Version != 1)
    {
        throw new InvalidOperationException($"unsupported challenge version {challenge.Version}");
    }

    if (challenge.ProductIdHash.Length != AvbCertConstants.Digest256Size)
    {
        throw new InvalidOperationException("invalid product_id_hash length in challenge");
    }

    if (challenge.Challenge.Length != AvbCertConstants.UnlockChallengeSize)
    {
        throw new InvalidOperationException("invalid challenge data length");
    }
}

static byte[] ReadAllBytes(ZipArchiveEntry entry)
{
    using var stream = entry.Open();
    using var memory = new MemoryStream();
    stream.CopyTo(memory);
    return memory.ToArray();
}

static string ReadAllText(ZipArchiveEntry entry)
{
    using var stream = entry.Open();
    using var reader = new StreamReader(stream);
    return reader.ReadToEnd();
}

static bool TryReadCredentialArchive(
    string archivePath,
    out byte[] pikCert,
    out byte[] pukCert,
    out string pukPem,
    out string error)
{
    pikCert = [];
    pukCert = [];
    pukPem = string.Empty;
    error = string.Empty;

    try
    {
        using var zipFile = File.OpenRead(archivePath);
        using var zip = new ZipArchive(zipFile, ZipArchiveMode.Read, leaveOpen: false);

        var pikEntries = zip.Entries.Where(e => CredentialArchivePatterns.PikRegex.IsMatch(Path.GetFileName(e.FullName))).ToList();
        var pukCertEntries = zip.Entries.Where(e => CredentialArchivePatterns.PukCertRegex.IsMatch(Path.GetFileName(e.FullName))).ToList();
        var pukKeyEntries = zip.Entries.Where(e => CredentialArchivePatterns.PukKeyRegex.IsMatch(Path.GetFileName(e.FullName))).ToList();

        if (pikEntries.Count != 1 || pukCertEntries.Count != 1 || pukKeyEntries.Count != 1)
        {
            error = "archive must contain exactly one PIK cert, one PUK cert, and one PUK PEM key";
            return false;
        }

        pikCert = ReadAllBytes(pikEntries[0]);
        pukCert = ReadAllBytes(pukCertEntries[0]);
        pukPem = ReadAllText(pukKeyEntries[0]);

        if (pikCert.Length != AvbCertCertificate.Size)
        {
            error = $"invalid PIK cert length, expected {AvbCertCertificate.Size}";
            return false;
        }

        if (pukCert.Length != AvbCertCertificate.Size)
        {
            error = $"invalid PUK cert length, expected {AvbCertCertificate.Size}";
            return false;
        }

        return true;
    }
    catch (Exception ex)
    {
        error = ex.Message;
        return false;
    }
}

static ReadOnlySpan<byte> GetPukSubjectHash(ReadOnlySpan<byte> pukCert)
{
    var subjectOffset = 4 + 1032;
    var subjectLength = AvbCertConstants.Digest256Size;
    return pukCert.Slice(subjectOffset, subjectLength);
}

static List<string> ExtractNonOptionArgs(string[] args)
{
    var list = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        var current = args[i];
        if (!current.StartsWith("--", StringComparison.Ordinal))
        {
            list.Add(current);
            continue;
        }

        if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            i++;
        }
    }
    return list;
}

static Dictionary<string, string> ParseOptions(string[] args)
{
    var map = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i++)
    {
        var key = args[i];
        if (!key.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        if (i + 1 >= args.Length)
        {
            break;
        }

        map[key] = args[i + 1];
        i++;
    }

    return map;
}

static HashSet<string> ParseFlags(string[] args)
{
    var flags = new HashSet<string>(StringComparer.Ordinal);
    for (var i = 0; i < args.Length; i++)
    {
        var key = args[i];
        if (!key.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            i++;
            continue;
        }

        flags.Add(key);
    }

    return flags;
}

static string ToHexLower(ReadOnlySpan<byte> data)
{
#if NET5_0_OR_GREATER
    return Convert.ToHexString(data).ToLowerInvariant();
#else
    var chars = new char[data.Length * 2];
    const string alphabet = "0123456789abcdef";
    for (var i = 0; i < data.Length; i++)
    {
        var b = data[i];
        chars[i * 2] = alphabet[b >> 4];
        chars[(i * 2) + 1] = alphabet[b & 0x0F];
    }
    return new string(chars);
#endif
}

static string EscapeJson(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");

file sealed class TempDirectory : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"FirmwareKit.AVB.{Guid.NewGuid():N}");

    public TempDirectory()
    {
        Directory.CreateDirectory(Path);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}

file sealed class CredentialArchivePatterns
{
    public static readonly Regex PikRegex = new Regex("^pik_certificate.*\\.bin$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    public static readonly Regex PukCertRegex = new Regex("^puk_certificate.*\\.bin$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    public static readonly Regex PukKeyRegex = new Regex("^puk.*\\.pem$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
}
