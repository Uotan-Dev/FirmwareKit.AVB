using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace FirmwareKit.AVB.Security;
/// <summary>
/// Provides cryptographic utilities for Android Verified Boot (AVB), including RSA public key parsing
/// and hash computation.
/// <para>为Android Verified Boot (AVB)提供加密工具，包括RSA公钥解析和哈希计算。</para>
/// </summary>
public static class AvbCrypto
{
    /// <summary>
    /// The public exponent used in AVB RSA keys (65537).
    /// <para>AVB RSA密钥中使用的公共指数（65537）。</para>
    /// </summary>
    public const int Exponent = 65537;

    /// <summary>
    /// Parses an RSA public key from the AVB binary format.
    /// <para>从AVB二进制格式解析RSA公钥。</para>
    /// </summary>
    /// <param name="data">The byte span containing the RSA public key in AVB format.
    /// <para>包含AVB格式RSA公钥的字节跨度。</para></param>
    /// <returns>An <see cref="RSAParameters"/> structure representing the public key.
    /// <para>表示公钥的<see cref="RSAParameters"/>结构。</para></returns>
    /// <exception cref="ArgumentException">Thrown when the key data is malformed or too small.
    /// <para>当密钥数据格式错误或太小时抛出。</para></exception>
    /// <remarks>
    /// The AVB RSA public key format consists of a header (8 bytes) specifying the number of bits and n0inv,
    /// followed by the modulus (n) and the RR value.
    /// <para>AVB RSA公钥格式由一个头（8字节）组成，指定位数和n0inv，
    /// 后跟模数（n）和RR值。</para>
    /// </remarks>
    public static RSAParameters ParseRSAPublicKey(ReadOnlySpan<byte> data)
    {
        if (!AvbRsaPublicKeyHeader.TryFromBytes(data, out var header))
        {
            throw new ArgumentException("Key header is malformed.");
        }

        var keyNumBits = header.KeyNumBits;
        if (keyNumBits is not (2048 or 4096 or 8192))
        {
            throw new ArgumentException($"Unsupported RSA key size: {keyNumBits}.");
        }

        var keyNumBytes = (int)(keyNumBits / 8);
        var expectedLength = 8 + (keyNumBytes * 2);
        if (data.Length != expectedLength)
        {
            throw new ArgumentException($"Key data length does not match {keyNumBits}-bit AVB key format.");
        }

        var modulus = data.Slice(8, keyNumBytes).ToArray();

        return new RSAParameters
        {
            Modulus = modulus,
            Exponent = [1, 0, 1]
        };
    }

    /// <summary>
    /// Attempts to parse an RSA public key from AVB binary format.
    /// <para>尝试从AVB二进制格式解析RSA公钥。</para>
    /// </summary>
    public static bool TryParseRSAPublicKey(ReadOnlySpan<byte> data, out RSAParameters parameters)
    {
        parameters = default;

        try
        {
            parameters = ParseRSAPublicKey(data);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Encodes an RSA public key to AVB binary public-key format.
    /// Layout: key_num_bits (be), n0inv (be), modulus (be), rr (be).
    /// <para>将RSA公钥编码为AVB二进制公钥格式。</para>
    /// <para>布局：key_num_bits (be), n0inv (be), modulus (be), rr (be)。</para>
    /// </summary>
    /// <param name="keyParameters">RSA key parameters with modulus and exponent.
    /// <para>带模数和指数的RSA密钥参数。</para></param>
    /// <returns>Serialized AVB public key bytes.
    /// <para>序列化的AVB公钥字节。</para></returns>
    public static byte[] EncodeRSAPublicKey(RSAParameters keyParameters)
    {
        if (keyParameters.Modulus == null || keyParameters.Modulus.Length == 0)
        {
            throw new ArgumentException("RSA modulus is required.");
        }

        if (keyParameters.Exponent == null || keyParameters.Exponent.Length == 0)
        {
            throw new ArgumentException("RSA exponent is required.");
        }

        var modulus = keyParameters.Modulus;
        var exponent = ReadUInt32BigEndian(keyParameters.Exponent);
        if (exponent != Exponent)
        {
            throw new NotSupportedException($"Only RSA exponent {Exponent} is supported by AVB tooling.");
        }

        var keyNumBits = modulus.Length * 8;
        if (keyNumBits is not (2048 or 4096 or 8192))
        {
            throw new NotSupportedException($"Only 2048, 4096, and 8192-bit RSA keys are supported, got {keyNumBits}.");
        }

        var n = FromBigEndianUnsigned(modulus);
        if (n.Sign <= 0)
        {
            throw new ArgumentException("Invalid RSA modulus.");
        }

        var n0 = (uint)(n % (BigInteger.One << 32));
        if ((n0 & 1u) == 0u)
        {
            throw new ArgumentException("RSA modulus must be odd.");
        }

        var n0inv = ComputeN0Inv(n0);
        var rr = BigInteger.ModPow(new BigInteger(2), 2 * keyNumBits, n);
        var rrBytes = ToBigEndianUnsigned(rr, modulus.Length);

        var output = new byte[8 + modulus.Length + rrBytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(0, 4), (uint)keyNumBits);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(4, 4), n0inv);
        modulus.CopyTo(output.AsSpan(8, modulus.Length));
        rrBytes.CopyTo(output.AsSpan(8 + modulus.Length, rrBytes.Length));
        return output;
    }

    private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> data)
    {
        uint value = 0;
        for (var i = 0; i < data.Length; i++)
        {
            value = (value << 8) | data[i];
        }

        return value;
    }

    private static BigInteger FromBigEndianUnsigned(ReadOnlySpan<byte> bytes)
    {
        var le = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            le[i] = bytes[bytes.Length - 1 - i];
        }

        le[bytes.Length] = 0;
        return new BigInteger(le);
    }

    private static byte[] ToBigEndianUnsigned(BigInteger value, int fixedSize)
    {
        if (value.Sign < 0)
        {
            throw new ArgumentException("Only non-negative integers are supported.");
        }

        var le = value.ToByteArray();
        var significantLength = le.Length;
        while (significantLength > 1 && le[significantLength - 1] == 0)
        {
            significantLength--;
        }

        if (significantLength > fixedSize)
        {
            throw new ArgumentException("Value does not fit in requested output size.");
        }

        var be = new byte[fixedSize];
        for (var i = 0; i < significantLength; i++)
        {
            be[fixedSize - 1 - i] = le[i];
        }

        return be;
    }

    private static uint ComputeN0Inv(uint n0)
    {
        unchecked
        {
            uint inv = 1;
            for (var i = 0; i < 5; i++)
            {
                inv *= 2 - (n0 * inv);
            }

            return 0u - inv;
        }
    }

    /// <summary>
    /// Computes the hash for the given data based on the specified AVB algorithm type.
    /// <para>根据指定的AVB算法类型计算给定数据的哈希值。</para>
    /// </summary>
    /// <param name="algorithm">The <see cref="AvbAlgorithmType"/> to use for hashing.
    /// <para>用于哈希的<see cref="AvbAlgorithmType"/>。</para></param>
    /// <param name="data">The byte span to hash.
    /// <para>要哈希的字节跨度。</para></param>
    /// <returns>The computed hash as a byte array.
    /// <para>计算出的哈希作为字节数组。</para></returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm type is unsupported.
    /// <para>当算法类型不受支持时抛出。</para></exception>
    public static byte[] CalculateHash(AvbAlgorithmType algorithm, ReadOnlySpan<byte> data)
    {
        return algorithm switch
        {
            AvbAlgorithmType.Sha256Rsa2048 or
            AvbAlgorithmType.Sha256Rsa4096 or
            AvbAlgorithmType.Sha256Rsa8192 => AvbCompat.HashData256(data),

            AvbAlgorithmType.Sha512Rsa2048 or
            AvbAlgorithmType.Sha512Rsa4096 or
            AvbAlgorithmType.Sha512Rsa8192 => AvbCompat.HashData512(data),

            AvbAlgorithmType.None => throw new NotSupportedException($"Unsupported algorithm {algorithm}"),
            _ => throw new NotSupportedException($"Unsupported algorithm {algorithm}")
        };
    }

    /// <summary>
    /// Computes a salted hash for the given data.
    /// <para>为给定数据计算加盐哈希值。</para>
    /// </summary>
    /// <param name="algorithmName">The name of the hash algorithm (e.g., "sha256").
    /// <para>哈希算法的名称（例如"sha256"）。</para></param>
    /// <param name="salt">The salt to prepend to the data before hashing.
    /// <para>哈希前要预先添加到数据的盐值。</para></param>
    /// <param name="data">The data to hash.
    /// <para>要哈希的数据。</para></param>
    /// <returns>The computed hash as a byte array.
    /// <para>计算出的哈希作为字节数组。</para></returns>
    public static byte[] CalculateHash(string algorithmName, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> data)
    {
        using var incrementalHash = IncrementalHash.CreateHash(GetHashAlgorithmName(algorithmName));
        if (!salt.IsEmpty)
        {
            incrementalHash.AppendData(salt.ToArray());
        }

        incrementalHash.AppendData(data.ToArray());
        return incrementalHash.GetHashAndReset();
    }

    /// <summary>
    /// Tries to get the digest size in bytes for a specified hash algorithm name.
    /// <para>尝试获取指定哈希算法名称的摘要大小（以字节为单位）。</para>
    /// </summary>
    /// <param name="algorithmName">The name of the hash algorithm.
    /// <para>哈希算法的名称。</para></param>
    /// <param name="digestSize">Outputs the digest size in bytes.
    /// <para>输出以字节为单位的摘要大小。</para></param>
    /// <returns><c>true</c> when the algorithm is recognized; otherwise, <c>false</c>.
    /// <para>当算法被识别时为<c>true</c>；否则为<c>false</c>。</para></returns>
    public static bool TryGetDigestSize(string algorithmName, out int digestSize)
    {
        switch (algorithmName.ToLowerInvariant())
        {
            case "sha1":
                digestSize = 20;
                return true;
            case "sha256":
                digestSize = 32;
                return true;
            case "sha512":
                digestSize = 64;
                return true;
            default:
                digestSize = 0;
                return false;
        }
    }

    /// <summary>
    /// Gets the digest size in bytes for a specified hash algorithm name.
    /// <para>获取指定哈希算法名称的摘要大小（以字节为单位）。</para>
    /// </summary>
    /// <param name="algorithmName">The name of the hash algorithm.
    /// <para>哈希算法的名称。</para></param>
    /// <returns>The digest size in bytes.
    /// <para>以字节为单位的摘要大小。</para></returns>
    public static int GetDigestSize(string algorithmName) =>
        TryGetDigestSize(algorithmName, out var digestSize)
            ? digestSize
            : throw new NotSupportedException($"Unsupported hash {algorithmName}");

    /// <summary>
    /// Converts a hash algorithm name string to a <see cref="HashAlgorithmName"/>.
    /// <para>将哈希算法名称字符串转换为<see cref="HashAlgorithmName"/>。</para>
    /// </summary>
    /// <param name="name">The name of the hash algorithm.
    /// <para>哈希算法的名称。</para></param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.
    /// <para>对应的<see cref="HashAlgorithmName"/>。</para></returns>
    /// <exception cref="NotSupportedException">Thrown when the hash name is unknown or unsupported.
    /// <para>当哈希名称未知或不受支持时抛出。</para></exception>
    public static HashAlgorithmName GetHashAlgorithmName(string name) => name.ToLowerInvariant() switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        "sha512" => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported hash {name}")
    };

    /// <summary>
    /// Maps a hash algorithm name string to a corresponding <see cref="AvbAlgorithmType"/>.
    /// <para>将哈希算法名称字符串映射到相应的<see cref="AvbAlgorithmType"/>。</para>
    /// </summary>
    /// <param name="name">The name of the hash algorithm.
    /// <para>哈希算法的名称。</para></param>
    /// <returns>The resolved <see cref="AvbAlgorithmType"/>, or <see cref="AvbAlgorithmType.None"/> if no mapping is found.
    /// <para>解析的<see cref="AvbAlgorithmType"/>，如果没有找到映射则为<see cref="AvbAlgorithmType.None"/>。</para></returns>
    public static AvbAlgorithmType GetAlgorithmType(string name) => name.ToLowerInvariant() switch
    {
        "sha1" => AvbAlgorithmType.None,
        "sha256" => AvbAlgorithmType.Sha256Rsa2048,
        "sha512" => AvbAlgorithmType.Sha512Rsa2048,
        _ => AvbAlgorithmType.None
    };

    /// <summary>
    /// Gets the <see cref="HashAlgorithmName"/> associated with the specified <see cref="AvbAlgorithmType"/>.
    /// <para>获取与指定<see cref="AvbAlgorithmType"/>关联的<see cref="HashAlgorithmName"/>。</para>
    /// </summary>
    /// <param name="algorithm">The <see cref="AvbAlgorithmType"/>.
    /// <para><see cref="AvbAlgorithmType"/>。</para></param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.
    /// <para>对应的<see cref="HashAlgorithmName"/>。</para></returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm type does not have a defined hash.
    /// <para>当算法类型没有定义的哈希时抛出。</para></exception>
    public static HashAlgorithmName GetHashAlgorithmName(AvbAlgorithmType algorithm)
    {
        return algorithm switch
        {
            AvbAlgorithmType.Sha256Rsa2048 or
            AvbAlgorithmType.Sha256Rsa4096 or
            AvbAlgorithmType.Sha256Rsa8192 => HashAlgorithmName.SHA256,

            AvbAlgorithmType.Sha512Rsa2048 or
            AvbAlgorithmType.Sha512Rsa4096 or
            AvbAlgorithmType.Sha512Rsa8192 => HashAlgorithmName.SHA512,

            AvbAlgorithmType.None => throw new NotSupportedException($"Unsupported algorithm {algorithm}"),
            _ => throw new NotSupportedException($"Unsupported algorithm {algorithm}")
        };
    }

    /// <summary>
    /// Gets the hash algorithm name and digest size for a supported AVB algorithm.
    /// <para>获取支持的AVB算法的哈希算法名称和摘要大小。</para>
    /// </summary>
    public static bool TryGetAlgorithmInfo(AvbAlgorithmType algorithm, out HashAlgorithmName hashAlgorithmName, out int hashSize)
    {
        switch (algorithm)
        {
            case AvbAlgorithmType.Sha256Rsa2048:
            case AvbAlgorithmType.Sha256Rsa4096:
            case AvbAlgorithmType.Sha256Rsa8192:
                hashAlgorithmName = HashAlgorithmName.SHA256;
                hashSize = 32;
                return true;

            case AvbAlgorithmType.Sha512Rsa2048:
            case AvbAlgorithmType.Sha512Rsa4096:
            case AvbAlgorithmType.Sha512Rsa8192:
                hashAlgorithmName = HashAlgorithmName.SHA512;
                hashSize = 64;
                return true;

            default:
                hashAlgorithmName = default;
                hashSize = 0;
                return false;
        }
    }

    /// <summary>
    /// Signs data using an RSA private key.
    /// <para>使用RSA私钥对数据进行签名。</para>
    /// </summary>
    /// <param name="privateKeyPath">Path to the private key PEM file.
    /// <para>私钥PEM文件的路径。</para></param>
    /// <param name="algorithm">The algorithm to use for signing.
    /// <para>用于签名的算法。</para></param>
    /// <param name="data">The data to sign.
    /// <para>要签名的数据。</para></param>
    /// <param name="signingHelper">Optional signing helper program.
    /// <para>可选的签名帮助程序。</para></param>
    /// <param name="signingHelperWithFiles">Optional signing helper program that uses files.
    /// <para>使用文件的可选签名帮助程序。</para></param>
    /// <returns>The signature as a byte array.
    /// <para>作为字节数组的签名。</para></returns>
    public static byte[] SignData(string privateKeyPath, AvbAlgorithmType algorithm, ReadOnlySpan<byte> data, string? signingHelper = null, string? signingHelperWithFiles = null)
    {
        if (signingHelperWithFiles != null)
        {
            return SignDataWithHelper(signingHelperWithFiles, algorithm, privateKeyPath, data);
        }

        if (signingHelper != null)
        {
            return SignDataWithHelper(signingHelper, algorithm, privateKeyPath, data);
        }

        return SignDataWithOpenSsl(privateKeyPath, algorithm, data);
    }

    /// <summary>
    /// Signs data using OpenSSL.
    /// <para>使用OpenSSL对数据进行签名。</para>
    /// </summary>
    private static byte[] SignDataWithOpenSsl(string privateKeyPath, AvbAlgorithmType algorithm, ReadOnlySpan<byte> data)
    {
        var tempFile = Path.GetTempFileName();
        var sigFile = Path.GetTempFileName();

        try
        {
            File.WriteAllBytes(tempFile, data.ToArray());

            var cmd = $"openssl rsautl -sign -inkey \"{privateKeyPath}\" -raw -in \"{tempFile}\" -out \"{sigFile}\"";

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {cmd}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                var error = process.StandardError.ReadToEnd();
                throw new System.Exception($"OpenSSL signing failed: {error}");
            }

            return File.ReadAllBytes(sigFile);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
            if (File.Exists(sigFile)) File.Delete(sigFile);
        }
    }

    /// <summary>
    /// Signs data using a signing helper program.
    /// <para>使用签名助手程序对数据进行签名。</para>
    /// </summary>
    private static byte[] SignDataWithHelper(string helper, AvbAlgorithmType algorithm, string privateKeyPath, ReadOnlySpan<byte> data)
    {
        var tempFile = Path.GetTempFileName();
        var sigFile = Path.GetTempFileName();

        try
        {
            File.WriteAllBytes(tempFile, data.ToArray());

            var cmd = $"{helper} {GetAlgorithmName(algorithm)} {privateKeyPath} {tempFile} {sigFile}";

            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {cmd}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                var error = process.StandardError.ReadToEnd();
                throw new System.Exception($"Signing helper failed: {error}");
            }

            return File.ReadAllBytes(sigFile);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
            if (File.Exists(sigFile)) File.Delete(sigFile);
        }
    }

    /// <summary>
    /// Verifies a signature using an RSA public key.
    /// <para>使用RSA公钥验证签名。</para>
    /// </summary>
    /// <param name="publicKey">The RSA public key parameters.
    /// <para>RSA公钥参数。</para></param>
    /// <param name="algorithm">The algorithm used for signing.
    /// <para>用于签名的算法。</para></param>
    /// <param name="data">The original data.
    /// <para>原始数据。</para></param>
    /// <param name="signature">The signature to verify.
    /// <para>要验证的签名。</para></param>
    /// <returns>True if the signature is valid, false otherwise.
    /// <para>如果签名有效则为true，否则为false。</para></returns>
    public static bool VerifySignature(RSAParameters publicKey, AvbAlgorithmType algorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(data.ToArray(), signature.ToArray(), GetHashAlgorithmName(algorithm), RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets the algorithm name as a string.
    /// <para>获取算法名称作为字符串。</para>
    /// </summary>
    private static string GetAlgorithmName(AvbAlgorithmType algorithm)
    {
        return algorithm switch
        {
            AvbAlgorithmType.Sha256Rsa2048 => "sha256-rsa2048",
            AvbAlgorithmType.Sha256Rsa4096 => "sha256-rsa4096",
            AvbAlgorithmType.Sha256Rsa8192 => "sha256-rsa8192",
            AvbAlgorithmType.Sha512Rsa2048 => "sha512-rsa2048",
            AvbAlgorithmType.Sha512Rsa4096 => "sha512-rsa4096",
            AvbAlgorithmType.Sha512Rsa8192 => "sha512-rsa8192",
            _ => throw new NotSupportedException($"Unsupported algorithm {algorithm}")
        };
    }
}