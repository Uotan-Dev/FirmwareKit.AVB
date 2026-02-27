
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FirmwareKit.AVB;
/// <summary>
/// Provides cryptographic utilities for Android Verified Boot (AVB), including RSA public key parsing 
/// and hash computation.
/// </summary>
public static class AvbCrypto
{
    /// <summary>
    /// The public exponent used in AVB RSA keys (65537).
    /// </summary>
    public const int Exponent = 65537;

    /// <summary>
    /// Parses an RSA public key from the AVB binary format.
    /// </summary>
    /// <param name="data">The byte span containing the RSA public key in AVB format.</param>
    /// <returns>An <see cref="RSAParameters"/> structure representing the public key.</returns>
    /// <exception cref="ArgumentException">Thrown when the key data is malformed or too small.</exception>
    /// <remarks>
    /// The AVB RSA public key format consists of a header (8 bytes) specifying the number of bits and n0inv, 
    /// followed by the modulus (n) and the RR value.
    /// </remarks>
    public static RSAParameters ParseRSAPublicKey(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
        {
            throw new ArgumentException("Key data too small");
        }

        var keyNumBits = BinaryPrimitives.ReadUInt32BigEndian(data[0..4]);
        _ = BinaryPrimitives.ReadUInt32BigEndian(data[4..8]);

        var keyNumBytes = (int)(keyNumBits / 8);
        if (data.Length < 8 + (keyNumBytes * 2))
        {
            throw new ArgumentException($"Key data too small for {keyNumBits} bits");
        }

        // Format is: header(8) + n(key_num_bytes) + rr(key_num_bytes)
        // big-endian
        var modulus = data.Slice(8, keyNumBytes).ToArray();

        return new RSAParameters
        {
            Modulus = modulus,
            Exponent = [1, 0, 1] // 65537
        };
    }

    /// <summary>
    /// Computes the hash for the given data based on the specified AVB algorithm type.
    /// </summary>
    /// <param name="algorithm">The <see cref="AvbAlgorithmType"/> to use for hashing.</param>
    /// <param name="data">The byte span to hash.</param>
    /// <returns>The computed hash as a byte array.</returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm type is unsupported.</exception>
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
    /// </summary>
    /// <param name="algorithmName">The name of the hash algorithm (e.g., "sha256").</param>
    /// <param name="salt">The salt to prepend to the data before hashing.</param>
    /// <param name="data">The data to hash.</param>
    /// <returns>The computed hash as a byte array.</returns>
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
    /// Gets the digest size in bytes for a specified hash algorithm name.
    /// </summary>
    /// <param name="algorithmName">The name of the hash algorithm.</param>
    /// <returns>The digest size in bytes.</returns>
    public static int GetDigestSize(string algorithmName) => algorithmName.ToLowerInvariant() switch
    {
        "sha1" => 20,
        "sha256" => 32,
        "sha512" => 64,
        _ => 32 // Default to SHA256 as per AOSP fallback in some cases
    };

    /// <summary>
    /// Converts a hash algorithm name string to a <see cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="name">The name of the hash algorithm.</param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown when the hash name is unknown or unsupported.</exception>
    public static HashAlgorithmName GetHashAlgorithmName(string name) => name.ToLowerInvariant() switch
    {
        "sha1" => HashAlgorithmName.SHA1,
        "sha256" => HashAlgorithmName.SHA256,
        "sha512" => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported hash {name}")
    };

    /// <summary>
    /// Maps a hash algorithm name string to a corresponding <see cref="AvbAlgorithmType"/>.
    /// </summary>
    /// <param name="name">The name of the hash algorithm.</param>
    /// <returns>The resolved <see cref="AvbAlgorithmType"/>, or <see cref="AvbAlgorithmType.None"/> if no mapping is found.</returns>
    public static AvbAlgorithmType GetAlgorithmType(string name) => name.ToLowerInvariant() switch
    {
        "sha1" => AvbAlgorithmType.None, // AVB doesn't have a standard SHA1 algorithm type for VBMeta but used in HashDescriptors
        "sha256" => AvbAlgorithmType.Sha256Rsa2048, // Default mapping
        "sha512" => AvbAlgorithmType.Sha512Rsa2048,
        _ => AvbAlgorithmType.None
    };

    /// <summary>
    /// Gets the <see cref="HashAlgorithmName"/> associated with the specified <see cref="AvbAlgorithmType"/>.
    /// </summary>
    /// <param name="algorithm">The <see cref="AvbAlgorithmType"/>.</param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown when the algorithm type does not have a defined hash.</exception>
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
}

