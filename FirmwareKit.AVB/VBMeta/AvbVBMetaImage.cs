
using System.Security.Cryptography;

namespace FirmwareKit.AVB;
/// <summary>
/// Represents a loaded Android Verified Boot (AVB) VBMeta image.
/// This class handles integrity checks and descriptor extraction.
/// </summary>
public sealed class AvbVBMetaImage
{
    private readonly ReadOnlyMemory<byte> _rawData;

    /// <summary>Gets the VBMeta image header.</summary>
    public AvbVBMetaImageHeader Header { get; }

    /// <summary>Gets the literal bytes comprising the authentication data block.</summary>
    public ReadOnlyMemory<byte> AuthenticationData { get; }

    /// <summary>Gets the literal bytes comprising the auxiliary data block.</summary>
    public ReadOnlyMemory<byte> AuxiliaryData { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AvbVBMetaImage"/> class from raw bytes.
    /// </summary>
    /// <param name="data">The raw bytes of the VBMeta image.</param>
    /// <exception cref="ArgumentException">Thrown when the data is too small or malformed.</exception>
    public AvbVBMetaImage(ReadOnlyMemory<byte> data)
    {
        if (data.Length < AvbVBMetaImageHeader.Size)
        {
            throw new ArgumentException("Data too small for header");
        }

        Header = AvbVBMetaImageHeader.FromBytes(data.Span[..AvbVBMetaImageHeader.Size]);

        long authStart = AvbVBMetaImageHeader.Size;
        var authLength = (long)Header.AuthenticationDataBlockSize;
        var auxStart = authStart + authLength;
        var auxLength = (long)Header.AuxiliaryDataBlockSize;

        if (data.Length < auxStart + auxLength)
        {
            throw new ArgumentException($"Data size {data.Length} is less than required size {auxStart + auxLength}");
        }

        AuthenticationData = data.Slice((int)authStart, (int)authLength);
        AuxiliaryData = data.Slice((int)auxStart, (int)auxLength);
        _rawData = data[..(int)(auxStart + auxLength)];
    }

    /// <summary>
    /// Verifies the structural and cryptographic integrity of the VBMeta image.
    /// Equivalent to 'avb_vbmeta_image_verify()' in libavb.
    /// </summary>
    /// <returns>A value indicating the verification result.</returns>
    public AvbVBMetaVerifyResult VerifyIntegrity()
    {
        if (Header.Magic != AvbVBMetaImageHeader.MagicHeader)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }


        if (!AvbVersion.IsCompatible(Header.RequiredLibavbVersionMajor, Header.RequiredLibavbVersionMinor))
        {
            return AvbVBMetaVerifyResult.UnsupportedVersion;
        }

        if (!Header.IsReleaseStringValid)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

        if (!Header.IsReservedValid)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

        if ((Header.AuthenticationDataBlockSize & 0x3f) != 0 || (Header.AuxiliaryDataBlockSize & 0x3f) != 0)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

        var authSize = Header.AuthenticationDataBlockSize;
        var auxSize = Header.AuxiliaryDataBlockSize;

        if (Header.HashSize > 0)
        {
            if (Header.HashOffset > authSize || Header.HashSize > authSize || authSize - Header.HashOffset < Header.HashSize)
            {
                return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
            }
        }

        if (Header.SignatureSize > 0)
        {
            if (Header.SignatureOffset > authSize || Header.SignatureSize > authSize || authSize - Header.SignatureOffset < Header.SignatureSize)
            {
                return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
            }
        }

        if (Header.PublicKeySize > 0)
        {
            if (Header.PublicKeyOffset > auxSize || Header.PublicKeySize > auxSize || auxSize - Header.PublicKeyOffset < Header.PublicKeySize)
            {
                return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
            }
        }

        if (Header.PublicKeyMetadataSize > 0)
        {
            if (Header.PublicKeyMetadataOffset > auxSize || auxSize - Header.PublicKeyMetadataOffset < Header.PublicKeyMetadataSize)
            {
                return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
            }
        }

        if (Header.AlgorithmType == (uint)AvbAlgorithmType.None)
        {
            return AvbVBMetaVerifyResult.OkNotSigned;
        }

        var algorithm = (AvbAlgorithmType)Header.AlgorithmType;
        var expectedHashLen = algorithm switch
        {
            AvbAlgorithmType.Sha256Rsa2048 or AvbAlgorithmType.Sha256Rsa4096 or AvbAlgorithmType.Sha256Rsa8192 => 32,
            AvbAlgorithmType.Sha512Rsa2048 or AvbAlgorithmType.Sha512Rsa4096 or AvbAlgorithmType.Sha512Rsa8192 => 64,
            AvbAlgorithmType.None => -1,
            _ => -1
        };

        if (expectedHashLen < 0)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

        if ((int)Header.HashSize != expectedHashLen)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

        var headerBlock = _rawData.Span[..AvbVBMetaImageHeader.Size];
        var auxiliaryBlock = AuxiliaryData.Span;

        var computedHash = CalculateVBMetaHash(algorithm, headerBlock, auxiliaryBlock);

        var storedHash = AuthenticationData.Span.Slice((int)Header.HashOffset, (int)Header.HashSize);
        if (AvbUtil.SafeMemCmp(computedHash, storedHash) != 0)
        {
            return AvbVBMetaVerifyResult.HashMismatch;
        }

        if (Header.SignatureSize > 0)
        {
            var storedSignature = AuthenticationData.Span.Slice((int)Header.SignatureOffset, (int)Header.SignatureSize);
            var publicKeyData = AuxiliaryData.Span.Slice((int)Header.PublicKeyOffset, (int)Header.PublicKeySize);

            using var rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(AvbCrypto.ParseRSAPublicKey(publicKeyData));
            }
            catch
            {
                return AvbVBMetaVerifyResult.SignatureMismatch;
            }

            if (!rsa.VerifyHash(computedHash, storedSignature.ToArray(), AvbCrypto.GetHashAlgorithmName(algorithm), RSASignaturePadding.Pkcs1))
            {
                return AvbVBMetaVerifyResult.SignatureMismatch;
            }
        }

        return AvbVBMetaVerifyResult.Ok;
    }

    private static byte[] CalculateVBMetaHash(AvbAlgorithmType algorithm, ReadOnlySpan<byte> header, ReadOnlySpan<byte> auxiliary)
    {
        var hashName = AvbCrypto.GetHashAlgorithmName(algorithm);
        using var incrementalHash = IncrementalHash.CreateHash(hashName);
        incrementalHash.AppendData(header.ToArray());
        incrementalHash.AppendData(auxiliary.ToArray());
        return incrementalHash.GetHashAndReset();
    }

    /// <summary>
    /// Parses and returns all descriptors embedded in the auxiliary data block.
    /// </summary>
    /// <returns>A list of descriptors (Hash, Hashtree, Chain, etc.)</returns>
    public List<AvbDescriptor> GetDescriptors()
    {
        var descriptorsSpan = AuxiliaryData.Span.Slice((int)Header.DescriptorsOffset, (int)Header.DescriptorsSize);
        var offset = 0;
        var result = new List<AvbDescriptor>();

        while (offset < (int)Header.DescriptorsSize)
        {
            var desc = AvbDescriptor.FromBytes(descriptorsSpan[offset..]);
            result.Add(desc);

            offset += 16 + (int)desc.NumBytesFollowing;
        }
        return result;
    }
}

