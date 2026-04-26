using FirmwareKit.AVB.Core;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Security;
using FirmwareKit.AVB.Utilities;
using System.Security.Cryptography;

namespace FirmwareKit.AVB.VBMeta;
/// <summary>
/// Represents a loaded Android Verified Boot (AVB) VBMeta image.
/// This class handles integrity checks and descriptor extraction.
/// <para>表示已加载的Android Verified Boot (AVB) VBMeta镜像。</para>
/// <para>此类处理完整性检查和描述符提取。</para>
/// </summary>
public sealed class AvbVBMetaImage
{
    private readonly ReadOnlyMemory<byte> _rawData;

    /// <summary>
    /// Gets the VBMeta image header.
    /// <para>获取VBMeta镜像头。</para>
    /// </summary>
    public AvbVBMetaImageHeader Header { get; }

    /// <summary>
    /// Gets the literal bytes comprising the authentication data block.
    /// <para>获取包含认证数据块的文字字节。</para>
    /// </summary>
    public ReadOnlyMemory<byte> AuthenticationData { get; }

    /// <summary>
    /// Gets the literal bytes comprising the auxiliary data block.
    /// <para>获取包含辅助数据块的文字字节。</para>
    /// </summary>
    public ReadOnlyMemory<byte> AuxiliaryData { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AvbVBMetaImage"/> class from raw bytes.
    /// <para>从原始字节初始化<see cref="AvbVBMetaImage"/>类的新实例。</para>
    /// </summary>
    /// <param name="data">The raw bytes of the VBMeta image.
    /// <para>VBMeta镜像的原始字节。</para></param>
    /// <exception cref="ArgumentException">Thrown when the data is too small or malformed.
    /// <para>当数据太小或格式错误时抛出。</para></exception>
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
        var totalRequired = auxStart + auxLength;

        if (authLength < 0 || auxLength < 0 || totalRequired < 0)
        {
            AuthenticationData = ReadOnlyMemory<byte>.Empty;
            AuxiliaryData = ReadOnlyMemory<byte>.Empty;
            _rawData = data;
            return;
        }

        if (data.Length < totalRequired)
        {
            AuthenticationData = ReadOnlyMemory<byte>.Empty;
            AuxiliaryData = ReadOnlyMemory<byte>.Empty;
            _rawData = data;
            return;
        }

        AuthenticationData = data.Slice((int)authStart, (int)authLength);
        AuxiliaryData = data.Slice((int)auxStart, (int)auxLength);
        _rawData = data[..(int)totalRequired];
    }

    /// <summary>
    /// Verifies the structural and cryptographic integrity of the VBMeta image.
    /// Equivalent to 'avb_vbmeta_image_verify()' in libavb.
    /// <para>验证VBMeta镜像的结构和加密完整性。</para>
    /// <para>等价于libavb中的'avb_vbmeta_image_verify()'。</para>
    /// </summary>
    /// <returns>A value indicating the verification result.
    /// <para>指示验证结果的值。</para></returns>
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

        var availableSize = (ulong)(_rawData.Length - AvbVBMetaImageHeader.Size);
        if (authSize > availableSize || auxSize > availableSize - authSize)
        {
            return AvbVBMetaVerifyResult.InvalidVBMetaHeader;
        }

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

    /// <summary>
    /// Converts a VBMeta verification result to a stable libavb-style string.
    /// <para>将VBMeta验证结果转换为稳定的libavb风格字符串。</para>
    /// </summary>
    /// <param name="result">The verification result to convert.
    /// <para>要转换的验证结果。</para></param>
    /// <returns>The string representation of the result.
    /// <para>结果的字符串表示。</para></returns>
    public static string ResultToString(AvbVBMetaVerifyResult result) => AvbResultStrings.ToLibAvbString(result);

    /// <summary>
    /// Tries to verify a vbmeta image and returns false only when parsing fails.
    /// <para>尝试验证vbmeta镜像，仅在解析失败时返回false。</para>
    /// </summary>
    /// <param name="data">The raw VBMeta image bytes.
    /// <para>原始VBMeta镜像字节。</para></param>
    /// <param name="result">When this method returns, contains the verification result if parsing succeeded.
    /// <para>当此方法返回时，如果解析成功则包含验证结果。</para></param>
    /// <returns>Returns true if successfully parsed, even on verification failure; returns false only on parse failure.
    /// <para>如果成功解析则返回true，即使验证失败；仅在解析失败时返回false。</para></returns>
    public static bool TryVerify(ReadOnlyMemory<byte> data, out AvbVBMetaVerifyResult result)
    {
        try
        {
            var image = new AvbVBMetaImage(data);
            result = image.VerifyIntegrity();
            return true;
        }
        catch
        {
            result = AvbVBMetaVerifyResult.InvalidVBMetaHeader;
            return false;
        }
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
    /// <para>解析并返回嵌入在辅助数据块中的所有描述符。</para>
    /// </summary>
    /// <returns>A list of descriptors (Hash, Hashtree, Chain, etc.).
    /// <para>描述符列表（Hash、Hashtree、Chain等）。</para></returns>
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

    /// <summary>
    /// Gets all descriptors in array form.
    /// <para>以数组形式获取所有描述符。</para>
    /// </summary>
    public AvbDescriptor[] GetAllDescriptors() => GetDescriptors().ToArray();

    /// <summary>
    /// Iterates descriptors and invokes the callback for each entry.
    /// <para>遍历描述符并为每个条目调用回调。</para>
    /// </summary>
    /// <param name="callback">Invoked for each descriptor; return false to stop iteration early.
    /// <para>为每个描述符调用；返回false以提前停止迭代。</para></param>
    /// <returns>Returns true if all descriptors were visited successfully; otherwise, false.
    /// <para>如果所有描述符都被成功访问则返回true；否则返回false。</para></returns>
    public bool ForEachDescriptor(Func<AvbDescriptor, bool> callback)
    {
        foreach (var descriptor in GetDescriptors())
        {
            if (!callback(descriptor))
            {
                return false;
            }
        }

        return true;
    }
}