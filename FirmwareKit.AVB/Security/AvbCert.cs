using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FirmwareKit.AVB.Security;

/// <summary>
/// Constants used by libavb_cert compatible flows.
/// <para>libavb_cert兼容流程使用的常量。</para>
/// </summary>
public static class AvbCertConstants
{
    /// <summary>
    /// Rollback index location for Product Intermediate Key (PIK) version.
    /// <para>产品中间密钥（PIK）版本的回滚索引位置。</para>
    /// </summary>
    public const int PikVersionLocation = 0x1000;

    /// <summary>
    /// Rollback index location for Product Signing/Unlock Key (PSK/PUK) version.
    /// <para>产品签名/解锁密钥（PSK/PUK）版本的回滚索引位置。</para>
    /// </summary>
    public const int PskVersionLocation = 0x1001;

    /// <summary>
    /// Size in bytes of product ID.
    /// <para>产品ID的字节大小。</para>
    /// </summary>
    public const int ProductIdSize = 16;

    /// <summary>
    /// Size in bytes of unlock challenge.
    /// <para>解锁挑战的字节大小。</para>
    /// </summary>
    public const int UnlockChallengeSize = 16;

    /// <summary>
    /// Size in bytes of AVB serialized RSA4096 public key.
    /// <para>AVB序列化RSA4096公钥的字节大小。</para>
    /// </summary>
    public const int PublicKeySize = 8 + 1024;

    /// <summary>
    /// Size in bytes of SHA-256 digest.
    /// <para>SHA-256摘要的字节大小。</para>
    /// </summary>
    public const int Digest256Size = 32;

    /// <summary>
    /// Size in bytes of SHA-512 digest.
    /// <para>SHA-512摘要的字节大小。</para>
    /// </summary>
    public const int Digest512Size = 64;

    /// <summary>
    /// Size in bytes of RSA-4096 PKCS#1 v1.5 signature.
    /// <para>RSA-4096 PKCS#1 v1.5签名的字节大小。</para>
    /// </summary>
    public const int Rsa4096SignatureSize = 512;
}

/// <summary>
/// Certificate-related platform operations for managed AVB cert validation.
/// <para>用于托管AVB证书验证的证书相关平台操作。</para>
/// </summary>
public interface IAvbCertOps
{
    /// <summary>
    /// Gets the AVB platform ops used for rollback index access.
    /// <para>获取用于回滚索引访问的AVB平台操作。</para>
    /// </summary>
    IAvbOps Ops { get; }

    /// <summary>
    /// Reads permanent attributes.
    /// <para>读取永久属性。</para>
    /// </summary>
    AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes attributes);

    /// <summary>
    /// Reads permanent attributes hash (SHA-256).
    /// <para>读取永久属性哈希（SHA-256）。</para>
    /// </summary>
    AvbIOResult ReadPermanentAttributesHash(Span<byte> hash);

    /// <summary>
    /// Reports key version used during successful validation.
    /// <para>报告成功验证期间使用的密钥版本。</para>
    /// </summary>
    void SetKeyVersion(int rollbackIndexLocation, ulong keyVersion);

    /// <summary>
    /// Fills output with cryptographically secure random bytes.
    /// <para>用加密安全的随机字节填充输出。</para>
    /// </summary>
    AvbIOResult GetRandomBytes(Span<byte> output);
}

/// <summary>
/// Data structure of libavb_cert permanent attributes.
/// <para>libavb_cert永久属性的数据结构。</para>
/// </summary>
public sealed record AvbCertPermanentAttributes
{
    /// <summary>
    /// Current format version, expected to be 1.
    /// <para>当前格式版本，期望为1。</para>
    /// </summary>
    public uint Version { get; init; }

    /// <summary>
    /// Product root public key (AVB serialized RSA4096 key).
    /// <para>产品根公钥（AVB序列化的RSA4096密钥）。</para>
    /// </summary>
    public byte[] ProductRootPublicKey { get; init; } = [];

    /// <summary>
    /// Product ID.
    /// <para>产品ID。</para>
    /// </summary>
    public byte[] ProductId { get; init; } = [];

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = 4 + AvbCertConstants.PublicKeySize + AvbCertConstants.ProductIdSize;

    /// <summary>
    /// Serializes the structure in libavb_cert binary layout.
    /// <para>以libavb_cert二进制布局序列化结构。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        if (ProductRootPublicKey.Length != AvbCertConstants.PublicKeySize)
        {
            throw new ArgumentException($"ProductRootPublicKey must be {AvbCertConstants.PublicKeySize} bytes.");
        }

        if (ProductId.Length != AvbCertConstants.ProductIdSize)
        {
            throw new ArgumentException($"ProductId must be {AvbCertConstants.ProductIdSize} bytes.");
        }

        var data = new byte[Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Version);
        ProductRootPublicKey.AsSpan().CopyTo(data.AsSpan(4, AvbCertConstants.PublicKeySize));
        ProductId.AsSpan().CopyTo(data.AsSpan(4 + AvbCertConstants.PublicKeySize, AvbCertConstants.ProductIdSize));
        return data;
    }

    /// <summary>
    /// Parses permanent attributes from binary payload.
    /// <para>从二进制有效载荷解析永久属性。</para>
    /// </summary>
    public static AvbCertPermanentAttributes FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Permanent attributes payload must be {Size} bytes.");
        }

        return new AvbCertPermanentAttributes
        {
            Version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4)),
            ProductRootPublicKey = data.Slice(4, AvbCertConstants.PublicKeySize).ToArray(),
            ProductId = data.Slice(4 + AvbCertConstants.PublicKeySize, AvbCertConstants.ProductIdSize).ToArray()
        };
    }
}

/// <summary>
/// Data structure of signed fields in libavb_cert certificate.
/// <para>libavb_cert证书中签名字段的数据结构。</para>
/// </summary>
public sealed record AvbCertCertificateSignedData
{
    /// <summary>
    /// Current format version, expected to be 1.
    /// <para>当前格式版本，期望为1。</para>
    /// </summary>
    public uint Version { get; init; }

    /// <summary>
    /// Certified public key (AVB serialized RSA4096 key).
    /// <para>认证的公钥（AVB序列化的RSA4096密钥）。</para>
    /// </summary>
    public byte[] PublicKey { get; init; } = [];

    /// <summary>
    /// Subject field (SHA-256 digest).
    /// <para>主题字段（SHA-256摘要）。</para>
    /// </summary>
    public byte[] Subject { get; init; } = [];

    /// <summary>
    /// Usage field (SHA-256 digest of usage string).
    /// <para>使用字段（使用字符串的SHA-256摘要）。</para>
    /// </summary>
    public byte[] Usage { get; init; } = [];

    /// <summary>
    /// Monotonic key version.
    /// <para>单调密钥版本。</para>
    /// </summary>
    public ulong KeyVersion { get; init; }

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = 4 + AvbCertConstants.PublicKeySize + AvbCertConstants.Digest256Size + AvbCertConstants.Digest256Size + 8;

    /// <summary>
    /// Serializes structure in libavb_cert binary layout.
    /// <para>以libavb_cert二进制布局序列化结构。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        if (PublicKey.Length != AvbCertConstants.PublicKeySize)
        {
            throw new ArgumentException($"PublicKey must be {AvbCertConstants.PublicKeySize} bytes.");
        }

        if (Subject.Length != AvbCertConstants.Digest256Size)
        {
            throw new ArgumentException($"Subject must be {AvbCertConstants.Digest256Size} bytes.");
        }

        if (Usage.Length != AvbCertConstants.Digest256Size)
        {
            throw new ArgumentException($"Usage must be {AvbCertConstants.Digest256Size} bytes.");
        }

        var data = new byte[Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Version);
        PublicKey.AsSpan().CopyTo(data.AsSpan(4, AvbCertConstants.PublicKeySize));
        Subject.AsSpan().CopyTo(data.AsSpan(4 + AvbCertConstants.PublicKeySize, AvbCertConstants.Digest256Size));
        Usage.AsSpan().CopyTo(data.AsSpan(4 + AvbCertConstants.PublicKeySize + AvbCertConstants.Digest256Size, AvbCertConstants.Digest256Size));
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(4 + AvbCertConstants.PublicKeySize + (2 * AvbCertConstants.Digest256Size), 8),
            KeyVersion);
        return data;
    }

    /// <summary>
    /// Parses signed data from binary payload.
    /// <para>从二进制有效载荷解析签名数据。</para>
    /// </summary>
    public static AvbCertCertificateSignedData FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Certificate signed-data payload must be {Size} bytes.");
        }

        var offset = 0;
        var version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;

        var publicKey = data.Slice(offset, AvbCertConstants.PublicKeySize).ToArray();
        offset += AvbCertConstants.PublicKeySize;

        var subject = data.Slice(offset, AvbCertConstants.Digest256Size).ToArray();
        offset += AvbCertConstants.Digest256Size;

        var usage = data.Slice(offset, AvbCertConstants.Digest256Size).ToArray();
        offset += AvbCertConstants.Digest256Size;

        var keyVersion = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));

        return new AvbCertCertificateSignedData
        {
            Version = version,
            PublicKey = publicKey,
            Subject = subject,
            Usage = usage,
            KeyVersion = keyVersion
        };
    }
}

/// <summary>
/// Data structure of a libavb_cert certificate.
/// <para>libavb_cert证书的数据结构。</para>
/// </summary>
public sealed record AvbCertCertificate
{
    /// <summary>
    /// Signed certificate fields.
    /// <para>签名的证书字段。</para>
    /// </summary>
    public AvbCertCertificateSignedData SignedData { get; init; } = new();

    /// <summary>
    /// RSA4096 signature over SHA-512 hash of signed data.
    /// <para>对签名数据的SHA-512哈希的RSA4096签名。</para>
    /// </summary>
    public byte[] Signature { get; init; } = [];

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = AvbCertCertificateSignedData.Size + AvbCertConstants.Rsa4096SignatureSize;

    /// <summary>
    /// Serializes certificate.
    /// <para>序列化证书。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        if (Signature.Length != AvbCertConstants.Rsa4096SignatureSize)
        {
            throw new ArgumentException($"Signature must be {AvbCertConstants.Rsa4096SignatureSize} bytes.");
        }

        var data = new byte[Size];
        var signedData = SignedData.ToBytes();
        signedData.CopyTo(data, 0);
        Signature.AsSpan().CopyTo(data.AsSpan(AvbCertCertificateSignedData.Size, AvbCertConstants.Rsa4096SignatureSize));
        return data;
    }

    /// <summary>
    /// Parses certificate from binary payload.
    /// <para>从二进制有效载荷解析证书。</para>
    /// </summary>
    public static AvbCertCertificate FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Certificate payload must be {Size} bytes.");
        }

        return new AvbCertCertificate
        {
            SignedData = AvbCertCertificateSignedData.FromBytes(data.Slice(0, AvbCertCertificateSignedData.Size)),
            Signature = data.Slice(AvbCertCertificateSignedData.Size, AvbCertConstants.Rsa4096SignatureSize).ToArray()
        };
    }
}

/// <summary>
/// Data structure of libavb_cert public key metadata embedded in vbmeta.
/// <para>嵌入在vbmeta中的libavb_cert公钥元数据的数据结构。</para>
/// </summary>
public sealed record AvbCertPublicKeyMetadata
{
    /// <summary>
    /// Current format version, expected to be 1.
    /// <para>当前格式版本，期望为1。</para>
    /// </summary>
    public uint Version { get; init; }

    /// <summary>
    /// PIK certificate signed by PRK.
    /// <para>由PRK签名的PIK证书。</para>
    /// </summary>
    public AvbCertCertificate ProductIntermediateKeyCertificate { get; init; } = new();

    /// <summary>
    /// PSK certificate signed by PIK.
    /// <para>由PIK签名的PSK证书。</para>
    /// </summary>
    public AvbCertCertificate ProductSigningKeyCertificate { get; init; } = new();

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = 4 + AvbCertCertificate.Size + AvbCertCertificate.Size;

    /// <summary>
    /// Parses metadata from binary payload.
    /// <para>从二进制有效载荷解析元数据。</para>
    /// </summary>
    public static AvbCertPublicKeyMetadata FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Public key metadata payload must be {Size} bytes.");
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
        var pik = AvbCertCertificate.FromBytes(data.Slice(4, AvbCertCertificate.Size));
        var psk = AvbCertCertificate.FromBytes(data.Slice(4 + AvbCertCertificate.Size, AvbCertCertificate.Size));

        return new AvbCertPublicKeyMetadata
        {
            Version = version,
            ProductIntermediateKeyCertificate = pik,
            ProductSigningKeyCertificate = psk
        };
    }
}

/// <summary>
/// Data structure of libavb_cert unlock challenge.
/// <para>libavb_cert解锁挑战的数据结构。</para>
/// </summary>
public sealed record AvbCertUnlockChallenge
{
    /// <summary>
    /// Current format version, expected to be 1.
    /// <para>当前格式版本，期望为1。</para>
    /// </summary>
    public uint Version { get; init; }

    /// <summary>
    /// SHA-256 digest of product ID.
    /// <para>产品ID的SHA-256摘要。</para>
    /// </summary>
    public byte[] ProductIdHash { get; init; } = [];

    /// <summary>
    /// Random challenge bytes.
    /// <para>随机挑战字节。</para>
    /// </summary>
    public byte[] Challenge { get; init; } = [];

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = 4 + AvbCertConstants.Digest256Size + AvbCertConstants.UnlockChallengeSize;

    /// <summary>
    /// Serializes unlock challenge in libavb_cert layout.
    /// <para>以libavb_cert布局序列化解锁挑战。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        if (ProductIdHash.Length != AvbCertConstants.Digest256Size)
        {
            throw new ArgumentException($"ProductIdHash must be {AvbCertConstants.Digest256Size} bytes.");
        }

        if (Challenge.Length != AvbCertConstants.UnlockChallengeSize)
        {
            throw new ArgumentException($"Challenge must be {AvbCertConstants.UnlockChallengeSize} bytes.");
        }

        var data = new byte[Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Version);
        ProductIdHash.AsSpan().CopyTo(data.AsSpan(4, AvbCertConstants.Digest256Size));
        Challenge.AsSpan().CopyTo(data.AsSpan(4 + AvbCertConstants.Digest256Size, AvbCertConstants.UnlockChallengeSize));
        return data;
    }

    /// <summary>
    /// Parses unlock challenge from binary payload.
    /// <para>从二进制有效载荷解析解锁挑战。</para>
    /// </summary>
    public static AvbCertUnlockChallenge FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Unlock challenge payload must be {Size} bytes.");
        }

        return new AvbCertUnlockChallenge
        {
            Version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4)),
            ProductIdHash = data.Slice(4, AvbCertConstants.Digest256Size).ToArray(),
            Challenge = data.Slice(4 + AvbCertConstants.Digest256Size, AvbCertConstants.UnlockChallengeSize).ToArray()
        };
    }
}

/// <summary>
/// Data structure of libavb_cert unlock credential.
/// <para>libavb_cert解锁凭证的数据结构。</para>
/// </summary>
public sealed record AvbCertUnlockCredential
{
    /// <summary>
    /// Current format version, expected to be 1.
    /// <para>当前格式版本，期望为1。</para>
    /// </summary>
    public uint Version { get; init; }

    /// <summary>
    /// PIK certificate signed by PRK.
    /// <para>由PRK签名的PIK证书。</para>
    /// </summary>
    public AvbCertCertificate ProductIntermediateKeyCertificate { get; init; } = new();

    /// <summary>
    /// PUK certificate signed by PIK.
    /// <para>由PIK签名的PUK证书。</para>
    /// </summary>
    public AvbCertCertificate ProductUnlockKeyCertificate { get; init; } = new();

    /// <summary>
    /// Signature of challenge hash by PUK private key.
    /// <para>由PUK私钥对挑战哈希的签名。</para>
    /// </summary>
    public byte[] ChallengeSignature { get; init; } = [];

    /// <summary>
    /// Serialized size.
    /// <para>序列化大小。</para>
    /// </summary>
    public const int Size = 4 + AvbCertCertificate.Size + AvbCertCertificate.Size + AvbCertConstants.Rsa4096SignatureSize;

    /// <summary>
    /// Serializes unlock credential in libavb_cert layout.
    /// <para>以libavb_cert布局序列化解锁凭证。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        if (ChallengeSignature.Length != AvbCertConstants.Rsa4096SignatureSize)
        {
            throw new ArgumentException($"ChallengeSignature must be {AvbCertConstants.Rsa4096SignatureSize} bytes.");
        }

        var data = new byte[Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), Version);
        ProductIntermediateKeyCertificate.ToBytes().CopyTo(data, 4);
        ProductUnlockKeyCertificate.ToBytes().CopyTo(data, 4 + AvbCertCertificate.Size);
        ChallengeSignature.AsSpan().CopyTo(data.AsSpan(4 + AvbCertCertificate.Size + AvbCertCertificate.Size, AvbCertConstants.Rsa4096SignatureSize));
        return data;
    }

    /// <summary>
    /// Parses unlock credential from binary payload.
    /// <para>从二进制有效载荷解析解锁凭证。</para>
    /// </summary>
    public static AvbCertUnlockCredential FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length != Size)
        {
            throw new ArgumentException($"Unlock credential payload must be {Size} bytes.");
        }

        return new AvbCertUnlockCredential
        {
            Version = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4)),
            ProductIntermediateKeyCertificate = AvbCertCertificate.FromBytes(data.Slice(4, AvbCertCertificate.Size)),
            ProductUnlockKeyCertificate = AvbCertCertificate.FromBytes(data.Slice(4 + AvbCertCertificate.Size, AvbCertCertificate.Size)),
            ChallengeSignature = data.Slice(4 + AvbCertCertificate.Size + AvbCertCertificate.Size, AvbCertConstants.Rsa4096SignatureSize).ToArray()
        };
    }
}

/// <summary>
/// Managed implementation of libavb_cert validation flows.
/// <para>libavb_cert验证流程的托管实现。</para>
/// </summary>
public sealed class AvbCertValidator
{
    // SHA-256("com.google.android.things.vboot")
    private static readonly byte[] CertUsageHashSigning =
    [
        0x75, 0x04, 0x7f, 0xe1, 0x5e, 0xd4, 0x99, 0x80, 0x2d, 0xfd, 0x77, 0x26, 0x00, 0x61, 0x18, 0xef,
        0x5b, 0x06, 0x58, 0x56, 0xf5, 0x9c, 0xa7, 0xf4, 0xdc, 0x63, 0xe7, 0x59, 0xe6, 0x48, 0xf8, 0x16
    ];

    // SHA-256("com.google.android.things.vboot.ca")
    private static readonly byte[] CertUsageHashIntermediateAuthority =
    [
        0x04, 0xec, 0x7c, 0xc7, 0x42, 0x41, 0x76, 0x3b, 0xcc, 0x72, 0xe3, 0x5e, 0xd3, 0x92, 0xdf, 0xd8,
        0x2a, 0x6c, 0x51, 0xae, 0xa8, 0xec, 0x6d, 0x43, 0x27, 0xc7, 0x0d, 0xf4, 0x53, 0x4b, 0x21, 0x5c
    ];

    // SHA-256("com.google.android.things.vboot.unlock")
    private static readonly byte[] CertUsageHashUnlock =
    [
        0x7b, 0x84, 0x6c, 0x4a, 0xfd, 0x85, 0x48, 0x8f, 0x42, 0x9b, 0x7a, 0xcf, 0x93, 0xcf, 0x6a, 0xff,
        0x5c, 0x50, 0x28, 0x1b, 0xbf, 0x9b, 0xd7, 0xb0, 0x18, 0xa5, 0x24, 0x2a, 0x86, 0x0d, 0xe3, 0xf8
    ];

    private readonly byte[] _lastUnlockChallenge = new byte[AvbCertConstants.UnlockChallengeSize];
    private bool _lastUnlockChallengeSet;

    /// <summary>
    /// Validates vbmeta public key using libavb_cert metadata.
    /// <para>使用libavb_cert元数据验证vbmeta公钥。</para>
    /// </summary>
    public AvbIOResult ValidateVBMetaPublicKey(
        IAvbCertOps certOps,
        ReadOnlySpan<byte> publicKeyData,
        ReadOnlySpan<byte> publicKeyMetadata,
        out bool isTrusted)
    {
        isTrusted = false;

        var io = certOps.ReadPermanentAttributes(out var attributes);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        Span<byte> permanentAttributesHash = stackalloc byte[AvbCertConstants.Digest256Size];
        io = certOps.ReadPermanentAttributesHash(permanentAttributesHash);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPermanentAttributes(attributes, permanentAttributesHash))
        {
            return AvbIOResult.Ok;
        }

        if (publicKeyMetadata.Length != AvbCertPublicKeyMetadata.Size)
        {
            return AvbIOResult.Ok;
        }

        var metadata = AvbCertPublicKeyMetadata.FromBytes(publicKeyMetadata);
        if (metadata.Version != 1)
        {
            return AvbIOResult.Ok;
        }

        io = certOps.Ops.ReadRollbackIndex(AvbCertConstants.PikVersionLocation, out var minPikVersion);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPikCertificate(
            metadata.ProductIntermediateKeyCertificate,
            attributes.ProductRootPublicKey,
            minPikVersion))
        {
            return AvbIOResult.Ok;
        }

        io = certOps.Ops.ReadRollbackIndex(AvbCertConstants.PskVersionLocation, out var minPskVersion);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPskCertificate(
            metadata.ProductSigningKeyCertificate,
            metadata.ProductIntermediateKeyCertificate.SignedData.PublicKey,
            minPskVersion,
            attributes.ProductId))
        {
            return AvbIOResult.Ok;
        }

        if (publicKeyData.Length != AvbCertConstants.PublicKeySize)
        {
            return AvbIOResult.Ok;
        }

        if (AvbUtil.SafeMemCmp(metadata.ProductSigningKeyCertificate.SignedData.PublicKey, publicKeyData) != 0)
        {
            return AvbIOResult.Ok;
        }

        certOps.SetKeyVersion(
            AvbCertConstants.PikVersionLocation,
            metadata.ProductIntermediateKeyCertificate.SignedData.KeyVersion);

        certOps.SetKeyVersion(
            AvbCertConstants.PskVersionLocation,
            metadata.ProductSigningKeyCertificate.SignedData.KeyVersion);

        isTrusted = true;
        return AvbIOResult.Ok;
    }

    /// <summary>
    /// Generates unlock challenge to be signed by unlock credentials.
    /// <para>生成由解锁凭证签名的解锁挑战。</para>
    /// </summary>
    public AvbIOResult GenerateUnlockChallenge(IAvbCertOps certOps, out AvbCertUnlockChallenge challenge)
    {
        challenge = new AvbCertUnlockChallenge
        {
            Version = 1,
            ProductIdHash = new byte[AvbCertConstants.Digest256Size],
            Challenge = new byte[AvbCertConstants.UnlockChallengeSize]
        };

        var io = certOps.ReadPermanentAttributes(out var attributes);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        io = certOps.GetRandomBytes(_lastUnlockChallenge);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        _lastUnlockChallengeSet = true;

        var productIdHash = Hash256(attributes.ProductId);
        challenge = challenge with
        {
            ProductIdHash = productIdHash,
            Challenge = _lastUnlockChallenge.ToArray()
        };

        return AvbIOResult.Ok;
    }

    /// <summary>
    /// Validates unlock credential and challenge signature.
    /// <para>验证解锁凭证和挑战签名。</para>
    /// </summary>
    public AvbIOResult ValidateUnlockCredential(
        IAvbCertOps certOps,
        AvbCertUnlockCredential credential,
        out bool isTrusted)
    {
        isTrusted = false;

        if (credential.Version != 1)
        {
            return AvbIOResult.Ok;
        }

        var io = certOps.ReadPermanentAttributes(out var attributes);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        Span<byte> permanentAttributesHash = stackalloc byte[AvbCertConstants.Digest256Size];
        io = certOps.ReadPermanentAttributesHash(permanentAttributesHash);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPermanentAttributes(attributes, permanentAttributesHash))
        {
            return AvbIOResult.Ok;
        }

        io = certOps.Ops.ReadRollbackIndex(AvbCertConstants.PikVersionLocation, out var minPikVersion);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPikCertificate(
            credential.ProductIntermediateKeyCertificate,
            attributes.ProductRootPublicKey,
            minPikVersion))
        {
            return AvbIOResult.Ok;
        }

        io = certOps.Ops.ReadRollbackIndex(AvbCertConstants.PskVersionLocation, out var minPukVersion);
        if (io != AvbIOResult.Ok)
        {
            return io;
        }

        if (!VerifyPukCertificate(
            credential.ProductUnlockKeyCertificate,
            credential.ProductIntermediateKeyCertificate.SignedData.PublicKey,
            minPukVersion,
            attributes.ProductId))
        {
            return AvbIOResult.Ok;
        }

        if (!_lastUnlockChallengeSet)
        {
            return AvbIOResult.Ok;
        }

        var challengeHash = Hash512(_lastUnlockChallenge);
        _lastUnlockChallengeSet = false;

        if (!VerifyRsaSignature(
                credential.ProductUnlockKeyCertificate.SignedData.PublicKey,
                challengeHash,
                credential.ChallengeSignature,
                HashAlgorithmName.SHA512))
        {
            return AvbIOResult.Ok;
        }

        certOps.SetKeyVersion(
            AvbCertConstants.PikVersionLocation,
            credential.ProductIntermediateKeyCertificate.SignedData.KeyVersion);

        certOps.SetKeyVersion(
            AvbCertConstants.PskVersionLocation,
            credential.ProductUnlockKeyCertificate.SignedData.KeyVersion);

        isTrusted = true;
        return AvbIOResult.Ok;
    }

    private static bool VerifyPermanentAttributes(
        AvbCertPermanentAttributes attributes,
        ReadOnlySpan<byte> expectedHash)
    {
        if (attributes.Version != 1)
        {
            return false;
        }

        if (attributes.ProductRootPublicKey.Length != AvbCertConstants.PublicKeySize ||
            attributes.ProductId.Length != AvbCertConstants.ProductIdSize)
        {
            return false;
        }

        var hash = Hash256(attributes.ToBytes());
        return AvbUtil.SafeMemCmp(hash, expectedHash) == 0;
    }

    private static bool VerifyPikCertificate(
        AvbCertCertificate certificate,
        ReadOnlySpan<byte> authority,
        ulong minimumVersion) =>
        VerifyCertificate(
            certificate,
            authority,
            minimumVersion,
            CertUsageHashIntermediateAuthority);

    private static bool VerifyPskCertificate(
        AvbCertCertificate certificate,
        ReadOnlySpan<byte> authority,
        ulong minimumVersion,
        ReadOnlySpan<byte> productId)
    {
        if (!VerifyCertificate(certificate, authority, minimumVersion, CertUsageHashSigning))
        {
            return false;
        }

        var expectedSubject = Hash256(productId);
        return AvbUtil.SafeMemCmp(certificate.SignedData.Subject, expectedSubject) == 0;
    }

    private static bool VerifyPukCertificate(
        AvbCertCertificate certificate,
        ReadOnlySpan<byte> authority,
        ulong minimumVersion,
        ReadOnlySpan<byte> productId)
    {
        if (!VerifyCertificate(certificate, authority, minimumVersion, CertUsageHashUnlock))
        {
            return false;
        }

        var expectedSubject = Hash256(productId);
        return AvbUtil.SafeMemCmp(certificate.SignedData.Subject, expectedSubject) == 0;
    }

    private static bool VerifyCertificate(
        AvbCertCertificate certificate,
        ReadOnlySpan<byte> authority,
        ulong minimumVersion,
        ReadOnlySpan<byte> expectedUsage)
    {
        if (authority.Length != AvbCertConstants.PublicKeySize)
        {
            return false;
        }

        if (certificate.SignedData.Version != 1)
        {
            return false;
        }

        if (certificate.SignedData.PublicKey.Length != AvbCertConstants.PublicKeySize ||
            certificate.SignedData.Subject.Length != AvbCertConstants.Digest256Size ||
            certificate.SignedData.Usage.Length != AvbCertConstants.Digest256Size ||
            certificate.Signature.Length != AvbCertConstants.Rsa4096SignatureSize)
        {
            return false;
        }

        var certificateHash = Hash512(certificate.SignedData.ToBytes());

        if (!VerifyRsaSignature(
                authority,
                certificateHash,
                certificate.Signature,
                HashAlgorithmName.SHA512))
        {
            return false;
        }

        if (certificate.SignedData.KeyVersion < minimumVersion)
        {
            return false;
        }

        return AvbUtil.SafeMemCmp(certificate.SignedData.Usage, expectedUsage) == 0;
    }

    private static bool VerifyRsaSignature(
        ReadOnlySpan<byte> avbSerializedPublicKey,
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        try
        {
            var keyParameters = AvbCrypto.ParseRSAPublicKey(avbSerializedPublicKey);
            using var rsa = RSA.Create();
            rsa.ImportParameters(keyParameters);
            return rsa.VerifyHash(hash.ToArray(), signature.ToArray(), hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Hash256(ReadOnlySpan<byte> data) => AvbCompat.HashData256(data);

    private static byte[] Hash512(ReadOnlySpan<byte> data) => AvbCompat.HashData512(data);
}