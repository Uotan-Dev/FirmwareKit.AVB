using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FirmwareKit.AVB;

/// <summary>
/// Constants used by libavb_cert compatible flows.
/// </summary>
public static class AvbCertConstants
{
    /// <summary>Rollback index location for Product Intermediate Key (PIK) version.</summary>
    public const int PikVersionLocation = 0x1000;

    /// <summary>Rollback index location for Product Signing/Unlock Key (PSK/PUK) version.</summary>
    public const int PskVersionLocation = 0x1001;

    /// <summary>Size in bytes of product ID.</summary>
    public const int ProductIdSize = 16;

    /// <summary>Size in bytes of unlock challenge.</summary>
    public const int UnlockChallengeSize = 16;

    /// <summary>Size in bytes of AVB serialized RSA4096 public key.</summary>
    public const int PublicKeySize = 8 + 1024;

    /// <summary>Size in bytes of SHA-256 digest.</summary>
    public const int Digest256Size = 32;

    /// <summary>Size in bytes of SHA-512 digest.</summary>
    public const int Digest512Size = 64;
    /// <summary>Size in bytes of RSA-4096 PKCS#1 v1.5 signature.</summary>
    public const int Rsa4096SignatureSize = 512;
}

/// <summary>
/// Certificate-related platform operations for managed AVB cert validation.
/// </summary>
public interface IAvbCertOps
{
    /// <summary>
    /// Gets the AVB platform ops used for rollback index access.
    /// </summary>
    IAvbOps Ops { get; }

    /// <summary>
    /// Reads permanent attributes.
    /// </summary>
    AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes attributes);

    /// <summary>
    /// Reads permanent attributes hash (SHA-256).
    /// </summary>
    AvbIOResult ReadPermanentAttributesHash(Span<byte> hash);

    /// <summary>
    /// Reports key version used during successful validation.
    /// </summary>
    void SetKeyVersion(int rollbackIndexLocation, ulong keyVersion);

    /// <summary>
    /// Fills output with cryptographically secure random bytes.
    /// </summary>
    AvbIOResult GetRandomBytes(Span<byte> output);
}

/// <summary>
/// Data structure of libavb_cert permanent attributes.
/// </summary>
public sealed record AvbCertPermanentAttributes
{
    /// <summary>Current format version, expected to be 1.</summary>
    public uint Version { get; init; }

    /// <summary>Product root public key (AVB serialized RSA4096 key).</summary>
    public byte[] ProductRootPublicKey { get; init; } = [];

    /// <summary>Product ID.</summary>
    public byte[] ProductId { get; init; } = [];

    /// <summary>Serialized size.</summary>
    public const int Size = 4 + AvbCertConstants.PublicKeySize + AvbCertConstants.ProductIdSize;

    /// <summary>
    /// Serializes the structure in libavb_cert binary layout.
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
/// </summary>
public sealed record AvbCertCertificateSignedData
{
    /// <summary>Current format version, expected to be 1.</summary>
    public uint Version { get; init; }

    /// <summary>Certified public key (AVB serialized RSA4096 key).</summary>
    public byte[] PublicKey { get; init; } = [];

    /// <summary>Subject field (SHA-256 digest).</summary>
    public byte[] Subject { get; init; } = [];

    /// <summary>Usage field (SHA-256 digest of usage string).</summary>
    public byte[] Usage { get; init; } = [];

    /// <summary>Monotonic key version.</summary>
    public ulong KeyVersion { get; init; }

    /// <summary>Serialized size.</summary>
    public const int Size = 4 + AvbCertConstants.PublicKeySize + AvbCertConstants.Digest256Size + AvbCertConstants.Digest256Size + 8;

    /// <summary>
    /// Serializes structure in libavb_cert binary layout.
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
/// </summary>
public sealed record AvbCertCertificate
{
    /// <summary>Signed certificate fields.</summary>
    public AvbCertCertificateSignedData SignedData { get; init; } = new();

    /// <summary>RSA4096 signature over SHA-512 hash of signed data.</summary>
    public byte[] Signature { get; init; } = [];

    /// <summary>Serialized size.</summary>
    public const int Size = AvbCertCertificateSignedData.Size + AvbCertConstants.Rsa4096SignatureSize;

    /// <summary>
    /// Serializes certificate.
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
/// </summary>
public sealed record AvbCertPublicKeyMetadata
{
    /// <summary>Current format version, expected to be 1.</summary>
    public uint Version { get; init; }

    /// <summary>PIK certificate signed by PRK.</summary>
    public AvbCertCertificate ProductIntermediateKeyCertificate { get; init; } = new();

    /// <summary>PSK certificate signed by PIK.</summary>
    public AvbCertCertificate ProductSigningKeyCertificate { get; init; } = new();

    /// <summary>Serialized size.</summary>
    public const int Size = 4 + AvbCertCertificate.Size + AvbCertCertificate.Size;

    /// <summary>
    /// Parses metadata from binary payload.
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
/// </summary>
public sealed record AvbCertUnlockChallenge
{
    /// <summary>Current format version, expected to be 1.</summary>
    public uint Version { get; init; }

    /// <summary>SHA-256 digest of product ID.</summary>
    public byte[] ProductIdHash { get; init; } = [];

    /// <summary>Random challenge bytes.</summary>
    public byte[] Challenge { get; init; } = [];

    /// <summary>Serialized size.</summary>
    public const int Size = 4 + AvbCertConstants.Digest256Size + AvbCertConstants.UnlockChallengeSize;

    /// <summary>
    /// Serializes unlock challenge in libavb_cert layout.
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
/// </summary>
public sealed record AvbCertUnlockCredential
{
    /// <summary>Current format version, expected to be 1.</summary>
    public uint Version { get; init; }

    /// <summary>PIK certificate signed by PRK.</summary>
    public AvbCertCertificate ProductIntermediateKeyCertificate { get; init; } = new();

    /// <summary>PUK certificate signed by PIK.</summary>
    public AvbCertCertificate ProductUnlockKeyCertificate { get; init; } = new();

    /// <summary>Signature of challenge hash by PUK private key.</summary>
    public byte[] ChallengeSignature { get; init; } = [];

    /// <summary>Serialized size.</summary>
    public const int Size = 4 + AvbCertCertificate.Size + AvbCertCertificate.Size + AvbCertConstants.Rsa4096SignatureSize;

    /// <summary>
    /// Serializes unlock credential in libavb_cert layout.
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
