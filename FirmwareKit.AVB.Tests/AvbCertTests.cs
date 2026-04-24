using System.Buffers.Binary;
using System.Security.Cryptography;
using static FirmwareKit.AVB.AvbCertConstants;

namespace FirmwareKit.AVB.Tests;

public class AvbCertTests
{
    [Fact]
    public void UnlockChallenge_BinaryRoundTrip_ShouldPreserveFields()
    {
        var productHash = new byte[Digest256Size];
        var challenge = new byte[UnlockChallengeSize];
        RandomNumberGenerator.Fill(productHash);
        RandomNumberGenerator.Fill(challenge);

        var source = new AvbCertUnlockChallenge
        {
            Version = 1,
            ProductIdHash = productHash,
            Challenge = challenge
        };

        var bytes = source.ToBytes();
        var parsed = AvbCertUnlockChallenge.FromBytes(bytes);

        Assert.Equal(AvbCertUnlockChallenge.Size, bytes.Length);
        Assert.Equal(source.Version, parsed.Version);
        Assert.Equal(source.ProductIdHash, parsed.ProductIdHash);
        Assert.Equal(source.Challenge, parsed.Challenge);
    }

    [Fact]
    public void UnlockCredential_BinaryRoundTrip_ShouldPreserveFields()
    {
        using var authority = RSA.Create(4096);
        using var subjectA = RSA.Create(4096);
        using var subjectB = RSA.Create(4096);

        var certA = CreateCertificate(
            authority: authority,
            subjectKey: subjectA,
            usage: Sha256("com.google.android.things.vboot.ca"),
            subject: new byte[Digest256Size],
            keyVersion: 1);

        var certB = CreateCertificate(
            authority: subjectA,
            subjectKey: subjectB,
            usage: Sha256("com.google.android.things.vboot.unlock"),
            subject: Sha256("subject"),
            keyVersion: 2);

        var signature = new byte[Rsa4096SignatureSize];
        RandomNumberGenerator.Fill(signature);

        var source = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = certA,
            ProductUnlockKeyCertificate = certB,
            ChallengeSignature = signature
        };

        var bytes = source.ToBytes();
        var parsed = AvbCertUnlockCredential.FromBytes(bytes);

        Assert.Equal(AvbCertUnlockCredential.Size, bytes.Length);
        Assert.Equal(source.Version, parsed.Version);
        Assert.Equal(source.ProductIntermediateKeyCertificate.SignedData.KeyVersion, parsed.ProductIntermediateKeyCertificate.SignedData.KeyVersion);
        Assert.Equal(source.ProductUnlockKeyCertificate.SignedData.KeyVersion, parsed.ProductUnlockKeyCertificate.SignedData.KeyVersion);
        Assert.Equal(source.ChallengeSignature, parsed.ChallengeSignature);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_ShouldTrustValidChain()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var psk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 1,
            ProductRootPublicKey = ToAvbPublicKey(prk),
            ProductId = productId
        };

        var pikCert = CreateCertificate(
            authority: prk,
            subjectKey: pik,
            usage: Sha256("com.google.android.things.vboot.ca"),
            subject: new byte[AvbCertConstants.Digest256Size],
            keyVersion: 5);

        var pskCert = CreateCertificate(
            authority: pik,
            subjectKey: psk,
            usage: Sha256("com.google.android.things.vboot"),
            subject: SHA256.HashData(productId),
            keyVersion: 7);

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(
            certOps,
            ToAvbPublicKey(psk),
            metadata,
            out var trusted);

        Assert.Equal(AvbIOResult.Ok, result);
        Assert.True(trusted);
        Assert.Equal((ulong)5, certOps.ReportedVersions[AvbCertConstants.PikVersionLocation]);
        Assert.Equal((ulong)7, certOps.ReportedVersions[AvbCertConstants.PskVersionLocation]);
    }

    [Fact]
    public void ValidateUnlockCredential_ShouldTrustCredentialForGeneratedChallenge()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var puk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 1,
            ProductRootPublicKey = ToAvbPublicKey(prk),
            ProductId = productId
        };

        var pikCert = CreateCertificate(
            authority: prk,
            subjectKey: pik,
            usage: Sha256("com.google.android.things.vboot.ca"),
            subject: new byte[AvbCertConstants.Digest256Size],
            keyVersion: 9);

        var pukCert = CreateCertificate(
            authority: pik,
            subjectKey: puk,
            usage: Sha256("com.google.android.things.vboot.unlock"),
            subject: SHA256.HashData(productId),
            keyVersion: 11);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var challengeIo = validator.GenerateUnlockChallenge(certOps, out var challenge);
        Assert.Equal(AvbIOResult.Ok, challengeIo);
        Assert.Equal(1u, challenge.Version);

        var challengeHash = SHA512.HashData(challenge.Challenge);
        var challengeSignature = puk.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = challengeSignature
        };

        var validateIo = validator.ValidateUnlockCredential(certOps, credential, out var trusted);

        Assert.Equal(AvbIOResult.Ok, validateIo);
        Assert.True(trusted);
        Assert.Equal((ulong)9, certOps.ReportedVersions[AvbCertConstants.PikVersionLocation]);
        Assert.Equal((ulong)11, certOps.ReportedVersions[AvbCertConstants.PskVersionLocation]);
    }

    private static byte[] BuildMetadata(AvbCertCertificate pikCert, AvbCertCertificate pskCert)
    {
        var data = new byte[AvbCertPublicKeyMetadata.Size];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 1);
        pikCert.ToBytes().CopyTo(data, 4);
        pskCert.ToBytes().CopyTo(data, 4 + AvbCertCertificate.Size);
        return data;
    }

    private static AvbCertCertificate CreateCertificate(
        RSA authority,
        RSA subjectKey,
        byte[] usage,
        byte[] subject,
        ulong keyVersion)
    {
        var signedData = new AvbCertCertificateSignedData
        {
            Version = 1,
            PublicKey = ToAvbPublicKey(subjectKey),
            Subject = subject,
            Usage = usage,
            KeyVersion = keyVersion
        };

        var signedDataBytes = signedData.ToBytes();
        var signature = authority.SignHash(SHA512.HashData(signedDataBytes), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        return new AvbCertCertificate
        {
            SignedData = signedData,
            Signature = signature
        };
    }

    private static byte[] ToAvbPublicKey(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        if (p.Modulus == null)
        {
            throw new InvalidOperationException("Missing modulus");
        }

        var modulus = p.Modulus;
        if (modulus.Length > 512)
        {
            throw new InvalidOperationException("Unexpected modulus length");
        }

        if (modulus.Length < 512)
        {
            var padded = new byte[512];
            modulus.CopyTo(padded, 512 - modulus.Length);
            modulus = padded;
        }

        var data = new byte[AvbCertConstants.PublicKeySize];
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0, 4), 4096);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4, 4), 0);
        modulus.CopyTo(data, 8);
        // rr (512 bytes) left as zero for tests; parser ignores rr for verification path.
        return data;
    }

    private static byte[] Sha256(string input) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(input));

    private sealed class FakeAvbCertOps(FakeAvbOps ops, AvbCertPermanentAttributes attributes) : IAvbCertOps
    {
        private readonly byte[] _permanentAttributesHash = SHA256.HashData(attributes.ToBytes());

        public IAvbOps Ops => ops;

        public Dictionary<int, ulong> ReportedVersions { get; } = [];

        public AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes outAttributes)
        {
            outAttributes = attributes;
            return AvbIOResult.Ok;
        }

        public AvbIOResult ReadPermanentAttributesHash(Span<byte> hash)
        {
            _permanentAttributesHash.CopyTo(hash);
            return AvbIOResult.Ok;
        }

        public void SetKeyVersion(int rollbackIndexLocation, ulong keyVersion)
        {
            ReportedVersions[rollbackIndexLocation] = keyVersion;
        }

        public AvbIOResult GetRandomBytes(Span<byte> output)
        {
            RandomNumberGenerator.Fill(output);
            return AvbIOResult.Ok;
        }
    }

    private sealed class FakeAvbOps : IAvbOps
    {
        public Dictionary<int, ulong> RollbackIndexes { get; } = [];

        public AvbIOResult ReadFromPartition(string partitionName, long offset, int numBytes, Span<byte> buffer, out int bytesRead)
        {
            bytesRead = 0;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult WriteToPartition(string partitionName, long offset, int numBytes, ReadOnlySpan<byte> buffer) => AvbIOResult.ErrorNoSuchPartition;

        public AvbIOResult ValidateVBMetaPublicKey(ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isValid)
        {
            isValid = false;
            return AvbIOResult.ErrorIo;
        }

        public AvbIOResult ReadRollbackIndex(int rollbackIndexLocation, out ulong rollbackIndex)
        {
            rollbackIndex = RollbackIndexes.TryGetValue(rollbackIndexLocation, out var value) ? value : 0;
            return AvbIOResult.Ok;
        }

        public AvbIOResult WriteRollbackIndex(int rollbackIndexLocation, ulong rollbackIndex)
        {
            RollbackIndexes[rollbackIndexLocation] = rollbackIndex;
            return AvbIOResult.Ok;
        }

        public AvbIOResult ReadIsDeviceUnlocked(out bool isUnlocked)
        {
            isUnlocked = false;
            return AvbIOResult.Ok;
        }

        public AvbIOResult GetUniqueGuidForPartition(string partitionName, out string guid)
        {
            guid = string.Empty;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult GetSizeOfPartition(string partitionName, out long size)
        {
            size = 0;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult GetPreloadedPartition(string partitionName, int numBytes, out ReadOnlySpan<byte> preloadedData)
        {
            preloadedData = ReadOnlySpan<byte>.Empty;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult ReadPersistentValue(string name, int bufferSize, Span<byte> outBuffer, out int outBytesRead)
        {
            outBytesRead = 0;
            return AvbIOResult.ErrorNoSuchValue;
        }

        public AvbIOResult WritePersistentValue(string name, int valueSize, ReadOnlySpan<byte> value) => AvbIOResult.Ok;

        public AvbIOResult ValidatePublicKeyForPartition(string partition, ReadOnlySpan<byte> publicKeyData, ReadOnlySpan<byte> publicKeyMetadata, out bool isTrusted, out uint rollbackIndexLocation)
        {
            isTrusted = false;
            rollbackIndexLocation = 0;
            return AvbIOResult.ErrorIo;
        }

        public AvbIOResult ReadAbMetadata(out AvbAbData data)
        {
            data = default;
            return AvbIOResult.ErrorNoSuchPartition;
        }

        public AvbIOResult WriteAbMetadata(AvbAbData data) => AvbIOResult.ErrorNoSuchPartition;
    }
}
