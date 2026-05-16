using FirmwareKit.AVB.Ab;
using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Security;
using System.Buffers.Binary;
using System.Security.Cryptography;
using static FirmwareKit.AVB.Security.AvbCertConstants;

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

    [Fact]
    public void ValidateVBMetaPublicKey_UnsupportedPermanentAttributesVersion_ShouldNotTrust()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var psk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 25,
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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_PermanentAttributesHashMismatch_ShouldNotTrust()
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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOpsWithBadHash(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_UnsupportedMetadataVersion_ShouldNotTrust()
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
        BinaryPrimitives.WriteUInt32LittleEndian(metadata.AsSpan(0, 4), 25);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_BadPIKCert_BadSignature_ShouldNotTrust()
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

        pikCert.Signature[0] ^= 1;

        var pskCert = CreateCertificate(
            authority: pik,
            subjectKey: psk,
            usage: Sha256("com.google.android.things.vboot"),
            subject: SHA256.HashData(productId),
            keyVersion: 7);

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_BadPSKCert_BadSignature_ShouldNotTrust()
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

        pskCert.Signature[0] ^= 1;

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_PSKCertUnexpectedUsage_ShouldNotTrust()
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

        var badUsage = Sha256("com.google.android.things.vboot.ca");
        var pskCert = CreateCertificate(
            authority: pik,
            subjectKey: psk,
            usage: badUsage,
            subject: SHA256.HashData(productId),
            keyVersion: 7);

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_PSKRollback_ShouldNotTrust()
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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 8;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_PIKRollback_ShouldNotTrust()
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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 6;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_FailReadPIKRollbackIndex_ShouldReturnErrorIO()
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

        var ops = new FakeAvbOpsWithFailingRollback(failPik: true, failPsk: false);
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_FailReadPSKRollbackIndex_ShouldReturnErrorIO()
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

        var ops = new FakeAvbOpsWithFailingRollback(failPik: false, failPsk: true);
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_BadPIKCert_ModifiedSubjectPublicKey_ShouldNotTrust()
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

        pikCert.SignedData.PublicKey[0] ^= 1;

        var pskCert = CreateCertificate(
            authority: pik,
            subjectKey: psk,
            usage: Sha256("com.google.android.things.vboot"),
            subject: SHA256.HashData(productId),
            keyVersion: 7);

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_BadPSKCert_ModifiedSubjectPublicKey_ShouldNotTrust()
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

        pskCert.SignedData.PublicKey[0] ^= 1;

        var metadata = BuildMetadata(pikCert, pskCert);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(psk), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateVBMetaPublicKey_PSKMismatch_ShouldNotTrust()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var psk = RSA.Create(4096);
        using var otherKey = RSA.Create(4096);

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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 0;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var result = validator.ValidateVBMetaPublicKey(certOps, ToAvbPublicKey(otherKey), metadata, out var trusted);
        Assert.Equal(AvbIOResult.Ok, result);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_UnsupportedVersion_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 25,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_NoAttributes_ShouldReturnErrorIO()
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
        var certOps = new FakeAvbCertOpsFailingAttributes(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_AttributesHashMismatch_ShouldNotTrust()
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

        var certOps = new FakeAvbCertOpsWithBadHash(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPIKCert_BadSignature_ShouldNotTrust()
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

        pikCert.Signature[0] ^= 1;

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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPUKCert_BadSignature_ShouldNotTrust()
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

        pukCert.Signature[0] ^= 1;

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPUKCert_ModifiedSubjectPublicKey_ShouldNotTrust()
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

        pukCert.SignedData.PublicKey[0] ^= 1;

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_ReplayChallenge_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out var challenge);

        var challengeHash = SHA512.HashData(challenge.Challenge);
        var challengeSignature = puk.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = challengeSignature
        };

        var io1 = validator.ValidateUnlockCredential(certOps, credential, out var trusted1);
        Assert.Equal(AvbIOResult.Ok, io1);
        Assert.True(trusted1);

        var io2 = validator.ValidateUnlockCredential(certOps, credential, out var trusted2);
        Assert.Equal(AvbIOResult.Ok, io2);
        Assert.False(trusted2);
    }

    [Fact]
    public void ValidateUnlockCredential_MultipleUnlock_ShouldTrustBoth()
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

        validator.GenerateUnlockChallenge(certOps, out var challenge1);
        var sig1 = puk.SignHash(SHA512.HashData(challenge1.Challenge), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        var cred1 = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = sig1
        };

        var io1 = validator.ValidateUnlockCredential(certOps, cred1, out var trusted1);
        Assert.Equal(AvbIOResult.Ok, io1);
        Assert.True(trusted1);

        validator.GenerateUnlockChallenge(certOps, out var challenge2);
        var sig2 = puk.SignHash(SHA512.HashData(challenge2.Challenge), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        var cred2 = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = sig2
        };

        var io2 = validator.ValidateUnlockCredential(certOps, cred2, out var trusted2);
        Assert.Equal(AvbIOResult.Ok, io2);
        Assert.True(trusted2);
    }

    [Fact]
    public void ValidateUnlockCredential_BadChallengeSignature_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var badSignature = new byte[AvbCertConstants.Rsa4096SignatureSize];
        badSignature[10] ^= 1;

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = badSignature
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PUKCertUnexpectedUsage_ShouldNotTrust()
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
            usage: Sha256("com.google.android.things.vboot"),
            subject: SHA256.HashData(productId),
            keyVersion: 11);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PUKRollback_ShouldNotTrust()
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
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 12;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_NoAttributesHash_ShouldReturnErrorIO()
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
        var certOps = new FakeAvbCertOpsFailingAttributesHash(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_UnsupportedAttributesVersion_ShouldNotTrust()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var puk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 25,
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_FailReadPIKRollbackIndex_ShouldReturnErrorIO()
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

        var ops = new FakeAvbOpsWithFailingRollback(true, false);
        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_FailReadPSKRollbackIndex_ShouldReturnErrorIO()
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

        var ops = new FakeAvbOpsWithFailingRollback(false, true);
        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.ErrorIo, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_UnsupportedPIKCertificateVersion_ShouldNotTrust()
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

        var pikSignedData = new AvbCertCertificateSignedData
        {
            Version = 25,
            PublicKey = ToAvbPublicKey(pik),
            Subject = new byte[AvbCertConstants.Digest256Size],
            Usage = Sha256("com.google.android.things.vboot.ca"),
            KeyVersion = 9
        };

        var pikSignedDataBytes = pikSignedData.ToBytes();
        var pikSignature = prk.SignHash(SHA512.HashData(pikSignedDataBytes), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var pikCert = new AvbCertCertificate
        {
            SignedData = pikSignedData,
            Signature = pikSignature
        };

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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPIKCert_ModifiedSubject_ShouldNotTrust()
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

        pikCert.SignedData.Subject[0] ^= 1;

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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPIKCert_ModifiedUsage_ShouldNotTrust()
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

        pikCert.SignedData.Usage[0] ^= 1;

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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPIKCert_ModifiedKeyVersion_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var modifiedPikCert = pikCert with { SignedData = pikCert.SignedData with { KeyVersion = pikCert.SignedData.KeyVersion ^ 1 } };

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = modifiedPikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PIKCertSubjectIgnored_ShouldTrust()
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

        var subject = new byte[AvbCertConstants.Digest256Size];
        subject[0] ^= 1;

        var pikCert = CreateCertificate(
            authority: prk,
            subjectKey: pik,
            usage: Sha256("com.google.android.things.vboot.ca"),
            subject: subject,
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

        validator.GenerateUnlockChallenge(certOps, out var challenge);

        var challengeHash = SHA512.HashData(challenge.Challenge);
        var challengeSignature = puk.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = challengeSignature
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.True(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PIKCertUnexpectedUsage_ShouldNotTrust()
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
            usage: Sha256("com.google.android.things.vboot"),
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PIKRollback_ShouldNotTrust()
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
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 10;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 0;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_UnsupportedPUKCertificateVersion_ShouldNotTrust()
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

        var pukSignedData = new AvbCertCertificateSignedData
        {
            Version = 25,
            PublicKey = ToAvbPublicKey(puk),
            Subject = SHA256.HashData(productId),
            Usage = Sha256("com.google.android.things.vboot.unlock"),
            KeyVersion = 11
        };

        var pukSignedDataBytes = pukSignedData.ToBytes();
        var pukSignature = pik.SignHash(SHA512.HashData(pukSignedDataBytes), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var pukCert = new AvbCertCertificate
        {
            SignedData = pukSignedData,
            Signature = pukSignature
        };

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPUKCert_ModifiedSubject_ShouldNotTrust()
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

        pukCert.SignedData.Subject[0] ^= 1;

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPUKCert_ModifiedUsage_ShouldNotTrust()
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

        pukCert.SignedData.Usage[0] ^= 1;

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_BadPUKCert_ModifiedKeyVersion_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var modifiedPukCert = pukCert with { SignedData = pukCert.SignedData with { KeyVersion = pukCert.SignedData.KeyVersion ^ 1 } };

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = modifiedPukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_PUKCertUnexpectedSubject_ShouldNotTrust()
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

        var unexpectedSubject = SHA256.HashData(productId);
        unexpectedSubject[0] ^= 1;

        var pukCert = CreateCertificate(
            authority: pik,
            subjectKey: puk,
            usage: Sha256("com.google.android.things.vboot.unlock"),
            subject: unexpectedSubject,
            keyVersion: 11);

        var ops = new FakeAvbOps();
        ops.RollbackIndexes[AvbCertConstants.PikVersionLocation] = 1;
        ops.RollbackIndexes[AvbCertConstants.PskVersionLocation] = 1;

        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        validator.GenerateUnlockChallenge(certOps, out _);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = new byte[AvbCertConstants.Rsa4096SignatureSize]
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_ChallengeMismatch_ShouldNotTrust()
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

        validator.GenerateUnlockChallenge(certOps, out _);

        var badChallenge = new byte[AvbCertConstants.UnlockChallengeSize];
        badChallenge[0] = 0xFF;
        var challengeHash = SHA512.HashData(badChallenge);
        var challengeSignature = puk.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pukCert,
            ChallengeSignature = challengeSignature
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void ValidateUnlockCredential_UnlockWithPSK_ShouldNotTrust()
    {
        using var prk = RSA.Create(4096);
        using var pik = RSA.Create(4096);
        using var psk = RSA.Create(4096);
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

        var pskCert = CreateCertificate(
            authority: pik,
            subjectKey: psk,
            usage: Sha256("com.google.android.things.vboot"),
            subject: SHA256.HashData(productId),
            keyVersion: 7);

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

        validator.GenerateUnlockChallenge(certOps, out var challenge);

        var challengeHash = SHA512.HashData(challenge.Challenge);
        var challengeSignature = psk.SignHash(challengeHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        var credential = new AvbCertUnlockCredential
        {
            Version = 1,
            ProductIntermediateKeyCertificate = pikCert,
            ProductUnlockKeyCertificate = pskCert,
            ChallengeSignature = challengeSignature
        };

        var io = validator.ValidateUnlockCredential(certOps, credential, out var trusted);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.False(trusted);
    }

    [Fact]
    public void GenerateUnlockChallenge_BasicTest_ShouldSucceed()
    {
        using var prk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 1,
            ProductRootPublicKey = ToAvbPublicKey(prk),
            ProductId = productId
        };

        var ops = new FakeAvbOps();
        var certOps = new FakeAvbCertOps(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var io = validator.GenerateUnlockChallenge(certOps, out var challenge);
        Assert.Equal(AvbIOResult.Ok, io);
        Assert.Equal(1U, challenge.Version);
        Assert.NotEqual(new byte[AvbCertConstants.UnlockChallengeSize], challenge.Challenge);

        var expectedPidHash = SHA256.HashData(productId);
        Assert.Equal(expectedPidHash, challenge.ProductIdHash);
    }

    [Fact]
    public void GenerateUnlockChallenge_NoRNG_ShouldReturnError()
    {
        using var prk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 1,
            ProductRootPublicKey = ToAvbPublicKey(prk),
            ProductId = productId
        };

        var ops = new FakeAvbOps();
        var certOps = new FakeAvbCertOpsFailingRng(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var io = validator.GenerateUnlockChallenge(certOps, out var challenge);
        Assert.NotEqual(AvbIOResult.Ok, io);
    }

    [Fact]
    public void GenerateUnlockChallenge_NoAttributes_ShouldReturnErrorIO()
    {
        using var prk = RSA.Create(4096);

        var productId = new byte[AvbCertConstants.ProductIdSize];
        RandomNumberGenerator.Fill(productId);

        var permanentAttributes = new AvbCertPermanentAttributes
        {
            Version = 1,
            ProductRootPublicKey = ToAvbPublicKey(prk),
            ProductId = productId
        };

        var ops = new FakeAvbOps();
        var certOps = new FakeAvbCertOpsFailingAttributes(ops, permanentAttributes);
        var validator = new AvbCertValidator();

        var io = validator.GenerateUnlockChallenge(certOps, out var challenge);
        Assert.NotEqual(AvbIOResult.Ok, io);
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

    private sealed class FakeAvbCertOps(IAvbOps ops, AvbCertPermanentAttributes attributes) : IAvbCertOps
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

    private sealed class FakeAvbCertOpsWithBadHash(IAvbOps ops, AvbCertPermanentAttributes attributes) : IAvbCertOps
    {
        public IAvbOps Ops => ops;

        public Dictionary<int, ulong> ReportedVersions { get; } = [];

        public AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes outAttributes)
        {
            outAttributes = attributes;
            return AvbIOResult.Ok;
        }

        public AvbIOResult ReadPermanentAttributesHash(Span<byte> hash)
        {
            hash.Fill(0xBB);
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

    private sealed class FakeAvbCertOpsFailingAttributes : IAvbCertOps
    {
        private readonly IAvbOps _ops;

        public FakeAvbCertOpsFailingAttributes(IAvbOps ops, AvbCertPermanentAttributes _)
        {
            _ops = ops;
        }

        public IAvbOps Ops => _ops;

        public Dictionary<int, ulong> ReportedVersions { get; } = [];

        public AvbIOResult ReadPermanentAttributes(out AvbCertPermanentAttributes outAttributes)
        {
            outAttributes = new AvbCertPermanentAttributes();
            return AvbIOResult.ErrorIo;
        }

        public AvbIOResult ReadPermanentAttributesHash(Span<byte> hash)
        {
            hash.Clear();
            return AvbIOResult.ErrorIo;
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

    private sealed class FakeAvbCertOpsFailingAttributesHash(IAvbOps ops, AvbCertPermanentAttributes attributes) : IAvbCertOps
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
            hash.Clear();
            return AvbIOResult.ErrorIo;
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

    private sealed class FakeAvbCertOpsFailingRng(IAvbOps ops, AvbCertPermanentAttributes attributes) : IAvbCertOps
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
            return AvbIOResult.ErrorIo;
        }
    }

    private sealed class FakeAvbOpsWithFailingRollback : IAvbOps
    {
        private readonly bool _failPik;
        private readonly bool _failPsk;

        public FakeAvbOpsWithFailingRollback(bool failPik, bool failPsk)
        {
            _failPik = failPik;
            _failPsk = failPsk;
        }

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
            if (_failPik && rollbackIndexLocation == AvbCertConstants.PikVersionLocation)
            {
                rollbackIndex = 0;
                return AvbIOResult.ErrorIo;
            }
            if (_failPsk && rollbackIndexLocation == AvbCertConstants.PskVersionLocation)
            {
                rollbackIndex = 0;
                return AvbIOResult.ErrorIo;
            }
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
