namespace LibAVBSharp.Tests;

public class AvbCryptoTests
{
    [Fact]
    public void Sha256()
    {
        /* Compare with
         * $ echo -n foobar |sha256sum
         * c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 -
         */
        var data = "foobar"u8;
        var hash = AvbCrypto.CalculateHash(AvbAlgorithmType.Sha256Rsa2048, data);
        Assert.Equal("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", AvbUtil.Bin2Hex(hash));
    }

    [Fact]
    public void Sha512()
    {
        /* Compare with
         * $ echo -n foobar |sha512sum
         * 0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425
         * -
         */
        var data = "foobar"u8;
        var hash = AvbCrypto.CalculateHash(AvbAlgorithmType.Sha512Rsa4096, data);
        Assert.Equal("0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425", AvbUtil.Bin2Hex(hash));
    }
}