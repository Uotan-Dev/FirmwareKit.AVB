using System.Buffers.Binary;

namespace FirmwareKit.AVB.Security;

/// <summary>
/// Managed representation of AVB serialized RSA public key header.
/// Layout: key_num_bits (be), n0inv (be).
/// <para>AVB序列化RSA公钥头的托管表示。</para>
/// <para>布局：key_num_bits (be), n0inv (be)。</para>
/// </summary>
public readonly record struct AvbRsaPublicKeyHeader
{
    /// <summary>
    /// Serialized header size in bytes.
    /// <para>序列化头的字节大小。</para>
    /// </summary>
    public const int Size = 8;

    /// <summary>
    /// RSA modulus size in bits.
    /// <para>RSA模数大小（以位为单位）。</para>
    /// </summary>
    public uint KeyNumBits { get; init; }

    /// <summary>
    /// Montgomery parameter n0inv.
    /// <para>蒙哥马利参数n0inv。</para>
    /// </summary>
    public uint N0Inv { get; init; }

    /// <summary>
    /// Gets a value indicating whether the header is structurally valid.
    /// <para>获取一个值，指示头在结构上是否有效。</para>
    /// </summary>
    public bool IsValid
    {
        get
        {
            if ((KeyNumBits % 8) != 0)
            {
                return false;
            }

            if (KeyNumBits is not (2048 or 4096 or 8192))
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Deserializes an AVB RSA public key header from bytes.
    /// <para>从字节反序列化AVB RSA公钥头。</para>
    /// </summary>
    public static AvbRsaPublicKeyHeader FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException("Data too small for AvbRsaPublicKeyHeader.");
        }

        return new AvbRsaPublicKeyHeader
        {
            KeyNumBits = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(0, 4)),
            N0Inv = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(4, 4))
        };
    }

    /// <summary>
    /// Attempts to deserialize and validate an AVB RSA public key header.
    /// <para>尝试反序列化并验证AVB RSA公钥头。</para>
    /// </summary>
    public static bool TryFromBytes(ReadOnlySpan<byte> data, out AvbRsaPublicKeyHeader header)
    {
        header = default;
        if (data.Length < Size)
        {
            return false;
        }

        try
        {
            header = FromBytes(data);
            return header.IsValid;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Serializes the header to bytes.
    /// <para>将头序列化为字节。</para>
    /// </summary>
    public byte[] ToBytes()
    {
        var bytes = new byte[Size];
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(0, 4), KeyNumBits);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4, 4), N0Inv);
        return bytes;
    }
}