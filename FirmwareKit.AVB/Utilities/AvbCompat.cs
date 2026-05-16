using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FirmwareKit.AVB.Utilities;

/// <summary>
/// Provides compatibility utilities for different .NET versions.
/// <para>为不同的.NET版本提供兼容性工具。</para>
/// </summary>
internal static class AvbCompat
{
    /// <summary>
    /// Converts a byte span to a hexadecimal string.
    /// <para>将字节跨度转换为十六进制字符串。</para>
    /// </summary>
    /// <param name="bytes">The byte span to convert.
    /// <para>要转换的字节跨度。</para></param>
    /// <returns>The hexadecimal string representation.
    /// <para>十六进制字符串表示。</para></returns>
    public static string ToHexString(ReadOnlySpan<byte> bytes)
    {
#if NET5_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        StringBuilder hex = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            hex.Append(b.ToString("x2"));
        }
        return hex.ToString();
#endif
    }

    /// <summary>
    /// Computes the SHA-256 hash of the given data.
    /// <para>计算给定数据的SHA-256哈希值。</para>
    /// </summary>
    /// <param name="data">The data to hash.
    /// <para>要哈希的数据。</para></param>
    /// <returns>The computed hash as a byte array.
    /// <para>计算出的哈希作为字节数组。</para></returns>
    public static byte[] HashData256(ReadOnlySpan<byte> data)
    {
#if NET6_0_OR_GREATER
        return SHA256.HashData(data);
#else
        using var hasher = SHA256.Create();
        return hasher.ComputeHash(data.ToArray());
#endif
    }

    /// <summary>
    /// Computes the SHA-512 hash of the given data.
    /// <para>计算给定数据的SHA-512哈希值。</para>
    /// </summary>
    /// <param name="data">The data to hash.
    /// <para>要哈希的数据。</para></param>
    /// <returns>The computed hash as a byte array.
    /// <para>计算出的哈希作为字节数组。</para></returns>
    public static byte[] HashData512(ReadOnlySpan<byte> data)
    {
#if NET6_0_OR_GREATER
        return SHA512.HashData(data);
#else
        using var hasher = SHA512.Create();
        return hasher.ComputeHash(data.ToArray());
#endif
    }

    /// <summary>
    /// Creates a read-only span from a reference and length.
    /// <para>从引用和长度创建只读跨度。</para>
    /// </summary>
    /// <typeparam name="T">The type of elements in the span.
    /// <para>跨度中元素的类型。</para></typeparam>
    /// <param name="reference">The reference to the first element.
    /// <para>对第一个元素的引用。</para></param>
    /// <param name="length">The number of elements.
    /// <para>元素数量。</para></param>
    /// <returns>A read-only span.
    /// <para>只读跨度。</para></returns>
    public static unsafe ReadOnlySpan<T> CreateReadOnlySpan<T>(ref T reference, int length) where T : unmanaged
    {
#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return MemoryMarshal.CreateReadOnlySpan(ref reference, length);
#else
        fixed (T* ptr = &reference)
        {
            return new ReadOnlySpan<T>(ptr, length);
        }
#endif
    }

    /// <summary>
    /// Creates a mutable span from a reference and length.
    /// <para>从引用和长度创建可变跨度。</para>
    /// </summary>
    /// <typeparam name="T">The type of elements in the span.
    /// <para>跨度中元素的类型。</para></typeparam>
    /// <param name="reference">The reference to the first element.
    /// <para>对第一个元素的引用。</para></param>
    /// <param name="length">The number of elements.
    /// <para>元素数量。</para></param>
    /// <returns>A mutable span.
    /// <para>可变跨度。</para></returns>
    public static unsafe Span<T> CreateSpan<T>(ref T reference, int length) where T : unmanaged
    {
#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        return MemoryMarshal.CreateSpan(ref reference, length);
#else
        fixed (T* ptr = &reference)
        {
            return new Span<T>(ptr, length);
        }
#endif
    }
}