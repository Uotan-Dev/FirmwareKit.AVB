using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FirmwareKit.AVB;

internal static class AvbCompat
{
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

    public static byte[] HashData256(ReadOnlySpan<byte> data)
    {
#if NET6_0_OR_GREATER
        return SHA256.HashData(data);
#else
        using var hasher = SHA256.Create();
        return hasher.ComputeHash(data.ToArray());
#endif
    }

    public static byte[] HashData512(ReadOnlySpan<byte> data)
    {
#if NET6_0_OR_GREATER
        return SHA512.HashData(data);
#else
        using var hasher = SHA512.Create();
        return hasher.ComputeHash(data.ToArray());
#endif
    }

    public static unsafe ReadOnlySpan<T> CreateReadOnlySpanReadOnly<T>(ref T reference, int length) where T : unmanaged
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
}
