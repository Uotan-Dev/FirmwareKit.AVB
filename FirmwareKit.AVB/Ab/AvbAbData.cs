
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace FirmwareKit.AVB;
/// <summary>
/// Contains data about a single slot in the A/B boot flow.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbAbSlotData
{
    /// <summary>The priority of the slot (0-15). A higher value means higher priority.</summary>
    public byte Priority;
    /// <summary>The number of remaining boot attempts (0-7).</summary>
    public byte TriesRemaining;
    /// <summary>Non-zero if the slot has been successfully booted.</summary>
    public byte SuccessfulBoot;
    private readonly byte _reserved;

    /// <summary>The maximum priority value (15).</summary>
    public const byte MaxPriority = 15;
    /// <summary>The maximum number of tries remaining (7).</summary>
    public const byte MaxTriesRemaining = 7;

    /// <summary>Serializes the slot data to a byte span.</summary>
    public readonly void ToBytes(Span<byte> data)
    {
        data[0] = Priority;
        data[1] = TriesRemaining;
        data[2] = SuccessfulBoot;
        data[3] = 0;
    }

    /// <summary>Deserializes the slot data from a byte span.</summary>
    public static AvbAbSlotData FromBytes(ReadOnlySpan<byte> data)
    {
        return new AvbAbSlotData
        {
            Priority = data[0],
            TriesRemaining = data[1],
            SuccessfulBoot = data[2]
        };
    }
}

/// <summary>
/// A/B metadata structure used to track boot slots and their states.
/// Equivalent to 'AvbABData' in libavb_ab.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public record struct AvbAbData
{
    /// <summary>The magic string used to identify A/B metadata ("\0AB0").</summary>
    public const string Magic = "\0AB0";
    /// <summary>Length of the magic string.</summary>
    public const int MagicLen = 4;
    /// <summary>The major version of the A/B metadata format.</summary>
    public const byte MajorVersion = 1;
    /// <summary>The minor version of the A/B metadata format.</summary>
    public const byte MinorVersion = 0;
    /// <summary>The total size of the <see cref="AvbAbData"/> structure (32 bytes).</summary>
    public const int Size = 32;

    /// <summary>The magic bytes.</summary>
    public byte[] MagicBytes; // 4 bytes
    /// <summary>The major version number.</summary>
    public byte VersionMajor;
    /// <summary>The minor version number.</summary>
    public byte VersionMinor;
    private ushort _reserved1;
    /// <summary>Metadata for slot A.</summary>
    public AvbAbSlotData SlotA;
    /// <summary>Metadata for slot B.</summary>
    public AvbAbSlotData SlotB;
    private byte[] _reserved2; // 12 bytes
    /// <summary>CRC32 checksum of the metadata (excluding the CRC32 field itself).</summary>
    public uint Crc32;

    /// <summary>Creates a default A/B metadata structure.</summary>
    public static AvbAbData CreateDefault()
    {
        return new AvbAbData
        {
            MagicBytes = System.Text.Encoding.ASCII.GetBytes(Magic),
            VersionMajor = MajorVersion,
            VersionMinor = MinorVersion,
            SlotA = new AvbAbSlotData { Priority = AvbAbSlotData.MaxPriority, TriesRemaining = AvbAbSlotData.MaxTriesRemaining, SuccessfulBoot = 0 },
            SlotB = new AvbAbSlotData { Priority = AvbAbSlotData.MaxPriority - 1, TriesRemaining = AvbAbSlotData.MaxTriesRemaining, SuccessfulBoot = 0 },
            _reserved2 = new byte[12]
        };
    }

    /// <summary>Serializes the A/B metadata to a byte array and computes the CRC32.</summary>
    public readonly byte[] ToBytes()
    {
        var data = new byte[Size];
        (MagicBytes ?? []).CopyTo(data, 0);
        data[4] = VersionMajor;
        data[5] = VersionMinor;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(6, 2), _reserved1);
        SlotA.ToBytes(data.AsSpan(8, 4));
        SlotB.ToBytes(data.AsSpan(12, 4));
        if (_reserved2 != null && _reserved2.Length >= 12)
        {
            _reserved2.AsSpan(0, 12).CopyTo(data.AsSpan(16, 12));
        }

        // Compute CRC32 for the first 28 bytes
        var crc = AvbCrc32.Compute(data.AsSpan(0, 28));
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28, 4), crc);

        return data;
    }

    /// <summary>Deserializes the A/B metadata from a byte span.</summary>
    public static AvbAbData FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
        {
            throw new ArgumentException("Data too small for AvbAbData");
        }

        var ab = new AvbAbData
        {
            MagicBytes = data[0..4].ToArray(),
            VersionMajor = data[4],
            VersionMinor = data[5],
            _reserved1 = BinaryPrimitives.ReadUInt16BigEndian(data[6..8]),
            SlotA = AvbAbSlotData.FromBytes(data[8..12]),
            SlotB = AvbAbSlotData.FromBytes(data[12..16]),
            _reserved2 = data[16..28].ToArray(),
            Crc32 = BinaryPrimitives.ReadUInt32BigEndian(data[28..32])
        };

        return ab;
    }

    /// <summary>Checks if the A/B metadata is valid (magic and CRC32 match).</summary>
    public readonly bool IsValid()
    {
        if (MagicBytes == null || System.Text.Encoding.ASCII.GetString(MagicBytes) != Magic)
        {
            return false;
        }

        if (VersionMajor > MajorVersion)
        {
            return false;
        }

        var expectedCrc = AvbCrc32.Compute(ToBytes().AsSpan(0, 28));
        return Crc32 == expectedCrc;
    }
}

/// <summary>
/// Provides CRC32 computation consistent with libavb's implementation.
/// </summary>
public static class AvbCrc32
{
    private static byte ReverseByte(byte b)
    {
        uint v = b;
        v = ((v & 0xF) << 4) | (v >> 4);
        v = ((v & 0x33) << 2) | ((v & 0xCC) >> 2);
        v = ((v & 0x55) << 1) | ((v & 0xAA) >> 1);
        return (byte)v;
    }

    private static uint ReverseUInt32(uint v)
    {
        return ((uint)ReverseByte((byte)v) << 24) |
               ((uint)ReverseByte((byte)(v >> 8)) << 16) |
               ((uint)ReverseByte((byte)(v >> 16)) << 8) |
               ReverseByte((byte)(v >> 24));
    }

    /// <summary>
    /// Computes the CRC32 checksum for the specified data buffer.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>The computed CRC32 value.</returns>
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= (uint)ReverseByte(b) << 24;
            for (var i = 0; i < 8; i++)
            {
                if ((crc & 0x80000000u) != 0)
                {
                    crc = (crc << 1) ^ 0x04C11DB7u;
                }
                else
                {
                    crc <<= 1;
                }
            }
        }
        return ReverseUInt32(~crc);
    }
}
