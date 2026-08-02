namespace FirmwareKit.AVB.Fec;

/// <summary>
/// dm-verity Forward Error Correction (FEC) support: Reed-Solomon parity
/// generation over GF(2^8) using the same parameters and on-disk layout as
/// AOSP system/extras/libfec (fec_ecc_interleave / fec_ecc_get_size) and the
/// avbtool 'fec' tool. The Reed-Solomon core is a direct port of Phil Karn's
/// init_rs_char()/encode_rs_char() with parameters FEC_PARAMS(roots), i.e.
/// init_rs_char(8, 0x11d, 0, 1, roots, 0).
/// <para>dm-verity前向纠错（FEC）支持：基于GF(2^8)的Reed-Solomon奇偶校验生成，
/// 参数与磁盘布局同AOSP system/extras/libfec（fec_ecc_interleave /
/// fec_ecc_get_size）及avbtool的'fec'工具一致。Reed-Solomon核心为Phil Karn
/// 的init_rs_char()/encode_rs_char()的直接移植，参数为FEC_PARAMS(roots)，即
/// init_rs_char(8, 0x11d, 0, 1, roots, 0)。</para>
/// </summary>
public static class AvbFec
{
    /// <summary>
    /// Reed-Solomon codeword symbol count (FEC_RSM).
    /// <para>Reed-Solomon码字符号数（FEC_RSM）。</para>
    /// </summary>
    public const int FecRsm = 255;

    /// <summary>
    /// FEC block size in bytes (FEC_BLOCKSIZE).
    /// <para>FEC块大小（字节）（FEC_BLOCKSIZE）。</para>
    /// </summary>
    public const int FecBlockSize = 4096;

    /// <summary>
    /// Magic value of the FEC header (FEC_MAGIC), little-endian.
    /// <para>FEC头的魔数（FEC_MAGIC），小端。</para>
    /// </summary>
    public const uint FecMagic = 0xFECFECFE;

    /// <summary>
    /// FEC header version (FEC_VERSION).
    /// <para>FEC头版本（FEC_VERSION）。</para>
    /// </summary>
    public const uint FecVersion = 0;

    /// <summary>
    /// Default number of Reed-Solomon roots (FEC_DEFAULT_ROOTS).
    /// <para>默认的Reed-Solomon根数（FEC_DEFAULT_ROOTS）。</para>
    /// </summary>
    public const int DefaultRoots = 2;

    /// <summary>
    /// Computes the total FEC size (parity data plus the 4096-byte header
    /// block) for a file, mirroring fec_ecc_get_size() from libfec/ecc.h.
    /// <para>计算文件的FEC总大小（奇偶校验数据加4096字节头块），
    /// 对应libfec/ecc.h的fec_ecc_get_size()。</para>
    /// </summary>
    public static ulong CalculateEccSize(ulong fileSize, int roots)
    {
        if (roots <= 0 || roots >= FecRsm)
        {
            throw new ArgumentOutOfRangeException(nameof(roots), "roots must be in (0, 255).");
        }

        return DivRoundUp(DivRoundUp(fileSize, FecBlockSize), (ulong)(FecRsm - roots)) *
               (ulong)roots * FecBlockSize + FecBlockSize;
    }

    /// <summary>
    /// Computes the Reed-Solomon parity (ECC) data for an image, matching the
    /// byte-for-byte output of the AOSP 'fec --encode' tool (without the
    /// 4096-byte FEC header block, which avbtool strips before appending the
    /// data to the partition image).
    /// <para>为镜像计算Reed-Solomon奇偶校验（ECC）数据，与AOSP 'fec --encode'
    /// 工具的输出逐字节一致（不含4096字节的FEC头块，avbtool在把数据追加到分区
    /// 镜像前会剥离该头块）。</para>
    /// </summary>
    /// <param name="data">The image data to protect. Must be a positive multiple of
    /// <see cref="FecBlockSize"/> bytes (like the fec tool).
    /// <para>要保护的数据。必须是<see cref="FecBlockSize"/>字节的正整数倍
    /// （与fec工具一致）。</para></param>
    /// <param name="roots">The number of parity bytes per codeword (FEC roots).
    /// <para>每个码字的奇偶校验字节数（FEC根数）。</para></param>
    /// <returns>The parity data, rounds * roots * <see cref="FecBlockSize"/> bytes long.
    /// <para>奇偶校验数据，长度为rounds * roots * <see cref="FecBlockSize"/>字节。</para></returns>
    public static byte[] ComputeParity(ReadOnlySpan<byte> data, int roots)
    {
        if (roots <= 0 || roots >= FecRsm)
        {
            throw new ArgumentOutOfRangeException(nameof(roots), "roots must be in (0, 255).");
        }

        if (data.Length <= 0 || data.Length % FecBlockSize != 0)
        {
            throw new ArgumentException($"data length {data.Length} must be a positive multiple of {FecBlockSize}.", nameof(data));
        }

        var rsN = FecRsm - roots;
        var blocks = DivRoundUp((ulong)data.Length, FecBlockSize);
        var rounds = DivRoundUp(blocks, (ulong)rsN);
        var fecSize = checked((int)(rounds * (ulong)roots * FecBlockSize));
        var parity = new byte[fecSize];

        var codec = new RsCharCodec(0x11d, 0, 1, roots);
        var end = rounds * (ulong)rsN * FecBlockSize;
        var dataBuf = new byte[FecRsm];
        var fecPos = 0;

        for (var i = 0UL; i < end; i += (ulong)rsN)
        {
            for (var j = 0; j < rsN; j++)
            {
                var offset = Interleave(i + (ulong)j, (ulong)rsN, rounds);
                dataBuf[j] = offset < (ulong)data.Length ? data[(int)offset] : (byte)0;
            }

            codec.Encode(dataBuf.AsSpan(0, rsN), parity.AsSpan(fecPos, roots));
            fecPos += roots;
        }

        return parity;
    }

    /// <summary>
    /// Maps a codeword byte position to a physical byte offset in the data,
    /// mirroring fec_ecc_interleave() from libfec/ecc.h.
    /// <para>将码字字节位置映射到数据中的物理字节偏移，
    /// 对应libfec/ecc.h的fec_ecc_interleave()。</para>
    /// </summary>
    public static ulong Interleave(ulong offset, ulong rsN, ulong rounds) =>
        (offset / rsN) + (offset % rsN) * rounds * FecBlockSize;

    private static ulong DivRoundUp(ulong x, ulong y) => x / y + (x % y == 0 ? 0UL : 1UL);

    /// <summary>
    /// Reed-Solomon codec over GF(2^8) - a direct port of Phil Karn's
    /// init_rs_char()/encode_rs_char() (table-based, byte-identical output).
    /// <para>GF(2^8)上的Reed-Solomon编解码器 - Phil Karn的
    /// init_rs_char()/encode_rs_char()的直接移植（基于查表，输出逐字节一致）。</para>
    /// </summary>
    private sealed class RsCharCodec
    {
        private const int SymSize = 8;
        private readonly int _nn;
        private readonly int _nroots;
        private readonly byte[] _alphaTo;
        private readonly byte[] _indexOf;
        private readonly byte[] _genpoly;

        public RsCharCodec(int gfpoly, int fcr, int prim, int nroots)
        {
            _nn = (1 << SymSize) - 1;
            _nroots = nroots;

            _indexOf = new byte[_nn + 1];
            _alphaTo = new byte[_nn + 1];
            _indexOf[0] = (byte)_nn; // A0: log(0) = -inf
            _alphaTo[_nn] = 0;

            // Generate the Galois field lookup tables.
            var sr = 1;
            for (var i = 0; i < _nn; i++)
            {
                _indexOf[sr] = (byte)i;
                _alphaTo[i] = (byte)sr;
                sr <<= 1;
                if ((sr & (1 << SymSize)) != 0)
                {
                    sr ^= gfpoly;
                }

                sr &= _nn;
            }

            // gfpoly 0x11d is primitive, so sr == 1 here.

            // Form the generator polynomial from its roots.
            _genpoly = new byte[nroots + 1];
            _genpoly[0] = 1;
            for (var i = 0; i < nroots; i++)
            {
                var root = fcr * prim + i * prim;
                _genpoly[i + 1] = 1;
                for (var j = i; j > 0; j--)
                {
                    _genpoly[j] = _genpoly[j] != 0
                        ? (byte)(_genpoly[j - 1] ^ _alphaTo[Modnn(_indexOf[_genpoly[j]] + root)])
                        : _genpoly[j - 1];
                }

                _genpoly[0] = _alphaTo[Modnn(_indexOf[_genpoly[0]] + root)];
            }

            // Convert to index form for quicker encoding.
            for (var i = 0; i <= nroots; i++)
            {
                _genpoly[i] = _indexOf[_genpoly[i]];
            }
        }

        private int Modnn(int x)
        {
            while (x >= _nn)
            {
                x -= _nn;
                x = (x >> SymSize) + (x & _nn);
            }

            return x;
        }

        /// <summary>
        /// Encodes data (NN - NROOTS symbols) into parity (NROOTS symbols),
        /// mirroring encode_rs.h.
        /// <para>将数据（NN - NROOTS个符号）编码为奇偶校验（NROOTS个符号），
        /// 对应encode_rs.h。</para>
        /// </summary>
        public void Encode(ReadOnlySpan<byte> data, Span<byte> parity)
        {
            var k = _nn - _nroots; // pad = 0
            parity.Clear();
            for (var i = 0; i < k; i++)
            {
                var feedback = _indexOf[data[i] ^ parity[0]];
                var notZero = feedback != _nn;
                if (notZero)
                {
                    for (var j = 1; j < _nroots; j++)
                    {
                        parity[j] ^= _alphaTo[Modnn(feedback + _genpoly[_nroots - j])];
                    }
                }

                // Shift left by one (uses the XOR-updated values, like the C memmove).
                for (var j = 0; j < _nroots - 1; j++)
                {
                    parity[j] = parity[j + 1];
                }

                parity[_nroots - 1] = notZero ? _alphaTo[Modnn(feedback + _genpoly[0])] : (byte)0;
            }
        }
    }
}
