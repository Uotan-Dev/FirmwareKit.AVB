using FirmwareKit.AVB.Security;
using FirmwareKit.AVB.Utilities;

namespace FirmwareKit.AVB.Hashtree;

/// <summary>
/// Builds and verifies dm-verity compatible Merkle trees (hashtrees) used by
/// AVB hashtree descriptors. Port of avbtool's calc_hash_level_offsets() and
/// generate_hash_tree().
/// <para>构建和验证AVB哈希树描述符使用的dm-verity兼容Merkle树（哈希树）。
/// 移植自avbtool的calc_hash_level_offsets()和generate_hash_tree()。</para>
/// </summary>
/// <remarks>
/// Layout: the tree stores the root level first, followed by successively
/// lower levels, with the level-0 (data hashes) block last. Each level is
/// padded to a multiple of the block size. Every digest is computed as
/// H(salt || block), matching avbtool.
/// <para>布局：树中根层在前，其后依次为更低层，level-0（数据哈希）块在最后。
/// 每层填充到块大小的整数倍。每个摘要计算为H(salt || block)，与avbtool一致。</para>
/// </remarks>
public static class AvbHashtree
{
    /// <summary>
    /// Gets the digest size in bytes for a hashtree hash algorithm.
    /// <para>获取哈希树哈希算法的摘要大小（字节）。</para>
    /// </summary>
    public static int GetDigestSize(string hashAlgorithm) => AvbCrypto.GetDigestSize(hashAlgorithm);

    /// <summary>
    /// Calculates the total size in bytes of the hash tree for the given image
    /// size, mirroring avbtool's calc_hash_level_offsets().
    /// <para>计算给定镜像大小的哈希树总字节数，对应avbtool的calc_hash_level_offsets()。</para>
    /// </summary>
    public static ulong CalculateTreeSize(ulong imageSize, int blockSize, int digestSize)
    {
        ValidateParameters(blockSize, digestSize);

        ulong treeSize = 0;
        var size = imageSize;
        while (size > (ulong)blockSize)
        {
            var numBlocks = (size + (ulong)blockSize - 1) / (ulong)blockSize;
            var levelSize = RoundToMultiple(numBlocks * (ulong)digestSize, (ulong)blockSize);
            treeSize += levelSize;
            size = levelSize;
        }

        return treeSize;
    }

    /// <summary>
    /// Calculates the byte offsets of every hash level inside the tree,
    /// mirroring avbtool's calc_hash_level_offsets(). The root level is
    /// stored at offset zero.
    /// <para>计算树内每个哈希层的字节偏移，对应avbtool的calc_hash_level_offsets()。
    /// 根层存储在偏移零处。</para>
    /// </summary>
    public static ulong[] CalculateLevelOffsets(ulong imageSize, int blockSize, int digestSize)
    {
        ValidateParameters(blockSize, digestSize);

        var levelSizes = new List<ulong>();
        var size = imageSize;
        while (size > (ulong)blockSize)
        {
            var numBlocks = (size + (ulong)blockSize - 1) / (ulong)blockSize;
            var levelSize = RoundToMultiple(numBlocks * (ulong)digestSize, (ulong)blockSize);
            levelSizes.Add(levelSize);
            size = levelSize;
        }

        var numLevels = levelSizes.Count;
        var offsets = new ulong[numLevels];
        for (var n = 0; n < numLevels; n++)
        {
            ulong offset = 0;
            for (var m = n + 1; m < numLevels; m++)
            {
                offset += levelSizes[m];
            }

            offsets[n] = offset;
        }

        return offsets;
    }

    /// <summary>
    /// Builds the dm-verity hash tree for an image, mirroring avbtool's
    /// generate_hash_tree().
    /// <para>为镜像构建dm-verity哈希树，对应avbtool的generate_hash_tree()。</para>
    /// </summary>
    /// <param name="image">The image data (data blocks to hash).
    /// <para>镜像数据（要哈希的数据块）。</para></param>
    /// <param name="blockSize">The block size, e.g. 4096.
    /// <para>块大小，例如4096。</para></param>
    /// <param name="hashAlgorithm">The hash algorithm name ("sha1", "sha256" or "sha512").
    /// <para>哈希算法名称（"sha1"、"sha256"或"sha512"）。</para></param>
    /// <param name="salt">The salt prepended to each block before hashing.
    /// <para>哈希前预置到每个块的盐值。</para></param>
    /// <param name="rootDigest">When this method returns, contains the top-level digest.
    /// <para>此方法返回时，包含顶层摘要。</para></param>
    /// <returns>The hash tree bytes (empty when the image fits in a single block).
    /// <para>哈希树字节（镜像适合单个块时为空）。</para></returns>
    public static byte[] Build(
        ReadOnlySpan<byte> image,
        int blockSize,
        string hashAlgorithm,
        ReadOnlySpan<byte> salt,
        out byte[] rootDigest)
    {
        var digestSize = GetDigestSize(hashAlgorithm);
        ValidateParameters(blockSize, digestSize);

        // No tree is needed when the whole image fits in a single block; the
        // root digest is the salted hash of the image itself.
        if (image.Length <= blockSize)
        {
            rootDigest = AvbCrypto.CalculateHash(hashAlgorithm, salt, image);
            return Array.Empty<byte>();
        }

        var treeSize = CalculateTreeSize((ulong)image.Length, blockSize, digestSize);
        var tree = new byte[checked((int)treeSize)];
        var levelOffsets = CalculateLevelOffsets((ulong)image.Length, blockSize, digestSize);

        var hashSrcSize = (ulong)image.Length;
        var levelNum = 0;
        var levelOutput = Array.Empty<byte>();

        while (hashSrcSize > (ulong)blockSize)
        {
            var numBlocks = (int)((hashSrcSize + (ulong)blockSize - 1) / (ulong)blockSize);
            levelOutput = new byte[(int)RoundToMultiple((ulong)(numBlocks * digestSize), (ulong)blockSize)];

            var outPos = 0;
            ulong srcOffset = 0;
            while (srcOffset < hashSrcSize)
            {
                var take = (int)Math.Min((ulong)blockSize, hashSrcSize - srcOffset);
                ReadOnlySpan<byte> block;
                if (levelNum == 0)
                {
                    block = image.Slice((int)srcOffset, take);
                }
                else
                {
                    // For deeper levels, hash the previously stored level data.
                    var prevLevelOffset = (int)(levelOffsets[levelNum - 1] + srcOffset);
                    block = tree.AsSpan(prevLevelOffset, take);
                }

                byte[] digest;
                if (take == blockSize)
                {
                    digest = AvbCrypto.CalculateHash(hashAlgorithm, salt, block);
                }
                else
                {
                    // Zero-pad the final partial data block to the block size.
                    var padded = new byte[blockSize];
                    block.CopyTo(padded);
                    digest = AvbCrypto.CalculateHash(hashAlgorithm, salt, padded);
                }

                digest.CopyTo(levelOutput, outPos);
                outPos += digestSize;
                srcOffset += (ulong)take;
            }

            levelOutput.CopyTo(tree, (int)levelOffsets[levelNum]);
            hashSrcSize = (ulong)levelOutput.Length;
            levelNum++;
        }

        // The root digest is the salted hash of the final level's output.
        rootDigest = AvbCrypto.CalculateHash(hashAlgorithm, salt, levelOutput);
        return tree;
    }

    /// <summary>
    /// Verifies an image against a stored hash tree and/or expected root
    /// digest. The tree is regenerated and compared byte-for-byte, matching
    /// avbtool's verify behavior for hashtree partitions.
    /// <para>对照存储的哈希树和/或预期根摘要验证镜像。树会被重新生成并逐字节比较，
    /// 与avbtool对哈希树分区的验证行为一致。</para>
    /// </summary>
    /// <returns>True when the image matches the provided tree and root digest.
    /// <para>当镜像与提供的树和根摘要匹配时为true。</para></returns>
    public static bool Verify(
        ReadOnlySpan<byte> image,
        int blockSize,
        string hashAlgorithm,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> tree,
        ReadOnlySpan<byte> expectedRootDigest)
    {
        if (tree.IsEmpty && expectedRootDigest.IsEmpty)
        {
            return false;
        }

        try
        {
            var computedTree = Build(image, blockSize, hashAlgorithm, salt, out var computedRootDigest);

            if (!tree.IsEmpty)
            {
                if (computedTree.Length != tree.Length || AvbUtil.SafeMemCmp(computedTree, tree) != 0)
                {
                    return false;
                }
            }

            if (!expectedRootDigest.IsEmpty)
            {
                if (computedRootDigest.Length != expectedRootDigest.Length ||
                    AvbUtil.SafeMemCmp(computedRootDigest, expectedRootDigest) != 0)
                {
                    return false;
                }
            }

            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (OverflowException)
        {
            return false;
        }
    }

    private static void ValidateParameters(int blockSize, int digestSize)
    {
        if (blockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize), "blockSize must be positive.");
        }

        if (digestSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(digestSize), "digestSize must be positive.");
        }

        if (digestSize > blockSize)
        {
            throw new ArgumentException("digestSize must not exceed blockSize.");
        }
    }

    private static ulong RoundToMultiple(ulong value, ulong alignment) =>
        (value + alignment - 1) / alignment * alignment;
}
