using FirmwareKit.AVB.Abstractions;
using FirmwareKit.AVB.Descriptors;
using FirmwareKit.AVB.Enums;
using FirmwareKit.AVB.Utilities;
using FirmwareKit.AVB.VBMeta;
using FirmwareKit.AVB.Verification;
using System.Text;

namespace FirmwareKit.AVB.Core;
/// <summary>
/// Generates the kernel command-line fragment for Android Verified Boot.
/// Equivalent to the logic in 'avb_slot_verify.c' for command-line generation.
/// <para>生成Android Verified Boot的内核命令行片段。</para>
/// <para>等价于'avb_slot_verify.c'中用于命令行生成的逻辑。</para>
/// </summary>
public static class AvbCmdlineGenerator
{
    private const string SystemPartUuidToken = "$(ANDROID_SYSTEM_PARTUUID)";
    private const string BootPartUuidToken = "$(ANDROID_BOOT_PARTUUID)";
    private const string VbmetaPartUuidToken = "$(ANDROID_VBMETA_PARTUUID)";
    private const string VbmetaDigestToken = "$(ANDROID_VBMETA_DIGEST)";

    private const string VerityModeToken = "$(ANDROID_VERITY_MODE)";

    /// <summary>
    /// Generates the kernel command-line based on verification data and slot information.
    /// <para>基于验证数据和槽位信息生成内核命令行。</para>
    /// </summary>
    /// <param name="data">The verification data containing loaded VBMeta images and results.
    /// <para>包含已加载VBMeta镜像和结果的验证数据。</para></param>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for platform-specific queries.</param>
    /// <param name="flags">Verification flags used during slot verification.
    /// <para>槽位验证期间使用的验证标志。</para></param>
    /// <param name="hashtreeErrorMode">The original hashtree error mode before resolution.
    /// <para>解析前的原始哈希树错误模式。</para></param>
    /// <returns>A string containing the generated kernel command-line fragment.
    /// <para>包含生成的内核命令行片段的字符串。</para></returns>
    public static string Generate(AvbSlotVerifyData data, IAvbOps ops, AvbSlotVerifyFlags flags, AvbHashtreeErrorMode hashtreeErrorMode)
    {
        var sb = new StringBuilder();

        foreach (var v in data.VbmetaImages)
        {
            var image = new AvbVBMetaImage(v.VbMetaBytes);
            foreach (var desc in image.GetDescriptors())
            {
                if (desc is AvbKernelCmdlineDescriptor kcd)
                {
                    // AOSP logic: Skip if descriptor flags don't match HASHTREE_DISABLED state of top-level VBMeta
                    var hashtreeDisabled = (data.ToplevelVBMetaFlags & (uint)AvbVBMetaImageFlags.HashtreeDisabled) != 0;
                    var apply = true;
                    if (hashtreeDisabled)
                    {
                        if ((kcd.Flags & AvbKernelCmdlineFlags.UseOnlyIfHashtreeNotDisabled) != 0)
                        {
                            apply = false;
                        }
                    }
                    else
                    {
                        if ((kcd.Flags & AvbKernelCmdlineFlags.UseOnlyIfHashtreeDisabled) != 0)
                        {
                            apply = false;
                        }
                    }

                    if (apply)
                    {
                        if (sb.Length > 0)
                        {
                            sb.Append(' ');
                        }

                        sb.Append(kcd.KernelCmdline);
                    }
                }
            }
        }

        if ((flags & AvbSlotVerifyFlags.NoVbmetaPartition) == 0)
        {
            AppendOption(sb, "androidboot.vbmeta.device", $"PARTUUID={VbmetaPartUuidToken}");

            if (data.VbmetaImages.Count > 0 && data.ToplevelPublicKey.Length > 0)
            {
                var pkDigest = AvbCompat.HashData256(data.ToplevelPublicKey);
                AppendOption(sb, "androidboot.vbmeta.public_key_digest", AvbCompat.ToHexString(pkDigest).ToLowerInvariant());
            }
        }

        var deviceState = ops.ReadIsDeviceUnlocked(out var unlocked) == AvbIOResult.Ok && unlocked ? "unlocked" : "locked";
        AppendOption(sb, "androidboot.vbmeta.device_state", deviceState);

        if (data.VbmetaImages.Count > 0)
        {
            AppendOption(sb, "androidboot.vbmeta.avb_version", $"{AvbVBMetaImageHeader.ExpectedVersionMajor}.{AvbVBMetaImageHeader.MaxSupportedVersionMinor}");

            var useSha512 = data.ToplevelAlgorithmType is >= AvbAlgorithmType.Sha512Rsa2048 and not AvbAlgorithmType.None;
            var digestType = useSha512 ? AvbDigestType.Sha512 : AvbDigestType.Sha256;
            var hashAlgStr = useSha512 ? "sha512" : "sha256";

            var digest = data.VbmetaDigest.Length > 0 ? data.VbmetaDigest : AvbSlotVerifier.CalculateVBMetaDigest(data, digestType);
            AppendOption(sb, "androidboot.vbmeta.hash_alg", hashAlgStr);
            AppendOption(sb, "androidboot.vbmeta.size", data.VbmetaImages.Sum(v => v.VbMetaBytes.Length).ToString());
            AppendOption(sb, "androidboot.vbmeta.digest", AvbCompat.ToHexString(digest).ToLowerInvariant());
        }

        var verityMode = "disabled";
        var dmVerityMode = "";
        if ((data.ToplevelVBMetaFlags & (uint)AvbVBMetaImageFlags.HashtreeDisabled) == 0)
        {
            switch (data.ResolvedHashtreeErrorMode)
            {
                case AvbHashtreeErrorMode.RestartAndInvalidate:
                    AppendOption(sb, "androidboot.vbmeta.invalidate_on_error", "yes");
                    verityMode = "enforcing";
                    dmVerityMode = "restart_on_corruption";
                    break;
                case AvbHashtreeErrorMode.Restart:
                    verityMode = "enforcing";
                    dmVerityMode = "restart_on_corruption";
                    break;
                case AvbHashtreeErrorMode.Eio:
                    verityMode = "eio";
                    dmVerityMode = "ignore_zero_blocks";
                    break;
                case AvbHashtreeErrorMode.Logging:
                    verityMode = "logging";
                    dmVerityMode = "ignore_corruption";
                    break;
                case AvbHashtreeErrorMode.Panic:
                    verityMode = "panicking";
                    dmVerityMode = "panic_on_corruption";
                    break;
                case AvbHashtreeErrorMode.ManagedRestartAndEio:
                    break;
                default:
                    break;
            }
        }
        AppendOption(sb, "androidboot.veritymode", verityMode);

        if (hashtreeErrorMode == AvbHashtreeErrorMode.ManagedRestartAndEio)
        {
            AppendOption(sb, "androidboot.veritymode.managed", "yes");
        }

        foreach (var p in data.LoadedPartitions)
        {
            if (p.Digest != null && p.Digest.Length > 0)
            {
                var algName = p.DigestType == AvbDigestType.Sha512 ? "sha512" : "sha256";
                AppendOption(sb, $"androidboot.vbmeta.{p.PartitionName}.hash_alg", algName);
                AppendOption(sb, $"androidboot.vbmeta.{p.PartitionName}.digest", AvbCompat.ToHexString(p.Digest).ToLowerInvariant());
            }
        }

        var cmdline = sb.ToString();
        // Substitute $(ANDROID_VERITY_MODE) (AOSP avb_append_options equivalent)
        if ((data.ToplevelVBMetaFlags & (uint)AvbVBMetaImageFlags.HashtreeDisabled) == 0 && !string.IsNullOrEmpty(dmVerityMode))
        {
            cmdline = Substitute(cmdline, VerityModeToken, dmVerityMode);
        }

        return cmdline;
    }

    /// <summary>
    /// Performs token substitutions (e.g., $(ANDROID_SYSTEM_PARTUUID)) in a command-line string.
    /// Equivalent to 'avb_sub_cmdline' in libavb.
    /// <para>在命令行字符串中执行令牌替换（例如 $(ANDROID_SYSTEM_PARTUUID)）。</para>
    /// <para>等价于libavb中的'avb_sub_cmdline'。</para>
    /// </summary>
    /// <param name="cmdline">The command-line string with tokens.
    /// <para>带有令牌的命令行字符串。</para></param>
    /// <param name="data">The verification data containing loaded partitions and digests.
    /// <para>包含已加载分区和摘要的验证数据。</para></param>
    /// <param name="ops">The <see cref="IAvbOps"/> instance for platform-specific queries.</param>
    /// <param name="slotSuffix">The A/B slot suffix.
    /// <para>A/B槽位后缀。</para></param>
    /// <returns>A new string with tokens replaced.
    /// <para>替换令牌后的新字符串。</para></returns>
    public static string SubstituteTokens(string cmdline, AvbSlotVerifyData data, IAvbOps ops, string slotSuffix)
    {
        var substitutions = BuildSubstitutionList(data, ops, slotSuffix);

        var aospTokens = new[]
        {
            (Token: SystemPartUuidToken, Name: "system"),
            (Token: BootPartUuidToken, Name: "boot"),
            (Token: VbmetaPartUuidToken, Name: "vbmeta")
        };

        var usingBootForVbmeta = data.VbmetaImages.Count > 0 && data.VbmetaImages[0].PartitionName == "boot";

        foreach (var (token, name) in aospTokens)
        {
            if (cmdline.Contains(token))
            {
                var partitionName = name;
                if (token == VbmetaPartUuidToken && usingBootForVbmeta)
                {
                    partitionName = "boot";
                }
                var value = GetGuid(ops, partitionName + slotSuffix);
                cmdline = Substitute(cmdline, token, value);
                substitutions.TryAdd(token, value);
            }
        }

        // Apply additional substitutions (AOSP additional_cmdline_subst equivalent)
        // This includes $(AVB_[PARTITION]_ROOT_DIGEST) etc.
        foreach (var pair in data.AdditionalSubstitutions)
        {
            var token = pair.Key;
            var value = pair.Value;
            cmdline = Substitute(cmdline, token, value);
            substitutions.TryAdd(token, value);
        }

        // Legacy/Custom token replacements (backward compatibility or extensions)
        foreach (var p in data.LoadedPartitions)
        {
            var token = $"$(ANDROID_{p.PartitionName.ToUpperInvariant()}_PARTUUID)";
            if (!aospTokens.Any(t => t.Token == token) && cmdline.Contains(token))
            {
                var value = GetGuid(ops, p.PartitionName + slotSuffix);
                cmdline = Substitute(cmdline, token, value);
                substitutions.TryAdd(token, value);
            }
        }

        if (cmdline.Contains(VbmetaDigestToken) && data.VbmetaImages.Count > 0)
        {
            var topAlgo = data.ToplevelAlgorithmType;
            var digestType = topAlgo <= AvbAlgorithmType.Sha256Rsa8192 ? AvbDigestType.Sha256 : AvbDigestType.Sha512;
            var digest = data.VbmetaDigest.Length > 0 ? data.VbmetaDigest : AvbSlotVerifier.CalculateVBMetaDigest(data, digestType);
            var value = AvbCompat.ToHexString(digest).ToLowerInvariant();
            cmdline = Substitute(cmdline, VbmetaDigestToken, value);
            substitutions.TryAdd(VbmetaDigestToken, value);
        }

        return substitutions.Apply(cmdline);
    }

    /// <summary>
    /// Builds a command-line substitution list from current slot verification data.
    /// <para>从当前槽位验证数据构建命令行替换列表。</para>
    /// </summary>
    public static AvbCmdlineSubstitutionList BuildSubstitutionList(AvbSlotVerifyData data, IAvbOps ops, string slotSuffix)
    {
        var list = new AvbCmdlineSubstitutionList();

        foreach (var pair in data.AdditionalSubstitutions)
        {
            list.TryAdd(pair.Key, pair.Value);
        }

        foreach (var p in data.LoadedPartitions)
        {
            if (p.Digest != null && p.Digest.Length > 0)
            {
                list.TryAddRootDigestSubstitution(p.PartitionName, p.Digest);
            }

            var token = $"$(ANDROID_{p.PartitionName.ToUpperInvariant()}_PARTUUID)";
            var guid = GetGuid(ops, p.PartitionName + slotSuffix);
            if (!string.IsNullOrEmpty(guid))
            {
                list.TryAdd(token, guid);
            }
        }

        return list;
    }

    /// <summary>
    /// Appends a key-value pair option to the command-line string builder.
    /// <para>向命令行字符串生成器追加键值对选项。</para>
    /// </summary>
    /// <param name="sb">The <see cref="StringBuilder"/> to append to.</param>
    /// <param name="key">The option key.
    /// <para>选项键。</para></param>
    /// <param name="value">The option value.
    /// <para>选项值。</para></param>
    private static void AppendOption(StringBuilder sb, string key, string value)
    {
        if (sb.Length > 0)
        {
            sb.Append(' ');
        }

        sb.Append(key).Append('=').Append(value);
    }

    /// <summary>
    /// Substitutes a token within the command-line string with a specified value.
    /// <para>在命令行字符串中用指定值替换令牌。</para>
    /// </summary>
    /// <param name="cmdline">The original command-line string.
    /// <para>原始命令行字符串。</para></param>
    /// <param name="token">The token to search for.
    /// <para>要搜索的令牌。</para></param>
    /// <param name="value">The value to replace the token with.
    /// <para>用于替换令牌的值。</para></param>
    /// <returns>The command-line string after substitution.
    /// <para>替换后的命令行字符串。</para></returns>
    private static string Substitute(string cmdline, string token, string value) => string.IsNullOrEmpty(value) ? cmdline : cmdline.Replace(token, value);

    /// <summary>
    /// Retrieves the partition UUID for the specified partition name.
    /// <para>检索指定分区名称的分区UUID。</para>
    /// </summary>
    /// <param name="ops">The <see cref="IAvbOps"/> instance to use.</param>
    /// <param name="partitionName">The name of the partition.
    /// <para>分区名称。</para></param>
    /// <returns>The partition UUID if available, otherwise an empty string.
    /// <para>如果可用则返回分区UUID，否则返回空字符串。</para></returns>
    private static string GetGuid(IAvbOps ops, string partitionName) => ops.GetUniqueGuidForPartition(partitionName, out var guid) == AvbIOResult.Ok ? guid : "";
}
