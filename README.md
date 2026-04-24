# FirmwareKit.AVB

A C# implementation of Android Verified Boot (AVB) library, supporting parsing and verification of VBMeta images and Android footprints.

## Features

- Parse VBMeta headers and images.
- Support for AVB descriptors and footers.
- Hardware-independent I/O interface via `IAvbOps`.
- Managed `libavb_ab` flow and boot-control facade via `AvbAbFlow` and `AvbBootControl`.
- Managed `libavb_user` equivalent helpers via `AvbUser` (verification/verity toggles).
- Managed `libavb_cert` equivalent validation via `AvbCertValidator` and `IAvbCertOps`.
- Multi-framework support: `net8.0`, `net10.0`.

## CLI (Managed, No Python Runtime)

This repository now includes a standalone managed CLI project: `FirmwareKit.AVB.Cli`.

Examples:

```bash
dotnet run --project FirmwareKit.AVB.Cli -- version
dotnet run --project FirmwareKit.AVB.Cli -- generate_test_image --image_size 4096 --output test.img
dotnet run --project FirmwareKit.AVB.Cli -- extract_public_key --key signing.pem --output avb_pk.bin
dotnet run --project FirmwareKit.AVB.Cli -- extract_public_key_digest --key signing.pem --output avb_pk.sha256
dotnet run --project FirmwareKit.AVB.Cli -- make_vbmeta_image --output vbmeta.img --algorithm NONE
dotnet run --project FirmwareKit.AVB.Cli -- add_hash_footer --image boot.img --partition_size 67108864 --partition_name boot
dotnet run --project FirmwareKit.AVB.Cli -- append_vbmeta_image --image boot.img --vbmeta_image vbmeta.img --partition_size 67108864
dotnet run --project FirmwareKit.AVB.Cli -- erase_footer --image boot.img
dotnet run --project FirmwareKit.AVB.Cli -- resize_image --image boot.img --partition_size 83886080
dotnet run --project FirmwareKit.AVB.Cli -- set_ab_metadata --misc_image misc.img --slot_data 15:7:1:14:7:0
dotnet run --project FirmwareKit.AVB.Cli -- zero_hashtree --image system.img
dotnet run --project FirmwareKit.AVB.Cli -- extract_vbmeta_image --image boot.img --output vbmeta_extracted.img
dotnet run --project FirmwareKit.AVB.Cli -- verify_image --image vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- info_image --image vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- print_partition_digests --image vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- calculate_vbmeta_digest --image vbmeta.img --hash_algorithm sha256
dotnet run --project FirmwareKit.AVB.Cli -- vbmeta verify vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- vbmeta info vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- vbmeta digest vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- vbmeta print-partition-digests vbmeta.img
dotnet run --project FirmwareKit.AVB.Cli -- ab inspect ab_metadata.bin
dotnet run --project FirmwareKit.AVB.Cli -- cert make-unlock-credential \
 --pik-cert pik_certificate.bin \
 --puk-cert puk_certificate.bin \
 --puk-key puk.pem \
 --challenge challenge.bin \
 --out unlock_credential.bin
dotnet run --project FirmwareKit.AVB.Cli -- cert inspect-archive unlock_creds.zip
dotnet run --project FirmwareKit.AVB.Cli -- cert make-unlock-credential-from-archive \
 --archive unlock_creds.zip \
 --challenge challenge.bin \
 --out unlock_credential.bin
dotnet run --project FirmwareKit.AVB.Cli -- cert make-unlock-credential-auto \
 --challenge challenge.bin \
 --out unlock_credential.bin \
 unlock_creds_1.zip unlock_creds_2.zip credentials_dir
dotnet run --project FirmwareKit.AVB.Cli -- persistent-digest build \
 --name factory \
 --digest-hex 00112233445566778899aabbccddeeff \
 --out persistent_digest.bin
dotnet run --project FirmwareKit.AVB.Cli -- persistent-digest build \
 --name factory \
 --clear-digest \
 --out persistent_digest_clear.bin
dotnet run --project FirmwareKit.AVB.Cli -- persistent-digest build-clear-factory \
 --out factory_clear_digest.bin
dotnet run --project FirmwareKit.AVB.Cli -- persistent-digest inspect factory_clear_digest.bin
dotnet run --project FirmwareKit.AVB.Cli -- auth-unlock run \
 --serial <fastboot_serial> \
 unlock_creds_1.zip unlock_creds_2.zip credentials_dir
```

## Installation

```bash
dotnet add package FirmwareKit.AVB
```

## Quick Start

```csharp
using FirmwareKit.AVB;

// Use AvbSlotVerifier to verify partitions
var verifier = new AvbSlotVerifier(ops);
var result = verifier.VerifySlot("boot", 0);
```

## License

MIT
