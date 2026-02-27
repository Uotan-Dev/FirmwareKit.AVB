# FirmwareKit.AVB

A C# implementation of Android Verified Boot (AVB) library, supporting parsing and verification of VBMeta images and Android footprints.

## Features

- Parse VBMeta headers and images.
- Support for AVB descriptors and footers.
- Hardware-independent I/O interface via `IAvbOps`.
- Multi-framework support: `net8.0`, `net10.0`.

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
