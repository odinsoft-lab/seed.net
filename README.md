## SEED-128 for .NET (C#)

A lightweight implementation of the Korean SEED 128-bit block cipher for .NET. The library targets .NET Standard 2.0 and the console example targets .NET 6.0.

![OdinSoft Logo](./docs/logo-files/odinsoft-logo.png)

### Highlights

- SEED-128 block cipher (16-byte block size)
- CBC/ECB operation modes
	- Padding=true: CBC mode (uses IV)
	- Padding=false: ECB mode (no IV)
- PKCS#7-style padding (enabled by default)
- Helpers for byte/string/Base64 conversions

### Supported runtimes

- Library: .NET Standard 2.0
- Example/Tests: .NET 6.0

---

## Background and Compliance (KR)

SEED is a 128-bit block cipher developed under the direction of the Government of the Republic of Korea and has been widely used as a domestic standard across e-government, public, and financial sectors. In certain Korean contexts, use of a KCMVP-approved crypto module and specific national algorithms may be required. Actual certification/review requirements vary by organization and project; verify the latest guidelines and requirements before deployment.

This repository follows the official specifications; the `docs/seed-specs` folder includes specifications, test vectors, and evaluation reports. Use those documents to validate this implementation with the provided test vectors where needed.

---

## Installation

Use the source in this repository either via a Project Reference or by including the code directly.

1) Add a Project Reference to `src/Seed128/seed128.csproj` in your solution
2) Or include the source files under `src/Seed128`

Note: `seed128.csproj` is configured to pack a package icon. If local builds fail due to the icon path, see “Build Issues & Fixes” below.

---

## Quick start

Namespace: `OdinSoft.Security.Cryptography`

```csharp
using System;
using System.Text;
using System.Security.Cryptography;
using OdinSoft.Security.Cryptography;

// Prepare 16-byte key/IV
var key = new byte[16];
var iv  = new byte[16];
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(iv);

// Default Padding=true (CBC mode)
var seed = new Seed128(key, iv);

// Encrypt/Decrypt (byte[])
var plain = Encoding.UTF8.GetBytes("hello SEED-128");
var cipher = seed.Encrypt(plain);
var roundtrip = seed.Decrypt(cipher);
Console.WriteLine(Encoding.UTF8.GetString(roundtrip)); // hello SEED-128

// Base64 helpers
string cipherB64 = seed.PlainBytesToChiperBase64(plain);
byte[] plain2 = seed.ChiperBase64ToPlainBytes(cipherB64);

// String <-> Base64 helpers
string encB64 = seed.PlainStringToChiperBase64("password");
string decB64 = seed.ChiperBase64ToPlainString(encB64);
```

---

## API summary

Class: `Seed128 : Seed`

- Constructor: `Seed128(byte[] seed_key, byte[] seed_iv)`
	- Default padding: `true` (CBC mode)
- `byte[] Encrypt(byte[] plain_data)`
- `byte[] Decrypt(byte[] encrypted_data)`
- `string PlainBase64ToChiperBase64(string plain_text)`
- `string ChiperBase64ToPlainBase64(string chiper_text)`
- `string PlainBytesToChiperBase64(byte[] plain_data)`
- `byte[] ChiperBase64ToPlainBytes(string chiper_text)`
- `string PlainStringToChiperBase64(string plain_text)`
- `string ChiperBase64ToPlainString(string chiper_text)`
- `string PlainStringToChiperString(string plain_text)`
- `string ChiperStringToPlainString(string chiper_text)`

Note: Some helpers use `Encoding.Default` for encoding and `Encoding.UTF8` for decoding. For consistent cross-platform behavior, prefer using the byte-array APIs (Encrypt/Decrypt) and manage encoding explicitly.

---

## Modes and padding

- Block size: 16 bytes
- Padding: PKCS#7-like (applied when Padding=true)
- Modes:
	- Padding=true: CBC (requires IV, XOR chaining)
	- Padding=false: ECB (no IV/padding)

For security, CBC with padding is generally recommended. Avoid ECB for structured or repetitive data.

---

## Build & run

This repository includes the library (`src/Seed128`) and a console example (`tests/Seed128.Test`).

- Build library: `src/Seed128/seed128.csproj`
- Run example: `tests/Seed128.Test/seed128.Test.csproj`

Build issues & fixes:

- `seed128.csproj` is configured to pack an icon from `..\..\doc\odinsoft-symbol.png`, while the repo contains `docs/logo-files/odinsoft-logo.png`. If local build fails, choose one:
	1) Disable packing: set `GeneratePackageOnBuild` to `False`
	2) Update icon path: point to the actual file (e.g., `docs/logo-files/odinsoft-logo.png`) and update the ItemGroup Include/PackagePath
	3) Add missing path/file: create `doc/odinsoft-symbol.png`

- The solution file (`seed.security..sln`) may reference a different test project path. Building projects individually is recommended.

---

## Example project

Located under `tests/Seed128.Test`:

- `Program.cs`: Demonstrates encrypting a string with `Seed128` and encrypting the generated symmetric key with RSA.
- `RsaEncryption.cs`: A simple example using .NET `RSACryptoServiceProvider`. For production, consider OAEP padding and robust key management.

---

## Specs and references

The `docs/seed-specs` folder contains official documents and test vectors related to SEED.

- [1] SEED Algorithm Specification (Korean): Algorithm overview, S-Boxes, key schedule, round function
	- File: `[1]_SEED_Algorithm_Specification_korean_M.pdf`
- [2] SEED+128 Specification (English): The SEED 128-bit specification and implementation notes
	- File: `[2]_SEED+128_Specification_english_M.pdf`
- [3] SEED+128 Self Evaluation (Korean): Self-evaluation report (security, performance, etc.)
	- File: `[3]_SEED+128_Self_Evaluation-Korean-M.pdf`
- [4] SEED+128 Self Evaluation (English): English version of the self-evaluation report
	- File: `[4]_SEED+128_Self_Evaluation-English_M.pdf`
- [5] SEED+128 Test Vector: Official test vectors (key/IV/plaintext/ciphertext)
	- File: `[5]_SEED+128_Test_Vector_M.pdf`
- [6] SEED+128 OID: Algorithm identifiers (OID)
	- File: `[6]_SEED+128_OID+20091203_M.pdf`
- SEED Evaluation Report by CRYPTREC: CRYPTREC evaluation report
	- File: `SEED_Evaluation_Report_by_CRYPTREC.pdf`
- SEED Test Vectors for Modified SEED: Test vectors for modified SEED
	- File: `SEED_Test_Vectors_for_Modified_SEED.pdf`

### Validating with official test vectors

To quickly validate this implementation:

1) Choose a 16-byte key, 16-byte IV, and block-aligned plaintext from `[5]_SEED+128_Test_Vector_M.pdf`.
2) Encrypt with the same key/IV using CBC (Padding=true) or ECB (Padding=false) as specified by the vector.
3) Compare the resulting ciphertext byte-for-byte with the document.

Tip: If the test vector is block-aligned, comparing with Padding=false (ECB or CBC without padding) is convenient. For CBC, ensure chaining (XOR with previous block) matches the vector’s definition.

---

## License

MIT License. See package metadata and repository headers for details.

---

## Credits

- Copyright © OdinSoft
- Authors: SeongAhn Lee et al.

---

## Contributing

Issues and PRs are welcome. Changes to packaging (icons/packing) may affect CI/release; please discuss before submitting.
