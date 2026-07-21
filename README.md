# liboqs-php

[![Tests](https://github.com/mir-evgenii/liboqs-php/actions/workflows/tests.yml/badge.svg)](https://github.com/mir-evgenii/liboqs-php/actions/workflows/tests.yml)
[![Packagist Version](https://img.shields.io/packagist/v/mir-evgenii/liboqs-php)](https://packagist.org/packages/mir-evgenii/liboqs-php)
[![PHP Version](https://img.shields.io/packagist/php-v/mir-evgenii/liboqs-php)](https://packagist.org/packages/mir-evgenii/liboqs-php)
[![Packagist Downloads](https://img.shields.io/packagist/dt/mir-evgenii/liboqs-php)](https://packagist.org/packages/mir-evgenii/liboqs-php)

Post-quantum cryptography for PHP — key encapsulation (ML-KEM), digital signatures (ML-DSA), and hybrid encryption — via [FFI](https://www.php.net/manual/en/book.ffi.php) bindings to [liboqs](https://github.com/open-quantum-safe/liboqs) (the [Open Quantum Safe](https://openquantumsafe.org/) project). No PHP extension compilation required.

> ⚠️ **Status**: experimental / educational. This is a thin FFI wrapper around liboqs — it has not been independently security-audited. Review the [security notes](#security-notes) before using it for anything sensitive.

## Why

Classical public-key cryptography (RSA, ECC/ECDSA, Diffie-Hellman) is vulnerable to Shor's algorithm on a sufficiently large quantum computer. NIST finalized post-quantum standards in 2024:

- **ML-KEM** (based on CRYSTALS-Kyber) — key encapsulation
- **ML-DSA** (based on CRYSTALS-Dilithium) — digital signatures

PHP has no built-in support for either. This library exposes them via `liboqs`, called directly from PHP through FFI.

## Features

- `OqsKem` — key encapsulation (ML-KEM-512/768/1024, and other algorithms liboqs supports)
- `OqsSig` — digital signatures (ML-DSA-44/65/87, Falcon, SLH-DSA, and more)
- `HybridEncryption` — a ready-made ML-KEM + HKDF + AES-256-GCM scheme for encrypting real data (KEM alone only transports a fixed-size secret, not arbitrary messages)

## Requirements

- PHP 8.1+ with the `ffi` extension enabled
- [liboqs](https://github.com/open-quantum-safe/liboqs) installed as a shared library
- `ext-openssl` (for `HybridEncryption`, uses AES-256-GCM)

## Installation

### 1. Install liboqs

**macOS (Homebrew build tools):**

```bash
brew install cmake ninja
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
```

This installs `liboqs.dylib` to `/usr/local/lib` (Intel) or you may need to point to `/opt/homebrew/lib` on Apple Silicon — see [`resolveLibraryPath()`](#library-path-resolution) below.

**Linux:**

```bash
sudo apt install cmake ninja-build build-essential
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
```

### 2. Enable FFI in php.ini

```ini
extension=ffi
ffi.enable=true
```

Verify:

```bash
php -m | grep -i ffi
```

### 3. Install this library

```bash
composer require mir-evgenii/liboqs-php
```

(Not yet published to Packagist — for now, clone this repo and `composer install` locally.)

## Usage

### Key encapsulation (ML-KEM)

```php
use Oqs\OqsKem;

$alice = new OqsKem('ML-KEM-768');
$keys = $alice->generateKeypair(); // ['public_key' => ..., 'secret_key' => ...]

$bob = new OqsKem('ML-KEM-768');
$encapsulated = $bob->encapsulate($keys['public_key']); // ['ciphertext' => ..., 'shared_secret' => ...]

$aliceSecret = $alice->decapsulate($encapsulated['ciphertext'], $keys['secret_key']);

hash_equals($aliceSecret, $encapsulated['shared_secret']); // true
```

### Digital signatures (ML-DSA)

```php
use Oqs\OqsSig;

$signer = new OqsSig('ML-DSA-65');
$keys = $signer->generateKeypair();

$signature = $signer->sign('message to authenticate', $keys['secret_key']);

$signer->verify('message to authenticate', $signature, $keys['public_key']); // true
$signer->verify('tampered message', $signature, $keys['public_key']);        // false
```

### Hybrid encryption (ML-KEM + HKDF + AES-256-GCM)

KEM algorithms only establish a shared secret — they don't encrypt arbitrary data. `HybridEncryption` wires the pieces together into one call:

```php
use Oqs\OqsKem;
use Oqs\HybridEncryption;

$alice = new OqsKem('ML-KEM-768');
$keys = $alice->generateKeypair();

// Bob encrypts using only Alice's public key
$blob = HybridEncryption::encrypt($keys['public_key'], 'secret message');

// Alice decrypts using her secret key
$plaintext = HybridEncryption::decrypt($blob, $keys['secret_key']);
```

## API reference

### `OqsKem`

| Method | Description |
|---|---|
| `__construct(string $algName = 'ML-KEM-768')` | Throws `OqsException` if the algorithm isn't supported |
| `generateKeypair(): array{public_key: string, secret_key: string}` | |
| `encapsulate(string $publicKey): array{ciphertext: string, shared_secret: string}` | |
| `decapsulate(string $ciphertext, string $secretKey): string` | Returns the shared secret |
| `algorithmName()`, `publicKeyLength()`, `secretKeyLength()`, `ciphertextLength()`, `sharedSecretLength()` | Metadata accessors |

### `OqsSig`

| Method | Description |
|---|---|
| `__construct(string $algName = 'ML-DSA-65')` | Throws `OqsException` if the algorithm isn't supported |
| `generateKeypair(): array{public_key: string, secret_key: string}` | |
| `sign(string $message, string $secretKey): string` | Returns the signature (trimmed to actual length) |
| `verify(string $message, string $signature, string $publicKey): bool` | Never throws for an invalid signature — only for malformed input lengths |
| `algorithmName()`, `publicKeyLength()`, `secretKeyLength()`, `maxSignatureLength()` | Metadata accessors |

### `HybridEncryption`

| Method | Description |
|---|---|
| `static encrypt(string $publicKey, string $plaintext): string` | Returns a self-contained binary blob |
| `static decrypt(string $blob, string $secretKey): string` | Throws `OqsException` if the blob is malformed or authentication fails |

## Available algorithms

liboqs supports many algorithms beyond ML-KEM/ML-DSA (BIKE, Classic McEliece, Falcon, SLH-DSA, and others). Any algorithm identifier liboqs was compiled with can be passed to `OqsKem`/`OqsSig`. To list what's available on your build:

```php
$ffi = /* ... */; // see src/header/liboqs_ffi.h for the raw FFI approach
```

or check the identifiers directly in your installed `/usr/local/include/oqs/kem.h` and `sig.h`.

## Library path resolution

`OqsKem` and `OqsSig` look for the liboqs shared library in a few standard locations (see `resolveLibraryPath()` in each class):

- macOS: `/opt/homebrew/lib/liboqs.dylib`, `/usr/local/lib/liboqs.dylib`
- Linux: `/usr/local/lib/liboqs.so`, `/usr/lib/liboqs.so`, `/usr/lib/x86_64-linux-gnu/liboqs.so`
- Windows: `C:\liboqs\bin\oqs.dll`

If your installation lives elsewhere, edit `resolveLibraryPath()` in `src/OqsKem.php` / `src/OqsSig.php` accordingly.

## Testing

```bash
composer install
vendor/bin/phpunit
```

Tests cover key/signature length validation, full round-trips, tamper detection, wrong-key rejection, and edge cases (empty messages, large payloads).

## Security notes

- This library is a **thin FFI wrapper** — all cryptographic logic lives in `liboqs`, not in this PHP code. Keep `liboqs` itself updated, since post-quantum algorithm implementations are still relatively young and may receive security patches.
- The FFI struct layouts in `src/header/liboqs_ffi.h` must exactly match your installed liboqs version's C structs (field order and types). If you upgrade liboqs and see crashes or garbage values, re-check the struct definitions against the new `kem.h`/`sig.h`.
- `HybridEncryption` uses AES-256-GCM with a random 96-bit nonce per message — never reuse a `(key, nonce)` pair. Since a fresh KEM encapsulation (and thus a fresh derived key) happens on every `encrypt()` call, this is handled for you.
- This project has not undergone formal security review. Use at your own risk for anything beyond experimentation.

## License

MIT