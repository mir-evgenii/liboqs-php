<?php

declare(strict_types=1);

namespace Oqs;

use Oqs\Exception\OqsException;
use Oqs\Internal\LibraryLocator;

/**
 * PHP wrapper around liboqs' OQS_KEM API (key encapsulation mechanisms
 * such as ML-KEM / Kyber) using FFI.
 *
 * Example:
 *   $alice = new OqsKem('ML-KEM-768');
 *   $keys  = $alice->generateKeypair();
 *
 *   $bob = new OqsKem('ML-KEM-768');
 *   $enc = $bob->encapsulate($keys['public_key']);
 *
 *   $secret = $alice->decapsulate($enc['ciphertext'], $keys['secret_key']);
 *   // $secret === $enc['shared_secret']
 *
 * The liboqs shared library is located via (in priority order): an explicit
 * $libraryPath constructor argument, the LIBOQS_PATH environment variable,
 * then a handful of common install locations for the current OS.
 */
final class OqsKem
{
    /** Cached FFI instance shared across all OqsKem objects in this process. */
    private static ?\FFI $ffi = null;

    /** Path the cached FFI instance above was loaded from. */
    private static ?string $loadedLibraryPath = null;

    private \FFI $instanceFfi;
    private \FFI\CData $kem;
    private bool $freed = false;

    public function __construct(string $algName = 'ML-KEM-768', ?string $libraryPath = null)
    {
        $this->instanceFfi = self::ffi($libraryPath);

        $kem = $this->instanceFfi->OQS_KEM_new($algName);
        if ($kem === null || \FFI::isNull($kem)) {
            throw new OqsException(
                "KEM algorithm '{$algName}' is not supported or was disabled at compile time"
            );
        }

        $this->kem = $kem;
    }

    public function __destruct()
    {
        $this->free();
    }

    /**
     * Explicitly release the underlying C object. Safe to call multiple times.
     */
    public function free(): void
    {
        if (!$this->freed) {
            $this->instanceFfi->OQS_KEM_free($this->kem);
            $this->freed = true;
        }
    }

    public function algorithmName(): string
    {
        return \FFI::string($this->kem->method_name);
    }

    public function publicKeyLength(): int
    {
        return $this->kem->length_public_key;
    }

    public function secretKeyLength(): int
    {
        return $this->kem->length_secret_key;
    }

    public function ciphertextLength(): int
    {
        return $this->kem->length_ciphertext;
    }

    public function sharedSecretLength(): int
    {
        return $this->kem->length_shared_secret;
    }

    /**
     * Generate a fresh keypair.
     *
     * @return array{public_key: string, secret_key: string}
     */
    public function generateKeypair(): array
    {
        $ffi = $this->instanceFfi;

        $pk = $ffi->new("uint8_t[{$this->kem->length_public_key}]");
        $sk = $ffi->new("uint8_t[{$this->kem->length_secret_key}]");

        $rc = $ffi->OQS_KEM_keypair($this->kem, $pk, $sk);
        if ($rc !== 0) {
            throw new OqsException("Keypair generation failed (rc={$rc})");
        }

        return [
            'public_key' => \FFI::string($pk, $this->kem->length_public_key),
            'secret_key' => \FFI::string($sk, $this->kem->length_secret_key),
        ];
    }

    /**
     * Encapsulate a fresh shared secret under the given public key.
     *
     * @return array{ciphertext: string, shared_secret: string}
     */
    public function encapsulate(string $publicKey): array
    {
        if (strlen($publicKey) !== $this->kem->length_public_key) {
            throw new OqsException(sprintf(
                'Invalid public key length: expected %d bytes, got %d',
                $this->kem->length_public_key,
                strlen($publicKey)
            ));
        }

        $ffi = $this->instanceFfi;

        $pkBuf = $ffi->new('uint8_t[' . strlen($publicKey) . ']');
        \FFI::memcpy($pkBuf, $publicKey, strlen($publicKey));

        $ct = $ffi->new("uint8_t[{$this->kem->length_ciphertext}]");
        $ss = $ffi->new("uint8_t[{$this->kem->length_shared_secret}]");

        $rc = $ffi->OQS_KEM_encaps($this->kem, $ct, $ss, $pkBuf);
        if ($rc !== 0) {
            throw new OqsException("Encapsulation failed (rc={$rc})");
        }

        return [
            'ciphertext'    => \FFI::string($ct, $this->kem->length_ciphertext),
            'shared_secret' => \FFI::string($ss, $this->kem->length_shared_secret),
        ];
    }

    /**
     * Recover the shared secret from a ciphertext using our secret key.
     */
    public function decapsulate(string $ciphertext, string $secretKey): string
    {
        if (strlen($ciphertext) !== $this->kem->length_ciphertext) {
            throw new OqsException(sprintf(
                'Invalid ciphertext length: expected %d bytes, got %d',
                $this->kem->length_ciphertext,
                strlen($ciphertext)
            ));
        }

        if (strlen($secretKey) !== $this->kem->length_secret_key) {
            throw new OqsException(sprintf(
                'Invalid secret key length: expected %d bytes, got %d',
                $this->kem->length_secret_key,
                strlen($secretKey)
            ));
        }

        $ffi = $this->instanceFfi;

        $ctBuf = $ffi->new('uint8_t[' . strlen($ciphertext) . ']');
        \FFI::memcpy($ctBuf, $ciphertext, strlen($ciphertext));

        $skBuf = $ffi->new('uint8_t[' . strlen($secretKey) . ']');
        \FFI::memcpy($skBuf, $secretKey, strlen($secretKey));

        $ss = $ffi->new("uint8_t[{$this->kem->length_shared_secret}]");

        $rc = $ffi->OQS_KEM_decaps($this->kem, $ss, $ctBuf, $skBuf);
        if ($rc !== 0) {
            throw new OqsException("Decapsulation failed (rc={$rc})");
        }

        return \FFI::string($ss, $this->kem->length_shared_secret);
    }

    /**
     * The full path liboqs was (or would be) loaded from in this process.
     * Returns null if no OqsKem instance has been constructed yet.
     */
    public static function loadedLibraryPath(): ?string
    {
        return self::$loadedLibraryPath;
    }

    /**
     * Load (once per process) and cache the FFI binding to liboqs.
     */
    private static function ffi(?string $libraryPath): \FFI
    {
        if (self::$ffi !== null) {
            if ($libraryPath !== null && $libraryPath !== self::$loadedLibraryPath) {
                throw new OqsException(
                    'liboqs is already loaded from ' . self::$loadedLibraryPath . ' in this process ' .
                    "and cannot be switched to {$libraryPath}. Set the library path before the first " .
                    'OqsKem usage (via LIBOQS_PATH or the constructor argument).'
                );
            }

            return self::$ffi;
        }

        if (!extension_loaded('ffi')) {
            throw new OqsException(
                'The PHP FFI extension is required. Add "extension=ffi" and "ffi.enable=true" to php.ini'
            );
        }

        $header = file_get_contents(__DIR__ . '/header/liboqs_ffi.h');
        if ($header === false) {
            throw new OqsException('Could not read liboqs_ffi.h header file');
        }

        $resolvedPath = self::resolveLibraryPath($libraryPath);
        self::$loadedLibraryPath = $resolvedPath;

        return self::$ffi = \FFI::cdef($header, $resolvedPath);
    }

    /**
     * Resolve the liboqs shared library path for the current platform.
     *
     * Priority: explicit $override argument, then the LIBOQS_PATH environment
     * variable, then a handful of common install locations for the current OS.
     */
    private static function resolveLibraryPath(?string $override): string
    {
        $candidates = match (PHP_OS_FAMILY) {
            'Darwin' => [
                '/opt/homebrew/lib/liboqs.dylib',
                '/usr/local/lib/liboqs.dylib',
            ],
            'Linux' => [
                '/usr/local/lib/liboqs.so',
                '/usr/lib/liboqs.so',
                '/usr/lib/x86_64-linux-gnu/liboqs.so',
            ],
            'Windows' => [
                'C:\\liboqs\\bin\\oqs.dll',
            ],
            default => [],
        };

        return LibraryLocator::resolve($override, $candidates);
    }
}