<?php

declare(strict_types=1);

namespace Oqs;

use Oqs\Exception\OqsException;

/**
 * PHP wrapper around liboqs' OQS_SIG API (digital signature schemes
 * such as ML-DSA / Dilithium, Falcon, SLH-DSA) using FFI.
 *
 * Example:
 *   $signer = new OqsSig('ML-DSA-65');
 *   $keys   = $signer->generateKeypair();
 *
 *   $signature = $signer->sign('hello world', $keys['secret_key']);
 *   $valid     = $signer->verify('hello world', $signature, $keys['public_key']);
 */
final class OqsSig
{
    /** Cached FFI instance shared with OqsKem (same header/library). */
    private static ?\FFI $ffi = null;

    private \FFI $instanceFfi;
    private \FFI\CData $sig;
    private bool $freed = false;

    public function __construct(string $algName = 'ML-DSA-65')
    {
        $this->instanceFfi = self::ffi();

        $sig = $this->instanceFfi->OQS_SIG_new($algName);
        if ($sig === null || \FFI::isNull($sig)) {
            throw new OqsException(
                "Signature algorithm '{$algName}' is not supported or was disabled at compile time"
            );
        }

        $this->sig = $sig;
    }

    public function __destruct()
    {
        $this->free();
    }

    public function free(): void
    {
        if (!$this->freed) {
            $this->instanceFfi->OQS_SIG_free($this->sig);
            $this->freed = true;
        }
    }

    public function algorithmName(): string
    {
        return \FFI::string($this->sig->method_name);
    }

    public function publicKeyLength(): int
    {
        return $this->sig->length_public_key;
    }

    public function secretKeyLength(): int
    {
        return $this->sig->length_secret_key;
    }

    /** Maximum signature length — actual signatures may be shorter. */
    public function maxSignatureLength(): int
    {
        return $this->sig->length_signature;
    }

    /**
     * Generate a fresh keypair.
     *
     * @return array{public_key: string, secret_key: string}
     */
    public function generateKeypair(): array
    {
        $ffi = $this->instanceFfi;

        $pk = $ffi->new("uint8_t[{$this->sig->length_public_key}]");
        $sk = $ffi->new("uint8_t[{$this->sig->length_secret_key}]");

        $rc = $ffi->OQS_SIG_keypair($this->sig, $pk, $sk);
        if ($rc !== 0) {
            throw new OqsException("Keypair generation failed (rc={$rc})");
        }

        return [
            'public_key' => \FFI::string($pk, $this->sig->length_public_key),
            'secret_key' => \FFI::string($sk, $this->sig->length_secret_key),
        ];
    }

    /**
     * Sign a message with the given secret key.
     * Returns the signature, trimmed to its actual (possibly variable) length.
     */
    public function sign(string $message, string $secretKey): string
    {
        if (strlen($secretKey) !== $this->sig->length_secret_key) {
            throw new OqsException(sprintf(
                'Invalid secret key length: expected %d bytes, got %d',
                $this->sig->length_secret_key,
                strlen($secretKey)
            ));
        }

        $ffi = $this->instanceFfi;

        // FFI cannot allocate a zero-length array; allocate at least 1 byte
        // and pass the real (possibly zero) length separately to liboqs.
        $msgBuf = $ffi->new('uint8_t[' . max(1, strlen($message)) . ']');
        if (strlen($message) > 0) {
            \FFI::memcpy($msgBuf, $message, strlen($message));
        }

        $skBuf = $ffi->new('uint8_t[' . strlen($secretKey) . ']');
        \FFI::memcpy($skBuf, $secretKey, strlen($secretKey));

        $sigBuf = $ffi->new("uint8_t[{$this->sig->length_signature}]");
        $sigLen = $ffi->new('size_t');
        $sigLen->cdata = $this->sig->length_signature;

        $rc = $ffi->OQS_SIG_sign(
            $this->sig,
            $sigBuf,
            \FFI::addr($sigLen),
            $msgBuf,
            strlen($message),
            $skBuf
        );

        if ($rc !== 0) {
            throw new OqsException("Signing failed (rc={$rc})");
        }

        // Some algorithms (e.g. Falcon) produce variable-length signatures
        // shorter than the maximum — trim to the actual length reported.
        return \FFI::string($sigBuf, $sigLen->cdata);
    }

    /**
     * Verify a signature against a message and public key.
     * Returns true if valid, false if invalid (never throws for a bad signature).
     */
    public function verify(string $message, string $signature, string $publicKey): bool
    {
        if (strlen($publicKey) !== $this->sig->length_public_key) {
            throw new OqsException(sprintf(
                'Invalid public key length: expected %d bytes, got %d',
                $this->sig->length_public_key,
                strlen($publicKey)
            ));
        }

        $ffi = $this->instanceFfi;

        // FFI cannot allocate a zero-length array; allocate at least 1 byte
        // and pass the real (possibly zero) length separately to liboqs.
        $msgBuf = $ffi->new('uint8_t[' . max(1, strlen($message)) . ']');
        if (strlen($message) > 0) {
            \FFI::memcpy($msgBuf, $message, strlen($message));
        }

        $sigBuf = $ffi->new('uint8_t[' . strlen($signature) . ']');
        \FFI::memcpy($sigBuf, $signature, strlen($signature));

        $pkBuf = $ffi->new('uint8_t[' . strlen($publicKey) . ']');
        \FFI::memcpy($pkBuf, $publicKey, strlen($publicKey));

        $rc = $ffi->OQS_SIG_verify(
            $this->sig,
            $msgBuf,
            strlen($message),
            $sigBuf,
            strlen($signature),
            $pkBuf
        );

        return $rc === 0;
    }

    /**
     * Load (once per process) and cache the FFI binding to liboqs.
     * Shared with OqsKem — same header file, same library.
     */
    private static function ffi(): \FFI
    {
        if (self::$ffi !== null) {
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

        return self::$ffi = \FFI::cdef($header, self::resolveLibraryPath());
    }

    private static function resolveLibraryPath(): string
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

        foreach ($candidates as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        throw new OqsException(
            'liboqs shared library not found. Checked: ' . implode(', ', $candidates) .
            '. Install liboqs or edit OqsSig::resolveLibraryPath().'
        );
    }
}