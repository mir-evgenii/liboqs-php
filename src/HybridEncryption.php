<?php

declare(strict_types=1);

namespace Oqs;

use Oqs\Exception\OqsException;

/**
 * Hybrid post-quantum encryption: ML-KEM (via OqsKem) establishes a shared
 * secret, HKDF derives a proper AES key from it, and AES-256-GCM encrypts
 * the actual data.
 *
 * KEM algorithms only transport a fixed-size secret — they do not encrypt
 * arbitrary messages. This class wires the three pieces together into a
 * single, simple API.
 *
 * Wire format produced by encrypt() (all binary, concatenated):
 *   [2 bytes: KEM ciphertext length (uint16 BE)]
 *   [KEM ciphertext                              ]
 *   [12 bytes: AES-GCM nonce/IV                  ]
 *   [16 bytes: AES-GCM authentication tag        ]
 *   [remaining bytes: AES-GCM ciphertext         ]
 *
 * Example:
 *   $alice = new OqsKem('ML-KEM-768');
 *   $keys  = $alice->generateKeypair();
 *
 *   // Bob encrypts something for Alice using only her public key
 *   $blob = HybridEncryption::encrypt($keys['public_key'], 'secret message');
 *
 *   // Alice decrypts it using her secret key
 *   $plaintext = HybridEncryption::decrypt($blob, $keys['secret_key']);
 */
final class HybridEncryption
{
    private const KEM_ALGORITHM = 'ML-KEM-768';
    private const HKDF_HASH = 'sha256';
    private const HKDF_INFO = 'oqs-hybrid-encryption-v1';
    private const AES_CIPHER = 'aes-256-gcm';
    private const AES_KEY_LENGTH = 32; // 256 bits
    private const GCM_IV_LENGTH = 12;  // recommended for GCM
    private const GCM_TAG_LENGTH = 16;

    /**
     * Encrypt data for the holder of $publicKey.
     * Only the corresponding secret key can decrypt it.
     */
    public static function encrypt(string $publicKey, string $plaintext): string
    {
        $kem = new OqsKem(self::KEM_ALGORITHM);

        $encapsulated = $kem->encapsulate($publicKey);
        $aesKey = self::deriveKey($encapsulated['shared_secret']);

        $iv = random_bytes(self::GCM_IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::AES_CIPHER,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::GCM_TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new OqsException('AES-GCM encryption failed');
        }

        $kemCiphertext = $encapsulated['ciphertext'];

        return pack('n', strlen($kemCiphertext))
            . $kemCiphertext
            . $iv
            . $tag
            . $ciphertext;
    }

    /**
     * Decrypt a blob produced by encrypt(), using the matching secret key.
     */
    public static function decrypt(string $blob, string $secretKey): string
    {
        $minLength = 2 + self::GCM_IV_LENGTH + self::GCM_TAG_LENGTH;
        if (strlen($blob) < $minLength) {
            throw new OqsException('Encrypted blob is too short / malformed');
        }

        $offset = 0;

        $kemCtLen = unpack('n', substr($blob, $offset, 2))[1];
        $offset += 2;

        $kemCiphertext = substr($blob, $offset, $kemCtLen);
        $offset += $kemCtLen;

        $iv = substr($blob, $offset, self::GCM_IV_LENGTH);
        $offset += self::GCM_IV_LENGTH;

        $tag = substr($blob, $offset, self::GCM_TAG_LENGTH);
        $offset += self::GCM_TAG_LENGTH;

        $ciphertext = substr($blob, $offset);

        $kem = new OqsKem(self::KEM_ALGORITHM);
        $sharedSecret = $kem->decapsulate($kemCiphertext, $secretKey);
        $aesKey = self::deriveKey($sharedSecret);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::AES_CIPHER,
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new OqsException(
                'AES-GCM decryption failed — data may be corrupted, tampered with, or the wrong secret key was used'
            );
        }

        return $plaintext;
    }

    /**
     * Derive a proper AES-256 key from a raw KEM shared secret via HKDF.
     */
    private static function deriveKey(string $sharedSecret): string
    {
        return hash_hkdf(self::HKDF_HASH, $sharedSecret, self::AES_KEY_LENGTH, self::HKDF_INFO);
    }
}