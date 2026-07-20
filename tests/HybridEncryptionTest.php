<?php

declare(strict_types=1);

namespace Oqs\Tests;

use Oqs\OqsKem;
use Oqs\HybridEncryption;
use Oqs\Exception\OqsException;
use PHPUnit\Framework\TestCase;

final class HybridEncryptionTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('ffi')) {
            $this->markTestSkipped('FFI extension not available');
        }
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $plaintext = 'The secret message for Alice.';
        $encrypted = HybridEncryption::encrypt($keys['public_key'], $plaintext);
        $decrypted = HybridEncryption::decrypt($encrypted, $keys['secret_key']);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptProducesDifferentCiphertextEachTime(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $plaintext = 'Same message, different ciphertexts.';
        $first = HybridEncryption::encrypt($keys['public_key'], $plaintext);
        $second = HybridEncryption::encrypt($keys['public_key'], $plaintext);

        // Randomized KEM encapsulation + random IV means ciphertexts must differ
        // even for identical plaintext.
        $this->assertNotSame($first, $second);

        // But both must still decrypt correctly.
        $this->assertSame($plaintext, HybridEncryption::decrypt($first, $keys['secret_key']));
        $this->assertSame($plaintext, HybridEncryption::decrypt($second, $keys['secret_key']));
    }

    public function testEmptyPlaintextRoundTrips(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $encrypted = HybridEncryption::encrypt($keys['public_key'], '');
        $decrypted = HybridEncryption::decrypt($encrypted, $keys['secret_key']);

        $this->assertSame('', $decrypted);
    }

    public function testLargePlaintextRoundTrips(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $plaintext = random_bytes(1024 * 100); // 100 KB of binary data
        $encrypted = HybridEncryption::encrypt($keys['public_key'], $plaintext);
        $decrypted = HybridEncryption::decrypt($encrypted, $keys['secret_key']);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testTamperedCiphertextFailsDecryption(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $encrypted = HybridEncryption::encrypt($keys['public_key'], 'sensitive data');

        $tampered = $encrypted;
        $lastIndex = strlen($tampered) - 1;
        $tampered[$lastIndex] = chr(ord($tampered[$lastIndex]) ^ 0xFF);

        $this->expectException(OqsException::class);
        HybridEncryption::decrypt($tampered, $keys['secret_key']);
    }

    public function testDecryptWithWrongSecretKeyFails(): void
    {
        $alice = new OqsKem('ML-KEM-768');
        $aliceKeys = $alice->generateKeypair();

        $mallory = new OqsKem('ML-KEM-768');
        $malloryKeys = $mallory->generateKeypair();

        $encrypted = HybridEncryption::encrypt($aliceKeys['public_key'], 'for Alice only');

        $this->expectException(OqsException::class);
        HybridEncryption::decrypt($encrypted, $malloryKeys['secret_key']);
    }

    public function testMalformedBlobThrows(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $this->expectException(OqsException::class);
        HybridEncryption::decrypt('not-a-valid-blob', $keys['secret_key']);
    }
}