<?php

declare(strict_types=1);

namespace Oqs\Tests;

use Oqs\OqsKem;
use Oqs\Exception\OqsException;
use PHPUnit\Framework\TestCase;

final class OqsKemTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('ffi')) {
            $this->markTestSkipped('FFI extension not available');
        }
    }

    public function testGenerateKeypairReturnsCorrectLengths(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $this->assertSame(1184, strlen($keys['public_key']));
        $this->assertSame(2400, strlen($keys['secret_key']));
        $this->assertSame(1184, $kem->publicKeyLength());
        $this->assertSame(2400, $kem->secretKeyLength());
    }

    public function testEncapsulateReturnsCorrectLengths(): void
    {
        $alice = new OqsKem('ML-KEM-768');
        $keys = $alice->generateKeypair();

        $bob = new OqsKem('ML-KEM-768');
        $result = $bob->encapsulate($keys['public_key']);

        $this->assertSame(1088, strlen($result['ciphertext']));
        $this->assertSame(32, strlen($result['shared_secret']));
    }

    public function testFullKeyExchangeProducesMatchingSharedSecret(): void
    {
        $alice = new OqsKem('ML-KEM-768');
        $keys = $alice->generateKeypair();

        $bob = new OqsKem('ML-KEM-768');
        $encapsulated = $bob->encapsulate($keys['public_key']);

        $aliceSecret = $alice->decapsulate($encapsulated['ciphertext'], $keys['secret_key']);

        $this->assertTrue(hash_equals($aliceSecret, $encapsulated['shared_secret']));
    }

    public function testDifferentKeypairsProduceDifferentSharedSecrets(): void
    {
        $alice = new OqsKem('ML-KEM-768');
        $keysA = $alice->generateKeypair();

        $bob = new OqsKem('ML-KEM-768');
        $encapsulatedA = $bob->encapsulate($keysA['public_key']);
        $encapsulatedB = $bob->encapsulate($keysA['public_key']);

        // Two independent encapsulations against the same public key
        // must produce different ciphertexts/secrets (randomized encryption).
        $this->assertNotSame($encapsulatedA['ciphertext'], $encapsulatedB['ciphertext']);
        $this->assertNotSame($encapsulatedA['shared_secret'], $encapsulatedB['shared_secret']);
    }

    public function testUnsupportedAlgorithmThrows(): void
    {
        $this->expectException(OqsException::class);
        new OqsKem('NotARealAlgorithm123');
    }

    public function testEncapsulateWithWrongPublicKeyLengthThrows(): void
    {
        $kem = new OqsKem('ML-KEM-768');

        $this->expectException(OqsException::class);
        $kem->encapsulate('too-short-key');
    }

    public function testDecapsulateWithWrongCiphertextLengthThrows(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();

        $this->expectException(OqsException::class);
        $kem->decapsulate('too-short-ciphertext', $keys['secret_key']);
    }

    public function testDecapsulateWithWrongSecretKeyThrowsOnLengthMismatch(): void
    {
        $kem = new OqsKem('ML-KEM-768');
        $keys = $kem->generateKeypair();
        $encapsulated = $kem->encapsulate($keys['public_key']);

        $this->expectException(OqsException::class);
        $kem->decapsulate($encapsulated['ciphertext'], 'wrong-length-secret-key');
    }

    public function testDecapsulateWithWrongButCorrectLengthSecretKeyDoesNotMatch(): void
    {
        // A structurally valid but *wrong* secret key must not decapsulate
        // to the same shared secret as the real one.
        $alice = new OqsKem('ML-KEM-768');
        $aliceKeys = $alice->generateKeypair();

        $mallory = new OqsKem('ML-KEM-768');
        $malloryKeys = $mallory->generateKeypair();

        $bob = new OqsKem('ML-KEM-768');
        $encapsulated = $bob->encapsulate($aliceKeys['public_key']);

        // Decapsulating with Mallory's secret key (same length, wrong key)
        // must not succeed with the same shared secret.
        $wrongSecret = $alice->decapsulate($encapsulated['ciphertext'], $malloryKeys['secret_key']);

        $this->assertFalse(hash_equals($wrongSecret, $encapsulated['shared_secret']));
    }
}