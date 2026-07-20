<?php

declare(strict_types=1);

namespace Oqs\Tests;

use Oqs\OqsSig;
use Oqs\Exception\OqsException;
use PHPUnit\Framework\TestCase;

final class OqsSigTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('ffi')) {
            $this->markTestSkipped('FFI extension not available');
        }
    }

    public function testGenerateKeypairReturnsCorrectLengths(): void
    {
        $sig = new OqsSig('ML-DSA-65');
        $keys = $sig->generateKeypair();

        $this->assertSame(1952, strlen($keys['public_key']));
        $this->assertSame(4032, strlen($keys['secret_key']));
    }

    public function testSignatureVerifiesAgainstCorrectMessageAndKey(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();

        $message = 'The quick brown fox jumps over the lazy dog';
        $signature = $signer->sign($message, $keys['secret_key']);

        $this->assertTrue($signer->verify($message, $signature, $keys['public_key']));
    }

    public function testSignatureDoesNotExceedMaxLength(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();

        $signature = $signer->sign('short message', $keys['secret_key']);

        $this->assertLessThanOrEqual($signer->maxSignatureLength(), strlen($signature));
    }

    public function testTamperedMessageFailsVerification(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();

        $signature = $signer->sign('original message', $keys['secret_key']);

        $this->assertFalse(
            $signer->verify('tampered message', $signature, $keys['public_key'])
        );
    }

    public function testTamperedSignatureFailsVerification(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();

        $message = 'original message';
        $signature = $signer->sign($message, $keys['secret_key']);

        // Flip one byte in the signature
        $tampered = $signature;
        $tampered[0] = chr(ord($tampered[0]) ^ 0xFF);

        $this->assertFalse(
            $signer->verify($message, $tampered, $keys['public_key'])
        );
    }

    public function testSignatureFromWrongKeyFailsVerification(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keysA = $signer->generateKeypair();
        $keysB = $signer->generateKeypair();

        $message = 'message signed by A';
        $signature = $signer->sign($message, $keysA['secret_key']);

        // Verifying with B's public key must fail — signature belongs to A
        $this->assertFalse(
            $signer->verify($message, $signature, $keysB['public_key'])
        );
    }

    public function testEmptyMessageCanBeSignedAndVerified(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();

        $signature = $signer->sign('', $keys['secret_key']);

        $this->assertTrue($signer->verify('', $signature, $keys['public_key']));
    }

    public function testUnsupportedAlgorithmThrows(): void
    {
        $this->expectException(OqsException::class);
        new OqsSig('NotARealSigAlgorithm123');
    }

    public function testSignWithWrongSecretKeyLengthThrows(): void
    {
        $signer = new OqsSig('ML-DSA-65');

        $this->expectException(OqsException::class);
        $signer->sign('message', 'too-short-key');
    }

    public function testVerifyWithWrongPublicKeyLengthThrows(): void
    {
        $signer = new OqsSig('ML-DSA-65');
        $keys = $signer->generateKeypair();
        $signature = $signer->sign('message', $keys['secret_key']);

        $this->expectException(OqsException::class);
        $signer->verify('message', $signature, 'too-short-public-key');
    }
}