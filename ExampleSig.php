<?php

declare(strict_types=1);

require __DIR__ . '/src/Exception/OqsException.php';
require __DIR__ . '/src/OqsSig.php';

use Oqs\OqsSig;
use Oqs\Exception\OqsException;

try {
    $signer = new OqsSig('ML-DSA-65');
    $keys = $signer->generateKeypair();

    echo "[Signer] {$signer->algorithmName()} keypair generated ";
    echo "(pk={$signer->publicKeyLength()}B, sk={$signer->secretKeyLength()}B, ";
    echo "max sig={$signer->maxSignatureLength()}B)\n";

    $message = 'This message is protected against quantum computers.';
    echo "\nMessage: \"{$message}\"\n";

    $signature = $signer->sign($message, $keys['secret_key']);
    echo 'Signature (' . strlen($signature) . " bytes): " . bin2hex(substr($signature, 0, 32)) . "...\n\n";

    // Verify with the correct message and public key
    $valid = $signer->verify($message, $signature, $keys['public_key']);
    echo $valid
        ? "✅ Verification SUCCESS: signature is valid\n"
        : "❌ Verification FAILED: signature is invalid\n";

    // Tamper check: verifying a modified message must fail
    $tampered = $signer->verify('This message was tampered with.', $signature, $keys['public_key']);
    echo $tampered
        ? "❌ Unexpected: tampered message passed verification!\n"
        : "✅ Tamper check passed: modified message correctly rejected\n";
} catch (OqsException $e) {
    fwrite(STDERR, 'OQS error: ' . $e->getMessage() . "\n");
    exit(1);
}