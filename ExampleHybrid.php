<?php

declare(strict_types=1);

require __DIR__ . '/src/Exception/OqsException.php';
require __DIR__ . '/src/OqsKem.php';
require __DIR__ . '/src/HybridEncryption.php';

use Oqs\OqsKem;
use Oqs\HybridEncryption;
use Oqs\Exception\OqsException;

try {
    // Alice generates a keypair once and publishes her public key
    $alice = new OqsKem('ML-KEM-768');
    $keys = $alice->generateKeypair();
    echo "[Alice] Keypair generated (pk={$alice->publicKeyLength()}B, sk={$alice->secretKeyLength()}B)\n\n";

    // Bob encrypts a message for Alice using only her public key
    $message = 'This text is protected by hybrid post-quantum encryption.';
    echo "[Bob] Plaintext: \"{$message}\"\n";

    $encrypted = HybridEncryption::encrypt($keys['public_key'], $message);
    echo '[Bob] Encrypted blob (' . strlen($encrypted) . ' bytes): ' . bin2hex(substr($encrypted, 0, 32)) . "...\n\n";

    // Alice decrypts it using her secret key
    $decrypted = HybridEncryption::decrypt($encrypted, $keys['secret_key']);
    echo "[Alice] Decrypted: \"{$decrypted}\"\n\n";

    echo $decrypted === $message
        ? "✅ SUCCESS: round-trip matches original plaintext\n"
        : "❌ FAILURE: decrypted text does not match\n";

    // Tamper check: flipping a byte in the ciphertext must make decryption fail
    echo "\n--- Tamper check ---\n";
    $tampered = $encrypted;
    $tampered[strlen($tampered) - 1] = chr(ord($tampered[strlen($tampered) - 1]) ^ 0xFF);

    try {
        HybridEncryption::decrypt($tampered, $keys['secret_key']);
        echo "❌ Unexpected: tampered ciphertext decrypted successfully!\n";
    } catch (OqsException $e) {
        echo "✅ Tamper check passed: " . $e->getMessage() . "\n";
    }
} catch (OqsException $e) {
    fwrite(STDERR, 'OQS error: ' . $e->getMessage() . "\n");
    exit(1);
}