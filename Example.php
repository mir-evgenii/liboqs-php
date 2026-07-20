<?php

declare(strict_types=1);

require __DIR__ . '/src/Exception/OqsException.php';
require __DIR__ . '/src/OqsKem.php';

use Oqs\OqsKem;
use Oqs\Exception\OqsException;

try {
    $alice = new OqsKem('ML-KEM-768');
    $keys = $alice->generateKeypair();
    echo "[Alice] {$alice->algorithmName()} keypair generated ";
    echo "(pk={$alice->publicKeyLength()}B, sk={$alice->secretKeyLength()}B)\n";

    $bob = new OqsKem('ML-KEM-768');
    $encapsulated = $bob->encapsulate($keys['public_key']);
    echo "[Bob] Encapsulated (ct={$bob->ciphertextLength()}B, ss={$bob->sharedSecretLength()}B)\n";

    $aliceSecret = $alice->decapsulate($encapsulated['ciphertext'], $keys['secret_key']);

    echo "\n";
    echo 'Bob\'s   shared secret: ' . bin2hex($encapsulated['shared_secret']) . "\n";
    echo 'Alice\'s shared secret: ' . bin2hex($aliceSecret) . "\n\n";

    echo hash_equals($aliceSecret, $encapsulated['shared_secret'])
        ? "✅ SUCCESS: shared secrets match\n"
        : "❌ FAILURE: shared secrets do NOT match\n";
} catch (OqsException $e) {
    fwrite(STDERR, 'OQS error: ' . $e->getMessage() . "\n");
    exit(1);
}