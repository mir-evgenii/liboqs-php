<?php

declare(strict_types=1);

namespace Oqs\Exception;

/**
 * Thrown when a liboqs / FFI operation fails — unsupported algorithm,
 * invalid key/ciphertext length, or a non-zero return code from liboqs.
 */
final class OqsException extends \RuntimeException
{
}