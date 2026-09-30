<?php

declare(strict_types=1);

namespace Oqs\Internal;

use Oqs\Exception\OqsException;

/**
 * Resolves the liboqs shared library path shared by OqsKem and OqsSig.
 *
 * Priority: an explicit override (constructor argument), then the
 * LIBOQS_PATH environment variable, then the first existing candidate
 * from a list of common install locations for the current OS.
 */
final class LibraryLocator
{
    /**
     * @param string[] $candidates
     */
    public static function resolve(?string $override, array $candidates): string
    {
        if ($override !== null) {
            if (!file_exists($override)) {
                throw new OqsException("liboqs shared library not found at explicit path: {$override}");
            }

            return $override;
        }

        $envPath = getenv('LIBOQS_PATH');
        if ($envPath !== false && $envPath !== '') {
            if (!file_exists($envPath)) {
                throw new OqsException("liboqs shared library not found at LIBOQS_PATH: {$envPath}");
            }

            return $envPath;
        }

        foreach ($candidates as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        throw new OqsException(
            'liboqs shared library not found. Checked: ' . implode(', ', $candidates) .
            '. Install liboqs, or set the LIBOQS_PATH environment variable, or pass an explicit ' .
            'library path to the OqsKem/OqsSig constructor.'
        );
    }
}
