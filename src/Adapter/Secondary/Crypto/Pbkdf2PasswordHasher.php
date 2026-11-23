<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Crypto;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SecretNotHashable;
use RuntimeException;

/**
 * PBKDF2-HMAC-SHA-256 (NIST SP 800-132, RFC 8018 §5.2), for FIPS 140: the one memory-free password
 * hash a FIPS-validated module offers.
 *
 * Derived through OpenSSL (`openssl_pbkdf2()`), never PHP's own `hash_pbkdf2()`, so a system running
 * OpenSSL in FIPS mode computes it in its FIPS provider. 600,000 iterations by default (OWASP's figure
 * for SHA-256), a 16-byte salt from the CSPRNG for every secret, a 32-byte key. The stored string
 * names all of it, in the PHC string format, so the iteration count can be raised without a
 * migration:
 *
 *     $pbkdf2-sha256$i=600000$<salt, base64>$<key, base64>
 *
 * The secret is taken whole: PBKDF2 neither truncates it nor stops at a NUL. Its length is bounded
 * (1,024 bytes) only to bound the work one request can ask for.
 */
final readonly class Pbkdf2PasswordHasher implements PasswordHasher
{
    public const int DEFAULT_ITERATIONS = 600_000;

    /** The least SP 800-132 allows, and OpenSSL's FIPS provider enforces. */
    public const int MIN_ITERATIONS = 1_000;

    /** What a stored hash may ask for: a row is trusted, but not to stall a sign-in for minutes. */
    private const int MAX_ITERATIONS = 10_000_000;

    public const int MAX_SECRET_BYTES = 1_024;

    private const int SALT_BYTES = 16;
    private const int KEY_BYTES = 32;
    private const string ALGORITHM = 'sha256';
    private const string PREFIX = '$pbkdf2-sha256$i=';

    /** The PHC string: base64 without padding, 22 characters for 16 bytes and 43 for 32. */
    private const string FORMAT = '#^\$pbkdf2-sha256\$i=([1-9][0-9]{3,7})\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$#D';

    /**
     * @param int $iterations Each one an HMAC-SHA-256 round, the cost growing linearly: 1,000 to
     *                        10,000,000, checked here, since it comes from a setting or a test.
     */
    public function __construct(private int $iterations = self::DEFAULT_ITERATIONS)
    {
        if ($iterations < self::MIN_ITERATIONS || $iterations > self::MAX_ITERATIONS) {
            throw new \InvalidArgumentException('PBKDF2 takes between 1,000 and 10,000,000 iterations.');
        }
    }

    #[\Override]
    public function hash(#[\SensitiveParameter] string $secret): string
    {
        if (strlen($secret) > self::MAX_SECRET_BYTES) {
            throw new SecretNotHashable(sprintf('A secret is at most %d bytes.', self::MAX_SECRET_BYTES));
        }

        $salt = random_bytes(self::SALT_BYTES);
        $key = self::derive($secret, $salt, $this->iterations)
            ?? throw new RuntimeException('OpenSSL could not derive a PBKDF2 key.');

        return self::PREFIX . $this->iterations . '$' . self::encode($salt) . '$' . self::encode($key);
    }

    #[\Override]
    public function verify(#[\SensitiveParameter] string $secret, string $hash): bool
    {
        $parsed = self::parse($hash);
        if ($parsed === null || strlen($secret) > self::MAX_SECRET_BYTES) {
            return false;
        }
        [$iterations, $salt, $expected] = $parsed;
        $key = self::derive($secret, $salt, $iterations);

        return $key !== null && hash_equals($expected, $key);
    }

    #[\Override]
    public function needsRehash(string $hash): bool
    {
        return (self::parse($hash)[0] ?? null) !== $this->iterations;
    }

    #[\Override]
    public function simulateVerification(#[\SensitiveParameter] string $secret): void
    {
        // A derivation at today's count takes what a verification does, whatever the secret.
        $_ = self::derive(random_bytes(self::SALT_BYTES), random_bytes(self::SALT_BYTES), $this->iterations);
    }

    private static function derive(#[\SensitiveParameter] string $secret, string $salt, int $iterations): ?string
    {
        $key = openssl_pbkdf2($secret, $salt, self::KEY_BYTES, $iterations, self::ALGORITHM);

        return $key === false || strlen($key) !== self::KEY_BYTES ? null : $key;
    }

    /** @return array{int, string, string}|null The iterations, the salt and the key; null when foreign. */
    private static function parse(string $hash): ?array
    {
        if (preg_match(self::FORMAT, $hash, $part) !== 1) {
            return null;
        }
        $iterations = (int) $part[1];
        $salt = base64_decode($part[2], true);
        $key = base64_decode($part[3], true);
        if (
            $iterations < self::MIN_ITERATIONS || $iterations > self::MAX_ITERATIONS
            || $salt === false || strlen($salt) !== self::SALT_BYTES
            || $key === false || strlen($key) !== self::KEY_BYTES
        ) {
            return null;
        }

        return [$iterations, $salt, $key];
    }

    private static function encode(string $bytes): string
    {
        return rtrim(base64_encode($bytes), '=');
    }
}
