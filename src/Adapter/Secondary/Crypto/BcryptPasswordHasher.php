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
use ValueError;

/**
 * bcrypt, through PHP's own `password_hash()`.
 *
 * Hashes written by the Python implementation (`$2b$`) verify here unchanged; new ones
 * carry PHP's `$2y$` prefix, which is the same algorithm.
 *
 * bcrypt reads at most 72 bytes and stops at a NUL byte, and PHP truncates silently.
 * A hash that covers less than what was typed makes every longer password sharing that
 * prefix equivalent, so such a secret is refused when hashing and never matches when
 * verifying.
 */
final readonly class BcryptPasswordHasher implements PasswordHasher
{
    /** The longest input bcrypt takes into account, in bytes. */
    public const int MAX_SECRET_BYTES = 72;

    public const int DEFAULT_COST = 12;

    /**
     * @param int<4, 31> $cost Work factor: each increment doubles the time a hash takes.
     */
    public function __construct(private int $cost = self::DEFAULT_COST)
    {
    }

    #[\Override]
    public function hash(#[\SensitiveParameter] string $secret): string
    {
        if (! $this->isRepresentable($secret)) {
            throw new SecretNotHashable(sprintf(
                'bcrypt takes at most %d bytes and no NUL byte; hashing this secret would alter it.',
                self::MAX_SECRET_BYTES,
            ));
        }

        $hash = password_hash($secret, PASSWORD_BCRYPT, ['cost' => $this->cost]);
        assert($hash !== '');

        return $hash;
    }

    #[\Override]
    public function verify(#[\SensitiveParameter] string $secret, string $hash): bool
    {
        if (! $this->isRepresentable($secret)) {
            return false;
        }

        try {
            return password_verify($secret, $hash);
        } catch (ValueError) {
            return false;
        }
    }

    #[\Override]
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    #[\Override]
    public function simulateVerification(#[\SensitiveParameter] string $secret): void
    {
        // Computing a hash at this cost takes what verifying one does. The input is
        // random rather than the secret, so the time spent does not depend on it either.
        password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    private function isRepresentable(#[\SensitiveParameter] string $secret): bool
    {
        return strlen($secret) <= self::MAX_SECRET_BYTES && ! str_contains($secret, "\0");
    }
}
