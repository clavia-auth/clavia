<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\SecretNotHashable;

/**
 * A password hasher that costs nothing, for tests that are not about hashing.
 *
 * Salted so that two hashes of one secret differ, like the real thing; otherwise as
 * weak as it looks. It honours the same contract as the PBKDF2 adapter, including the
 * secrets that adapter refuses.
 */
final class FakePasswordHasher implements PasswordHasher
{
    private const string PREFIX = '$fake$';

    private const int MAX_SECRET_BYTES = 1024;

    private int $salt = 0;

    public bool $outdated = false;

    /** How many times a verification was simulated, so a test can see the timing guard ran. */
    public int $simulatedVerifications = 0;

    #[\Override]
    public function hash(#[\SensitiveParameter] string $secret): string
    {
        if (! $this->isRepresentable($secret)) {
            throw new SecretNotHashable('The secret is too long.');
        }

        $salt = (string) ++$this->salt;

        return self::PREFIX . $salt . '$' . hash('sha256', $salt . $secret);
    }

    #[\Override]
    public function verify(#[\SensitiveParameter] string $secret, string $hash): bool
    {
        $parts = explode('$', $hash);
        if (! $this->isRepresentable($secret) || count($parts) !== 4 || ! str_starts_with($hash, self::PREFIX)) {
            return false;
        }

        return hash_equals($parts[3], hash('sha256', $parts[2] . $secret));
    }

    #[\Override]
    public function canVerify(string $hash): bool
    {
        return count(explode('$', $hash)) === 4 && str_starts_with($hash, self::PREFIX);
    }

    #[\Override]
    public function needsRehash(string $hash): bool
    {
        return $this->outdated || ! str_starts_with($hash, self::PREFIX);
    }

    #[\Override]
    public function simulateVerification(#[\SensitiveParameter] string $secret): void
    {
        $this->simulatedVerifications++;
    }

    private function isRepresentable(#[\SensitiveParameter] string $secret): bool
    {
        return strlen($secret) <= self::MAX_SECRET_BYTES;
    }
}
