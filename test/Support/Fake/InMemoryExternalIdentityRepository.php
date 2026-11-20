<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * Linked identities kept in an array, keyed like the table: `(provider, subject)`.
 */
final class InMemoryExternalIdentityRepository implements ExternalIdentityRepository
{
    /** @var array<string, ExternalIdentity> */
    private array $identities = [];

    #[\Override]
    public function find(ProviderName $provider, string $subject): ?ExternalIdentity
    {
        return $this->identities[self::key($provider->value, $subject)] ?? null;
    }

    #[\Override]
    public function add(ExternalIdentity $identity): void
    {
        $key = self::key($identity->provider->value, $identity->subject);
        if (isset($this->identities[$key])) {
            throw new AlreadyExists('This identity is already linked to an account.');
        }
        $this->identities[$key] = $identity;
    }

    /** @return list<ExternalIdentity> */
    public function all(): array
    {
        return array_values($this->identities);
    }

    private static function key(string $provider, string $subject): string
    {
        return $provider . "\n" . $subject;
    }
}
