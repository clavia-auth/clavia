<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * Linked identities kept in an array, keyed like the table: `(provider, subject)`.
 */
final class InMemoryExternalIdentityRepository implements ExternalIdentityRepository
{
    /** @var array<string, ExternalIdentity> */
    private array $identities = [];

    #[\Override]
    public function find(ConnectionName $provider, string $subject): ?ExternalIdentity
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

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        $identities = array_values(array_filter(
            $this->identities,
            static fn (ExternalIdentity $identity): bool => $identity->userId->equals($userId),
        ));
        usort(
            $identities,
            static fn (ExternalIdentity $a, ExternalIdentity $b): int
                => [$a->provider->value, $a->subject] <=> [$b->provider->value, $b->subject],
        );

        return $identities;
    }

    #[\Override]
    public function unlink(UserId $userId, ConnectionName $provider): int
    {
        $unlinked = 0;
        foreach ($this->identities as $key => $identity) {
            if ($identity->userId->equals($userId) && $identity->provider->equals($provider)) {
                unset($this->identities[$key]);
                $unlinked++;
            }
        }

        return $unlinked;
    }

    #[\Override]
    public function countThrough(ConnectionName $provider): int
    {
        return count(array_filter(
            $this->identities,
            static fn (ExternalIdentity $identity): bool => $identity->provider->equals($provider),
        ));
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
