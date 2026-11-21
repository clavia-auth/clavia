<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;

/**
 * Consents in memory, honouring the foreign keys PostgreSQL enforces: given the accounts,
 * the applications and the APIs, a consent naming one that is gone is not there —
 * applied as the data is read, which is when it shows.
 */
final class InMemoryConsentRepository implements ConsentRepository
{
    /** @var array<string, UserConsent> By person, application and API. */
    private array $consents = [];

    public function __construct(
        private readonly ?InMemoryUserRepository $users = null,
        private readonly ?InMemoryClientRepository $clients = null,
        private readonly ?InMemoryResourceServerRepository $resourceServers = null,
    ) {
    }

    #[\Override]
    public function find(UserId $userId, ClientId $clientId, ?ResourceServerId $resourceServerId): ?UserConsent
    {
        $consent = $this->consents[self::key($userId, $clientId, $resourceServerId)] ?? null;

        return $consent !== null && $this->stands($consent) ? $consent : null;
    }

    #[\Override]
    public function save(UserConsent $consent): void
    {
        $this->consents[self::key($consent->userId, $consent->clientId, $consent->resourceServerId)] = $consent;
    }

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        $consents = array_values(array_filter(
            $this->consents,
            fn (UserConsent $consent): bool => $consent->userId->equals($userId) && $this->stands($consent),
        ));
        usort(
            $consents,
            static fn (UserConsent $a, UserConsent $b): int => [$a->grantedAt, $a->clientId->value]
                <=> [$b->grantedAt, $b->clientId->value],
        );

        return $consents;
    }

    #[\Override]
    public function withdraw(UserId $userId, ClientId $clientId): void
    {
        foreach ($this->consents as $key => $consent) {
            if ($consent->userId->equals($userId) && $consent->clientId->equals($clientId)) {
                unset($this->consents[$key]);
            }
        }
    }

    /** Whether everything the consent names still exists. */
    private function stands(UserConsent $consent): bool
    {
        if ($this->users !== null && $this->users->find($consent->userId) === null) {
            return false;
        }
        if ($this->clients !== null && $this->clients->find($consent->clientId) === null) {
            return false;
        }

        return $consent->resourceServerId === null
            || $this->resourceServers === null
            || $this->resourceServers->find($consent->resourceServerId) !== null;
    }

    private static function key(UserId $userId, ClientId $clientId, ?ResourceServerId $resourceServerId): string
    {
        return $userId->value . ' ' . $clientId->value . ' ' . ($resourceServerId?->value ?? '');
    }
}
