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
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * Registrations in memory, honouring the foreign key PostgreSQL enforces: given the clients, a
 * deleted client has no registration, applied as the data is read.
 */
final class InMemoryClientRegistrationRepository implements ClientRegistrationRepository
{
    /** @var array<string, ClientRegistration> By client id. */
    private array $registrations = [];

    public function __construct(private readonly ?InMemoryClientRepository $clients = null)
    {
    }

    #[\Override]
    public function add(ClientRegistration $registration): void
    {
        $this->registrations[$registration->clientId->value] = $registration;
    }

    #[\Override]
    public function find(ClientId $clientId): ?ClientRegistration
    {
        if ($this->clients !== null && $this->clients->find($clientId) === null) {
            return null;
        }

        return $this->registrations[$clientId->value] ?? null;
    }

    #[\Override]
    public function findByAccessToken(Digest $digest): ?ClientRegistration
    {
        foreach ($this->registrations as $registration) {
            if ($registration->accessTokenDigest->equals($digest)) {
                return $this->find($registration->clientId);
            }
        }

        return null;
    }

    #[\Override]
    public function ofClients(array $clientIds): array
    {
        return array_values(array_filter(array_map($this->find(...), $clientIds)));
    }

    #[\Override]
    public function markUsed(ClientId $clientId, DateTimeImmutable $at): void
    {
        $registration = $this->registrations[$clientId->value] ?? null;
        if ($registration !== null && $registration->firstUsedAt === null) {
            $this->registrations[$clientId->value] = new ClientRegistration(
                $registration->clientId,
                $registration->accessTokenDigest,
                $registration->initialAccessTokenId,
                $registration->registeredAt,
                $at,
            );
        }
    }

    #[\Override]
    public function neverUsedSince(DateTimeImmutable $before): array
    {
        $unused = [];
        foreach ($this->registrations as $registration) {
            $current = $this->find($registration->clientId);
            if ($current !== null && $current->firstUsedAt === null && $current->registeredAt < $before) {
                $unused[] = $current;
            }
        }
        usort(
            $unused,
            static fn (ClientRegistration $a, ClientRegistration $b): int
                => [$a->registeredAt, $a->clientId->value] <=> [$b->registeredAt, $b->clientId->value],
        );

        return array_map(static fn (ClientRegistration $registration): ClientId => $registration->clientId, $unused);
    }

    #[\Override]
    public function save(ClientRegistration $registration): void
    {
        if (isset($this->registrations[$registration->clientId->value])) {
            $this->registrations[$registration->clientId->value] = $registration;
        }
    }
}
