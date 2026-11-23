<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientDeleted;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Deletes the self-registered clients never issued a token, `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME`
 * days after they registered (docs/design/dynamic-client-registration.md §5.4). Run daily
 * (`clavia clients:purge-unused`), whether registration is on or not.
 *
 * Reads registration rows only, so an operator's client is never reached; and one token issued
 * settles a client for good. Each client is deleted as the Management API deletes one, with its
 * own `ClientDeleted` in the trail, the system as the actor.
 */
final readonly class PurgeUnusedRegistrations
{
    /** @param positive-int $lifetimeDays */
    public function __construct(
        private ClientRegistrationRepository $registrations,
        private ClientRepository $clients,
        private TransactionManager $transactions,
        private Clock $clock,
        private DomainEvents $events,
        private int $lifetimeDays,
    ) {
    }

    /**
     * @return non-negative-int The clients deleted.
     */
    public function __invoke(): int
    {
        $before = $this->clock->now()->modify(sprintf('-%d days', $this->lifetimeDays));
        $deleted = 0;
        foreach ($this->registrations->neverUsedSince($before) as $clientId) {
            // One client at a time: one that cannot be deleted leaves the others to their turn.
            $deleted += $this->transactions->transactional(function () use ($clientId): int {
                $client = $this->clients->find($clientId);
                if ($client === null) {
                    return 0;
                }
                $this->clients->delete($client->id);
                $this->events->dispatch(new ClientDeleted($client));

                return 1;
            });
        }

        return $deleted;
    }
}
