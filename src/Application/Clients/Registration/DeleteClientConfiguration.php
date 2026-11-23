<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientDeleted;

/**
 * `DELETE /oauth2/register/{client_id}` (RFC 7592 §2.3): a self-registered client deletes itself,
 * as the Management API deletes a client — every code, token, consent and grant it holds goes
 * with it, and its registration access token with its registration.
 *
 * Not {@see \Clavia\Application\Management\Clients\DeleteClient}: that one refuses the client a
 * Management API token was issued to, which is exactly the client acting here.
 */
final readonly class DeleteClientConfiguration
{
    public function __construct(
        private RegisteredClients $registered,
        private ClientRepository $clients,
        private TransactionManager $transactions,
        private AuditContext $audit,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws RegistrationAccessTokenRejected
     */
    public function __invoke(#[\SensitiveParameter] ?string $registrationAccessToken, string $clientId): void
    {
        $client = $this->registered->authenticate($registrationAccessToken, $clientId)->client;

        $this->transactions->transactional(function () use ($client): void {
            $this->clients->delete($client->id);
            $this->audit->actAs(Actor::application($client->id));
            $this->events->dispatch(new ClientDeleted($client));
        });
    }
}
