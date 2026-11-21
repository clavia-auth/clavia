<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Grant a client the scopes it may request from an API, as itself: `clavia clients:grant`.
 *
 * Shell only, with no HTTP equivalent: an endpoint that wrote client grants would let
 * its caller widen its own access, which would make every other permission on this
 * server decorative. Escalation should take access to the deployment, not a leaked token.
 *
 * Replaces what the client held on that API rather than adding to it: the command
 * states what the client should have, so running it with fewer scopes takes the others
 * away.
 */
final readonly class GrantClientAccess
{
    public function __construct(
        private ClientRepository $clients,
        private ResourceServerRepository $resourceServers,
        private ClientGrantRepository $clientGrants,
        private Clock $clock,
    ) {
    }

    /**
     * @param ScopeSet|null $scopes Null for every permission the API defines.
     *
     * @throws NotFound     When the client or the API does not exist.
     * @throws InvalidValue When the API does not define one of the scopes, the client is not
     *                      registered for the client credentials grant, or a third-party client
     *                      would be granted a system API.
     */
    public function __invoke(ClientId $clientId, Audience $audience, ?ScopeSet $scopes = null): ClientGrant
    {
        $client = $this->clients->find($clientId) ?? throw NotFound::of('client');
        $resourceServer = $this->resourceServers->findByIdentifier($audience) ?? throw NotFound::of('API');

        if (! $client->mayUseGrant(GrantType::ClientCredentials)) {
            // A grant it could never redeem: refused where the mistake is made.
            throw new InvalidValue(sprintf(
                "The client '%s' is not registered for the client credentials grant.",
                $client->id->value,
            ));
        }

        if ($resourceServer->isSystem && ! $client->isFirstParty()) {
            // The server's own API administers this very deployment: an outsider's machine
            // never gets near it, however it is configured.
            throw new InvalidValue(sprintf(
                "The client '%s' is third-party: it cannot be granted the system API '%s'.",
                $client->id->value,
                $resourceServer->identifier->value,
            ));
        }

        $grant = ClientGrant::grant(
            $client->id,
            $resourceServer,
            $scopes ?? $resourceServer->permissionScopes(),
            $this->clock->now(),
        );
        $this->clientGrants->save($grant);

        return $grant;
    }
}
