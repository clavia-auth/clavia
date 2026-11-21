<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/resource-servers`: register an API.
 *
 * Never a system API: that marks an API this server depends on, which cannot then be
 * deleted, and only provisioning on the machine may create one.
 */
final readonly class RegisterResourceServer
{
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private SecretGenerator $secrets,
        private Clock $clock,
    ) {
    }

    /**
     * @throws InvalidValue
     * @throws AlreadyExists When an API is already registered with the identifier.
     */
    public function __invoke(NewResourceServer $new): ResourceServer
    {
        NewResourceServer::checkIdentifier($new->identifier);

        $resourceServer = ResourceServer::register(
            ResourceServerId::generate($this->secrets),
            Audience::fromString($new->identifier),
            $new->name,
            NewResourceServer::permissions($new->permissions),
            $this->clock->now(),
            enforcePolicies: $new->enforcePolicies,
            allowSkippingConsent: $new->allowSkippingConsent,
        );
        $this->resourceServers->save($resourceServer);

        return $resourceServer;
    }
}
