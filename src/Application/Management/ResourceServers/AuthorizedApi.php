<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;

/**
 * The API an operator names, and the store its reads are answered from
 * (docs/design/fine-grained-authorization.md §5.6): an API with a store, authorization switched on or
 * off (switched off, the store is kept and still answers), on a server naming a decision engine.
 */
final readonly class AuthorizedApi
{
    /**
     * @param bool $available Whether fine-grained authorization is on (`CLAVIA_FGA_URL`).
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private bool $available,
    ) {
    }

    /**
     * @return array{ResourceServer, AuthorizationSettings}
     *
     * @throws NotFound When there is no such API, or it has no store (never set up, or deleted).
     * @throws Conflict When this server names no decision engine.
     */
    public function of(ResourceServerId $id): array
    {
        $api = $this->resourceServers->find($id) ?? throw NotFound::of('API');
        $settings = $api->authorization ?? throw NotFound::of('fine-grained authorization on this API');
        if (! $this->available) {
            throw new Conflict('Fine-grained authorization is off on this server: it names no decision engine.');
        }

        return [$api, $settings];
    }
}
