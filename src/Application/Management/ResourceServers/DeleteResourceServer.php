<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\ResourceServer\Event\ResourceServerDeleted;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\ResourceServer\SystemApiProtected;

/**
 * `DELETE /api/v1/resource-servers/{resource_server_id}`: the API, its permissions and
 * every client grant on it. Tokens already issued for it keep their `aud` and expire as
 * they would.
 */
final readonly class DeleteResourceServer
{
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws SystemApiProtected For a system API.
     */
    public function __invoke(ResourceServerId $id): void
    {
        $resourceServer = $this->resourceServers->find($id) ?? throw NotFound::of('API');
        $resourceServer->assertDeletable();

        $this->resourceServers->delete($resourceServer->id);
        $this->events->dispatch(new ResourceServerDeleted($resourceServer));
    }
}
