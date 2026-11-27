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
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/resource-servers` and `GET /api/v1/resource-servers/{resource_server_id}`.
 */
final readonly class ReadResourceServers
{
    public function __construct(private ResourceServerRepository $resourceServers)
    {
    }

    /** @return Page<ResourceServer> */
    public function page(PageRequest $request): Page
    {
        return $this->resourceServers->page($request);
    }

    /**
     * @throws NotFound
     */
    public function one(ResourceServerId $id): ResourceServer
    {
        return $this->resourceServers->find($id) ?? throw NotFound::of('API');
    }

    /**
     * The API, known to have fine-grained authorization set up, switched on or off.
     *
     * @throws NotFound When the API does not exist or has none.
     */
    public function withAuthorization(ResourceServerId $id): ResourceServer
    {
        $api = $this->one($id);

        return $api->authorization === null
            ? throw NotFound::of('fine-grained authorization on this API')
            : $api;
    }
}
