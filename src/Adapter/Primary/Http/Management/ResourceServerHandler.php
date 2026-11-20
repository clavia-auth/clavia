<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/resource-servers/{resource_server_id}`: `GET` (`getResourceServer`),
 * `PATCH` (`updateResourceServer`), `DELETE` (`deleteResourceServer`).
 */
final readonly class ResourceServerHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadResourceServers $read,
        private UpdateResourceServer $update,
        private DeleteResourceServer $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = ResourceServerId::fromString(ManagementRequest::pathParameter($request, 'resource_server_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::resourceServer($this->read->one($id)));
            case 'PATCH':
                $api = ($this->update)(
                    $id,
                    $management->body->string('name'),
                    ResourceServerFields::permissions($management->body),
                );

                return $this->responder->json(ManagementViews::resourceServer($api));
            case 'DELETE':
                ($this->delete)($id);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
