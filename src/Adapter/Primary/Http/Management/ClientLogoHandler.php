<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\ReadClientLogo;
use Clavia\Application\Management\Clients\RemoveClientLogo;
use Clavia\Application\Management\Clients\SetClientLogo;
use Clavia\Domain\Client\ClientId;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET | PUT | DELETE /api/v1/clients/{client_id}/logo` (`getClientLogo`, `setClientLogo`,
 * `removeClientLogo`): the application's logo on its sign-in pages (#25). The body of a `PUT` is the image
 * itself, whose content decides what it is.
 */
final readonly class ClientLogoHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadClientLogo $read,
        private SetClientLogo $set,
        private RemoveClientLogo $remove,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $id = ClientId::fromString(ManagementRequest::of($request)->path('client_id'));

        switch ($request->getMethod()) {
            case RequestMethodInterface::METHOD_GET:
                $logo = ($this->read)($id);

                return $this->responder->image($logo->mediaType, $logo->content);
            case RequestMethodInterface::METHOD_PUT:
                ($this->set)($id, (string) $request->getBody());

                return $this->responder->noContent();
            case RequestMethodInterface::METHOD_DELETE:
                ($this->remove)($id);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
