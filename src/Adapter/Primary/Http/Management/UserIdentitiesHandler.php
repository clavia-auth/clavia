<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\ReadIdentities;
use Clavia\Application\Management\Users\UnlinkIdentity;
use Clavia\Domain\Identity\UserId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/users/{user_id}/identities` (`listUserIdentities`) and
 * `DELETE /api/v1/users/{user_id}/identities/{connection}` (`unlinkUserIdentity`).
 */
final readonly class UserIdentitiesHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadIdentities $read,
        private UnlinkIdentity $unlink,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $user = UserId::fromString($management->path('user_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->jsonList(array_map(ManagementViews::identity(...), ($this->read)($user)));
            case 'DELETE':
                ($this->unlink)($user, $management->path('connection'));

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
