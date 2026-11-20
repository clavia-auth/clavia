<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Management\Users\UserChanges;
use Clavia\Domain\Identity\UserId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/users/{user_id}`: `GET` (`getUser`), `PATCH` (`updateUser`), `DELETE`
 * (`deleteUser`).
 */
final readonly class UserHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadUsers $read,
        private UpdateUser $update,
        private DeleteUser $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = UserId::fromString(ManagementRequest::pathParameter($request, 'user_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::user($this->read->one($id)));
            case 'PATCH':
                $body = $management->body;

                return $this->responder->json(ManagementViews::user(($this->update)($id, new UserChanges(
                    $body->string('email'),
                    $body->string('password'),
                    $body->bool('email_verified'),
                    $body->bool('is_active'),
                    UserFields::profileChanges($body),
                ))));
            case 'DELETE':
                ($this->delete)($id, $management->caller);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
