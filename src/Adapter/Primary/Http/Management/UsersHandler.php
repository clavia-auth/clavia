<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\NewUser;
use Clavia\Application\Management\Users\ReadUsers;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/users`: `GET` lists users (`listUsers`), `POST` creates one (`createUser`).
 */
final readonly class UsersHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadUsers $read,
        private CreateUser $create,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);

        return match ($request->getMethod()) {
            RequestMethodInterface::METHOD_GET => $this->responder->json(ManagementViews::page(
                $this->read->page(Paging::fromRequest($management)),
                ManagementViews::user(...),
            )),
            RequestMethodInterface::METHOD_POST => $this->create($management->body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function create(JsonObject $body): ResponseInterface
    {
        $user = ($this->create)(new NewUser(
            $body->string('email') ?? throw new LogicException("The contract requires 'email'."),
            $body->string('password'),
            $body->bool('email_verified') ?? false,
            $body->bool('is_active') ?? true,
            UserFields::profile($body),
            $body->string('connection'),
        ));

        return $this->responder->created(ManagementViews::user($user), '/api/v1/users/' . $user->user->id->value);
    }
}
