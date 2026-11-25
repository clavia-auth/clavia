<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Management\Users\UserChanges;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
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
        $id = UserId::fromString($management->path('user_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::user($this->read->one($id)));
            case 'PATCH':
                $body = $management->body;
                $metadata = null;
                if ($body->has('app_metadata')) {
                    // Writing it is granting access (custom claims, authorization): a scope of its own,
                    // on top of the operation's `update:users`, checked before anything changes.
                    $management->caller->require(ManagementPermission::UpdateUsersAppMetadata);
                    try {
                        $metadata = AppMetadata::fromJson($body->json('app_metadata') ?? '{}');
                    } catch (InvalidValue $refusal) {
                        return $this->responder->problem(new Problem(
                            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                            ContractViolation::DETAIL,
                            [['pointer' => '/app_metadata', 'detail' => $refusal->getMessage()]],
                        ));
                    }
                }

                return $this->responder->json(ManagementViews::user(($this->update)($id, new UserChanges(
                    $body->string('email'),
                    $body->string('password'),
                    $body->bool('email_verified'),
                    $body->bool('is_active'),
                    UserFields::profileChanges($body),
                    $metadata,
                ))));
            case 'DELETE':
                ($this->delete)($id, $management->caller);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
