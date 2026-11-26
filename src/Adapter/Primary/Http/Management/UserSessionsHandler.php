<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\UserSessions;
use Clavia\Domain\Identity\UserId;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|DELETE /api/v1/users/{user_id}/sessions` (`listUserSessions`, `endUserSessions`) and
 * `DELETE /api/v1/users/{user_id}/sessions/{sid}` (`endUserSession`).
 */
final readonly class UserSessionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private UserSessions $sessions,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $user = UserId::fromString($management->path('user_id'));

        switch ($request->getMethod()) {
            case RequestMethodInterface::METHOD_GET:
                return $this->responder->jsonList(array_map(
                    ManagementViews::session(...),
                    $this->sessions->of($user),
                ));
            case RequestMethodInterface::METHOD_DELETE:
                if ($management->hasPath('sid')) {
                    $this->sessions->end($user, $management->path('sid'));
                } else {
                    $this->sessions->endAll($user);
                }

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
