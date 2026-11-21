<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\ReadConsents;
use Clavia\Application\Management\Users\WithdrawConsent;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/users/{user_id}/consents` (`listUserConsents`) and
 * `DELETE /api/v1/users/{user_id}/consents/{client_id}` (`withdrawUserConsent`).
 */
final readonly class UserConsentsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadConsents $read,
        private WithdrawConsent $withdraw,
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
                return $this->responder->jsonList(array_map(ManagementViews::consent(...), ($this->read)($user)));
            case 'DELETE':
                ($this->withdraw)($user, ClientId::fromString($management->path('client_id')));

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
