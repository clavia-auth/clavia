<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\ResetUserMfa;
use Clavia\Domain\Identity\UserId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `DELETE /api/v1/users/{user_id}/mfa` (`resetUserMfa`): turn the user's two-factor
 * authentication off.
 */
final readonly class UserMfaHandler implements RequestHandlerInterface
{
    public function __construct(
        private ResetUserMfa $reset,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ($this->reset)(UserId::fromString(ManagementRequest::of($request)->path('user_id')));

        return $this->responder->noContent();
    }
}
