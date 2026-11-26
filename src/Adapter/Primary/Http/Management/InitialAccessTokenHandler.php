<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\InitialAccessTokens\RevokeInitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/initial-access-tokens/{initial_access_token_id}`: `DELETE` revokes it
 * (`revokeInitialAccessToken`).
 */
final readonly class InitialAccessTokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private RevokeInitialAccessToken $revoke,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== RequestMethodInterface::METHOD_DELETE) {
            throw new LogicException('Routed with a method the handler does not serve.');
        }
        $management = ManagementRequest::of($request);

        ($this->revoke)(InitialAccessTokenId::fromString($management->path('initial_access_token_id')));

        return $this->responder->noContent();
    }
}
